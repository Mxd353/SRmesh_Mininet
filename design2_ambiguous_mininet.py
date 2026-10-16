#!/usr/bin/env python3
r"""design2_ambiguous_mininet.py -- 两个 ECMP 点的端到端真实验证
================================================================

拓扑 (两个 ECMP 点串联):

    h1 --x1-- r1 --x2-- r3 --x5-- r4 --x6-- r6 --x9-- h2
               |         |         |         |
              x3-- r2 --x4        x7-- r5 --x8

两个 ECMP 点:

    点1: r1 -> h2 的流量走 r3(直连 x2) 或 r2(绕行 x3+x4)
    点2: r4 -> h2 的流量走 r6(直连 x6) 或 r5(绕行 x7+x8)

h1 -> h2 有 2*2 = 4 种路径组合. 用 netem 注入真值时延, 链路级 ping 采集确定性
观测, 单向 UDP 时间戳采集歧义观测, 最后跑 Design 2 推断并与真值对比.

用法:

    sudo python3 design2_ambiguous_mininet.py --test
"""
import argparse
import os
import re
import sys
import time

if os.geteuid() != 0:
    sys.exit("需要 root: sudo python3 design2_ambiguous_mininet.py --test")

from mininet.clean import cleanup
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node

from common import Router, add6, run_cmd, section
from design2 import author_infer, choice, infer, link
from mnlog import attach_file_log, detail, summary

# ---- 链路 id ----
X = ['x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9']

# ---- netem 单向链路真值 (TCLink 两端各装一次) ----
TRUTH = {
    'x1': 5, 'x2': 40, 'x3': 4, 'x4': 2, 'x5': 5,
    'x6': 20, 'x7': 4, 'x8': 3, 'x9': 5,
}

# ---- 地址 (每跳一个 /64) ----
H1 = '2001:db8:1::2'
R1_H = '2001:db8:1::1'
R1_R3 = '2001:db8:13::1'
R3_R1 = '2001:db8:13::3'
R1_R2 = '2001:db8:12::1'
R2_R1 = '2001:db8:12::2'
R2_R3 = '2001:db8:23::2'
R3_R2 = '2001:db8:23::3'
R3_R4 = '2001:db8:34::3'
R4_R3 = '2001:db8:34::4'
R4_R6 = '2001:db8:46::4'
R6_R4 = '2001:db8:46::6'
R4_R5 = '2001:db8:45::4'
R5_R4 = '2001:db8:45::5'
R5_R6 = '2001:db8:56::5'
R6_R5 = '2001:db8:56::6'
R6_H = '2001:db8:6::1'
H2 = '2001:db8:6::2'


def ping_ms(node, dst, count=6):
    """预热后取 ping 平均 RTT/2, 作为单向链路时延."""
    node.cmd("ping6 -c 2 -W 2 %s >/dev/null 2>&1" % dst)
    out = node.cmd("ping6 -c %d -W 2 %s" % (count, dst))
    m = re.search(r"rtt min/avg/max/mdev = [0-9.]+/([0-9.]+)/", out)
    if not m:
        summary("[WARN] ping failed: %s -> %s" % (node.name, dst))
        return None
    return float(m.group(1)) / 2.0


def sample_e2e(h1, h2, helper, samples=32):
    """单向 UDP 时间戳采样 h1->h2 端到端时延, 覆盖不同 ECMP 组合."""
    values = []
    for i in range(samples):
        source = "2001:db8:1::%x" % (0x10 + i)
        port = 20000 + i
        h2.cmd("python3 %s recv %d 6 3 > /tmp/d2a_recv_%d.txt 2>&1 &"
               % (helper, port, i))
        time.sleep(0.1)
        h1.cmd("python3 %s send %s %d %s 6 0.02 >/dev/null 2>&1"
               % (helper, H2, port, source))
        time.sleep(0.3)
        out = h2.cmd("cat /tmp/d2a_recv_%d.txt" % i)
        m = re.search(r"AVG_MS=([0-9.]+)", out)
        if m:
            values.append(round(float(m.group(1)), 1))
            detail("  ECMP sample source=%s one-way=%.1fms" % (source, values[-1]))
    return values


def cluster(values, gap=5.0):
    """按时延聚成若干组, 返回每组均值 (代表 4 种组合)."""
    groups = []
    for v in sorted(values):
        if groups and v - groups[-1][-1] <= gap:
            groups[-1].append(v)
        else:
            groups.append([v])
    return [sum(g) / len(g) for g in groups]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--epsilon", type=float, default=3.0)
    ap.add_argument("--log", default=None)
    args = ap.parse_args()
    setLogLevel("warning")
    logpath = attach_file_log("design2_ambiguous_mininet", args.log)
    summary(">>>>> log: %s" % logpath)

    here = os.path.dirname(os.path.abspath(__file__))
    oneway = os.path.join(here, "design2_oneway.py")

    cleanup()
    net = Mininet(controller=None, link=TCLink)
    h1 = net.addHost("h1", cls=Node, ip=None)
    r1 = net.addHost("r1", cls=Router, ip=None)
    r2 = net.addHost("r2", cls=Router, ip=None)
    r3 = net.addHost("r3", cls=Router, ip=None)
    r4 = net.addHost("r4", cls=Router, ip=None)
    r5 = net.addHost("r5", cls=Router, ip=None)
    r6 = net.addHost("r6", cls=Router, ip=None)
    h2 = net.addHost("h2", cls=Node, ip=None)

    net.addLink(h1, r1, intfName1="h1-eth0", intfName2="r1-eth1", delay="5ms")
    net.addLink(r1, r3, intfName1="r1-eth2", intfName2="r3-eth1", delay="40ms")
    net.addLink(r1, r2, intfName1="r1-eth3", intfName2="r2-eth1", delay="4ms")
    net.addLink(r2, r3, intfName1="r2-eth2", intfName2="r3-eth2", delay="2ms")
    net.addLink(r3, r4, intfName1="r3-eth3", intfName2="r4-eth1", delay="5ms")
    net.addLink(r4, r6, intfName1="r4-eth2", intfName2="r6-eth1", delay="20ms")
    net.addLink(r4, r5, intfName1="r4-eth3", intfName2="r5-eth1", delay="4ms")
    net.addLink(r5, r6, intfName1="r5-eth2", intfName2="r6-eth2", delay="3ms")
    net.addLink(r6, h2, intfName1="r6-eth3", intfName2="h2-eth0", delay="5ms")
    net.start()

    section("配置地址")
    add6(h1, "h1-eth0", H1 + "/64")
    for i in range(0x10, 0x30):     # 多源地址触发不同 ECMP hash
        add6(h1, "h1-eth0", "2001:db8:1::%x/64" % i, flush=False)
    add6(r1, "r1-eth1", R1_H + "/64")
    add6(r1, "r1-eth2", R1_R3 + "/64")
    add6(r1, "r1-eth3", R1_R2 + "/64")
    add6(r2, "r2-eth1", R2_R1 + "/64")
    add6(r2, "r2-eth2", R2_R3 + "/64")
    add6(r3, "r3-eth1", R3_R1 + "/64")
    add6(r3, "r3-eth2", R3_R2 + "/64")
    add6(r3, "r3-eth3", R3_R4 + "/64")
    add6(r4, "r4-eth1", R4_R3 + "/64")
    add6(r4, "r4-eth2", R4_R6 + "/64")
    add6(r4, "r4-eth3", R4_R5 + "/64")
    add6(r5, "r5-eth1", R5_R4 + "/64")
    add6(r5, "r5-eth2", R5_R6 + "/64")
    add6(r6, "r6-eth1", R6_R4 + "/64")
    add6(r6, "r6-eth2", R6_R5 + "/64")
    add6(r6, "r6-eth3", R6_H + "/64")
    add6(h2, "h2-eth0", H2 + "/64")

    section("配置前向路由 (含两个 ECMP 点)")
    run_cmd(h1, "ip -6 route add default via %s dev h1-eth0" % R1_H)
    run_cmd(h2, "ip -6 route add default via %s dev h2-eth0" % R6_H)
    # ECMP 点 1: r1 -> h2 走 r3(直连) 或 r2(绕行)
    run_cmd(r1, "ip -6 route add %s/128 nexthop via %s dev r1-eth2 "
           "nexthop via %s dev r1-eth3" % (H2, R3_R1, R2_R1))
    run_cmd(r2, "ip -6 route add %s/128 via %s dev r2-eth2" % (H2, R3_R2))
    run_cmd(r3, "ip -6 route add %s/128 via %s dev r3-eth3" % (H2, R4_R3))
    # ECMP 点 2: r4 -> h2 走 r6(直连) 或 r5(绕行)
    run_cmd(r4, "ip -6 route add %s/128 nexthop via %s dev r4-eth2 "
           "nexthop via %s dev r4-eth3" % (H2, R6_R4, R5_R4))
    run_cmd(r5, "ip -6 route add %s/128 via %s dev r5-eth2" % (H2, R6_R5))

    section("采集确定性链路观测 (RTT/2)")
    measured = {}
    for name, node, dst in (
            ('x1', h1, R1_H), ('x2', r1, R3_R1), ('x3', r1, R2_R1),
            ('x4', r2, R3_R2), ('x5', r3, R4_R3), ('x6', r4, R6_R4),
            ('x7', r4, R5_R4), ('x8', r5, R6_R5), ('x9', r6, H2)):
        measured[name] = ping_ms(node, dst)
        summary("[INFO] %s: measured = %.2f ms, truth = %.2f ms"
                % (name, measured[name], TRUTH[name]))

    section("采集 h1->h2 单向歧义观测")
    e2e_values = sample_e2e(h1, h2, oneway)
    summary("[INFO] 采到 %d 个端到端样本" % len(e2e_values))
    reps = cluster(e2e_values)
    summary("[INFO] 聚类成 %d 组, 代表时延: %s" % (len(reps), reps))

    # 期望 4 种组合时延
    expect = sorted([
        TRUTH['x1'] + TRUTH['x2'] + TRUTH['x5'] + TRUTH['x6'] + TRUTH['x9'],
        TRUTH['x1'] + TRUTH['x2'] + TRUTH['x5'] + TRUTH['x7'] + TRUTH['x8'] + TRUTH['x9'],
        TRUTH['x1'] + TRUTH['x3'] + TRUTH['x4'] + TRUTH['x5'] + TRUTH['x6'] + TRUTH['x9'],
        TRUTH['x1'] + TRUTH['x3'] + TRUTH['x4'] + TRUTH['x5'] + TRUTH['x7'] + TRUTH['x8'] + TRUTH['x9'],
    ])
    summary("[INFO] 理论 4 种组合时延: %s" % sorted(expect))

    section("Design 2 推断")
    observations = [(measured[l], [link(l)]) for l in X]
    e2e_segs = [
        link('x1'),
        choice([['x2'], ['x3', 'x4']]),
        link('x5'),
        choice([['x6'], ['x7', 'x8']]),
        link('x9'),
    ]
    for d in reps:
        observations.append((d, e2e_segs))

    ours = infer(X, observations, epsilon=args.epsilon)
    author = author_infer(observations, epsilon=args.epsilon)

    def mae(r):
        return sum(abs(r[l] - TRUTH[l]) for l in TRUTH) / len(TRUTH)

    for l in X:
        summary("[RESULT] %-3s: truth = %5.1f ms, measured = %5.2f ms, "
                "ours = %5.2f ms, author = %5.2f ms"
                % (l, TRUTH[l], measured[l], ours[l], author[l]))
    summary("[RESULT] MAE: ours = %.2f ms, author = %.2f ms" % (mae(ours), mae(author)))
    bn = [l for l in TRUTH if TRUTH[l] > 20]
    summary("[RESULT] bottleneck: truth = %s, ours = %s, author = %s"
            % (bn, [l for l in TRUTH if ours[l] > 20], [l for l in TRUTH if author[l] > 20]))

    section("完成")
    net.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
