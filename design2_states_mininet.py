#!/usr/bin/env python3
r"""design2_states_mininet.py -- 覆盖 A/B/C/D 四种分支状态的端到端验证
================================================================

用一条链式拓扑放三个 ECMP 点, 每个点的锚点配置不同, 从而在一次运行里同时命中
Design 2 Phase 2 的四种分支状态:

    h1 -e0- r0 =={ x1 | x2-rr1-x3 }== r1 -e1- r2
            =={ x4 | x5-rr2-x6 }== r3 -e2- r4
            =={ x7 | x8 }== r5 -e3- h2

三个 ECMP 点 (探测: 源节点 -> 目的节点的 lo 地址, 一次只走一条分支):

    Diamond-1 (r0->r1)  分支 {x1 | x2+x3},  锚 x1,x2, 不锚 x3
        短样本(x1)     -> 情形 A (全已知, 幂等空转)
        长样本(x2+x3)  -> 情形 C (单未知, 反解 x3)
    Diamond-2 (r2->r3)  分支 {x4 | x5+x6},  锚 x4(瓶颈), 不锚 x5,x6
        长样本(x5+x6)  -> 情形 D (多未知, 只能给"和")
    Diamond-3 (r4->r5)  分支 {x7 | x8},     两分支都不锚
        任一样本      -> 情形 B (两分支都无锚点, 不可辨识)

确定性锚点用相邻链路 ping 的 RTT/2; 歧义观测用单向 UDP 时间戳, 靠不同源地址触发
不同 ECMP 分支. 输入只给测量值, 不泄漏分支标签.

用法:

    sudo python3 design2_states_mininet.py --test
"""
import argparse
import os
import re
import sys
import time

if os.geteuid() != 0:
    sys.exit("需要 root: sudo python3 design2_states_mininet.py --test")

from mininet.clean import cleanup
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node

from common import Router, add6, print_topology, run_cmd, section
from design2 import choice, infer, link
from mnlog import attach_file_log, detail, summary

# ---- 链路 id 与真值 (netem 单向时延, ms) ----
E0, X1, X2, X3 = 'e0', 'x1', 'x2', 'x3'
E1, X4, X5, X6 = 'e1', 'x4', 'x5', 'x6'
E2, X7, X8, E3 = 'e2', 'x7', 'x8', 'e3'

ALL = [E0, X1, X2, X3, E1, X4, X5, X6, E2, X7, X8, E3]
TRUTH = {E0: 5, X1: 4, X2: 14, X3: 3, E1: 5, X4: 60,
         X5: 3, X6: 3, E2: 5, X7: 5, X8: 7, E3: 5}
ANCHORS = [E0, X1, X2, E1, X4, E2, E3]

# ---- 地址 (每跳一个 /64) ----
H1, R0_H1 = '2001:db8:0::2', '2001:db8:0::1'
R0_X1, R1_X1 = '2001:db8:1::1', '2001:db8:1::2'
R0_X2, RR1_X2 = '2001:db8:2::1', '2001:db8:2::2'
RR1_X3, R1_X3 = '2001:db8:3::1', '2001:db8:3::2'
R1_E1, R2_E1 = '2001:db8:4::1', '2001:db8:4::2'
R2_X4, R3_X4 = '2001:db8:5::1', '2001:db8:5::2'
R2_X5, RR2_X5 = '2001:db8:6::1', '2001:db8:6::2'
RR2_X6, R3_X6 = '2001:db8:7::1', '2001:db8:7::2'
R3_E2, R4_E2 = '2001:db8:8::1', '2001:db8:8::2'
R4_X7, R5_X7 = '2001:db8:9::1', '2001:db8:9::2'
R4_X8, R5_X8 = '2001:db8:10::1', '2001:db8:10::2'
R5_E3, H2 = '2001:db8:11::1', '2001:db8:11::2'

# 目的节点的 lo 地址 (ECMP 目标)
R1_LO, R3_LO, R5_LO = '2001:db8:100::1', '2001:db8:300::1', '2001:db8:500::1'

# 三个 ECMP 点: (名称, 源节点, 目的节点, 目的 lo, 分支, 端口基址, 源地址池前缀)
DIAMONDS = [
    ('diamond-1', 'r0', 'r1', R1_LO, [[X1], [X2, X3]], 20000, '2001:db8:a0'),
    ('diamond-2', 'r2', 'r3', R3_LO, [[X4], [X5, X6]], 21000, '2001:db8:b0'),
    ('diamond-3', 'r4', 'r5', R5_LO, [[X7], [X8]],     22000, '2001:db8:c0'),
]


def ping_ms(node, dst, count=6):
    """预热后取 ping 平均 RTT/2, 作为相邻链路的单向时延锚点."""
    node.cmd("ping6 -c 2 -W 2 %s >/dev/null 2>&1" % dst)
    out = node.cmd("ping6 -c %d -W 2 %s" % (count, dst))
    m = re.search(r"rtt min/avg/max/mdev = [0-9.]+/([0-9.]+)/", out)
    if not m:
        summary("[WARN] ping failed: %s -> %s" % (node.name, dst))
        return None
    return float(m.group(1)) / 2.0


def sample_branch(src, dst, helper, dest_addr, port_base, pool, samples=24):
    """单向 UDP 时间戳采样 src->dst, 靠不同源地址触发不同 ECMP 分支."""
    values = []
    for i in range(samples):
        source = "%s::%x" % (pool, 0x10 + i)
        port = port_base + i
        dst.cmd("python3 %s recv %d 6 3 > /tmp/d2s_%d.txt 2>&1 &"
                % (helper, port, port))
        time.sleep(0.1)
        src.cmd("python3 %s send %s %d %s 6 0.02 >/dev/null 2>&1"
                % (helper, dest_addr, port, source))
        time.sleep(0.3)
        out = dst.cmd("cat /tmp/d2s_%d.txt" % port)
        m = re.search(r"AVG_MS=([0-9.]+)", out)
        if m:
            values.append(round(float(m.group(1)), 1))
            detail("  %s sample src=%s -> %.1f ms" % (src.name, source, values[-1]))
    return values


def cluster(values, gap=5.0):
    """按时延聚成若干组, 返回每组均值 (每个均值代表一条分支的观测)."""
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
    ap.add_argument("--samples", type=int, default=24)
    ap.add_argument("--log", default=None)
    args = ap.parse_args()
    setLogLevel("warning")
    logpath = attach_file_log("design2_states_mininet", args.log)
    summary(">>>>> log: %s" % logpath)

    here = os.path.dirname(os.path.abspath(__file__))
    oneway = os.path.join(here, "design2_oneway.py")

    cleanup()
    net = Mininet(controller=None, link=TCLink)
    h1 = net.addHost("h1", cls=Node, ip=None)
    r0 = net.addHost("r0", cls=Router, ip=None)
    rr1 = net.addHost("rr1", cls=Router, ip=None)
    r1 = net.addHost("r1", cls=Router, ip=None)
    r2 = net.addHost("r2", cls=Router, ip=None)
    rr2 = net.addHost("rr2", cls=Router, ip=None)
    r3 = net.addHost("r3", cls=Router, ip=None)
    r4 = net.addHost("r4", cls=Router, ip=None)
    r5 = net.addHost("r5", cls=Router, ip=None)
    h2 = net.addHost("h2", cls=Node, ip=None)

    net.addLink(h1, r0, intfName1="h1-eth0", intfName2="r0-eth0", delay="5ms")
    net.addLink(r0, r1, intfName1="r0-eth1", intfName2="r1-eth0", delay="4ms")
    net.addLink(r0, rr1, intfName1="r0-eth2", intfName2="rr1-eth0", delay="14ms")
    net.addLink(rr1, r1, intfName1="rr1-eth1", intfName2="r1-eth1", delay="3ms")
    net.addLink(r1, r2, intfName1="r1-eth2", intfName2="r2-eth0", delay="5ms")
    net.addLink(r2, r3, intfName1="r2-eth1", intfName2="r3-eth0", delay="60ms")
    net.addLink(r2, rr2, intfName1="r2-eth2", intfName2="rr2-eth0", delay="3ms")
    net.addLink(rr2, r3, intfName1="rr2-eth1", intfName2="r3-eth1", delay="3ms")
    net.addLink(r3, r4, intfName1="r3-eth2", intfName2="r4-eth0", delay="5ms")
    net.addLink(r4, r5, intfName1="r4-eth1", intfName2="r5-eth0", delay="5ms")
    net.addLink(r4, r5, intfName1="r4-eth2", intfName2="r5-eth1", delay="7ms")
    net.addLink(r5, h2, intfName1="r5-eth2", intfName2="h2-eth0", delay="5ms")
    net.start()

    section("配置地址")
    add6(h1, "h1-eth0", H1 + "/64")
    add6(r0, "r0-eth0", R0_H1 + "/64")
    add6(r0, "r0-eth1", R0_X1 + "/64")
    add6(r0, "r0-eth2", R0_X2 + "/64")
    add6(rr1, "rr1-eth0", RR1_X2 + "/64")
    add6(rr1, "rr1-eth1", RR1_X3 + "/64")
    add6(r1, "r1-eth0", R1_X1 + "/64")
    add6(r1, "r1-eth1", R1_X3 + "/64")
    add6(r1, "r1-eth2", R1_E1 + "/64")
    add6(r2, "r2-eth0", R2_E1 + "/64")
    add6(r2, "r2-eth1", R2_X4 + "/64")
    add6(r2, "r2-eth2", R2_X5 + "/64")
    add6(rr2, "rr2-eth0", RR2_X5 + "/64")
    add6(rr2, "rr2-eth1", RR2_X6 + "/64")
    add6(r3, "r3-eth0", R3_X4 + "/64")
    add6(r3, "r3-eth1", R3_X6 + "/64")
    add6(r3, "r3-eth2", R3_E2 + "/64")
    add6(r4, "r4-eth0", R4_E2 + "/64")
    add6(r4, "r4-eth1", R4_X7 + "/64")
    add6(r4, "r4-eth2", R4_X8 + "/64")
    add6(r5, "r5-eth0", R5_X7 + "/64")
    add6(r5, "r5-eth1", R5_X8 + "/64")
    add6(r5, "r5-eth2", R5_E3 + "/64")
    add6(h2, "h2-eth0", H2 + "/64")
    # 目的节点的 lo 地址 (ECMP 目标) 与各源的地址池 (触发不同 hash)
    for node, addr in ((r1, R1_LO), (r3, R3_LO), (r5, R5_LO)):
        run_cmd(node, "ip -6 addr add %s/128 dev lo nodad" % addr)
    for name, src, _, _, _, _, pool in DIAMONDS:
        src_node = {"r0": r0, "r2": r2, "r4": r4}[src]
        dev = {"r0": "r0-eth0", "r2": "r2-eth0", "r4": "r4-eth0"}[src]
        for i in range(args.samples):
            add6(src_node, dev, "%s::%x/64" % (pool, 0x10 + i), flush=False)

    section("配置三个 ECMP 点的路由")
    # Diamond-1: r0 -> r1.lo, 直连 x1 或绕行 x2+x3
    run_cmd(r0, "ip -6 route add %s/128 nexthop via %s dev r0-eth1 "
           "nexthop via %s dev r0-eth2" % (R1_LO, R1_X1, RR1_X2))
    run_cmd(rr1, "ip -6 route add %s/128 via %s dev rr1-eth1" % (R1_LO, R1_X3))
    # Diamond-2: r2 -> r3.lo, 直连 x4 或绕行 x5+x6
    run_cmd(r2, "ip -6 route add %s/128 nexthop via %s dev r2-eth1 "
           "nexthop via %s dev r2-eth2" % (R3_LO, R3_X4, RR2_X5))
    run_cmd(rr2, "ip -6 route add %s/128 via %s dev rr2-eth1" % (R3_LO, R3_X6))
    # Diamond-3: r4 -> r5.lo, 两条并行直连 x7 / x8
    run_cmd(r4, "ip -6 route add %s/128 nexthop via %s dev r4-eth1 "
           "nexthop via %s dev r4-eth2" % (R5_LO, R5_X7, R5_X8))

    print_topology(net, '拓扑 (三个 ECMP 点: 覆盖 A/B/C/D)')
    section("采集确定性锚点 (RTT/2)")
    measured = {}
    for name, node, dst in ((E0, h1, R0_H1), (X1, r0, R1_X1), (X2, r0, RR1_X2),
                            (E1, r1, R2_E1), (X4, r2, R3_X4), (E2, r3, R4_E2),
                            (E3, r5, H2)):
        measured[name] = ping_ms(node, dst)
        summary("[INFO] 锚点 %-3s: measured = %s ms, truth = %.1f ms"
                % (name, measured[name], TRUTH[name]))

    section("采集三个 ECMP 点的歧义观测 (单向时间戳)")
    nodes = {"r0": r0, "r1": r1, "r2": r2, "r3": r3, "r4": r4, "r5": r5}
    reps_by_diamond = {}
    for name, src, dstn, dest_addr, branches, port_base, pool in DIAMONDS:
        values = sample_branch(nodes[src], nodes[dstn], oneway, dest_addr,
                               port_base, pool, args.samples)
        reps = cluster(values)
        reps_by_diamond[name] = reps
        summary("[INFO] %s: 采到 %d 样本, 聚成 %d 组, 代表时延 = %s ms"
                % (name, len(values), len(reps), reps))

    section("Design 2 推断 (epsilon=%.1f ms)" % args.epsilon)
    observations = [(measured[l], [link(l)]) for l in ANCHORS
                    if measured[l] is not None]
    for name, src, dstn, dest_addr, branches, port_base, pool in DIAMONDS:
        for d in reps_by_diamond[name]:
            observations.append((d, [choice(branches)]))

    trace = []
    result = infer(ALL, observations, epsilon=args.epsilon, trace=trace)

    # ---- 分支状态覆盖报告 ----
    covered = {}
    for t in trace:
        covered.setdefault(t['state'], t)
    summary("[RESULT] 分支状态覆盖: %s (共 %d 次歧义解析)"
            % (''.join(sorted(covered)), len(trace)))
    for s, label in (('A', '全已知(幂等)'), ('B', '两分支都无锚点(不可辨识)'),
                     ('C', '单未知(反解)'), ('D', '多未知(只能给和)')):
        t = covered.get(s)
        if t:
            summary("[RESULT] 情形 %s %-22s: delay=%5.1f ms, unk=%s"
                    % (s, label, t['delay'], t['unk']))
        else:
            summary("[WARN] 情形 %s %-22s: 未触发" % (s, label))

    # ---- 链路推断对比 ----
    for l in ALL:
        if l in ANCHORS:
            summary("[RESULT] %-3s: truth = %5.1f ms, anchor = %5.2f ms, "
                    "infer = %5.2f ms" % (l, TRUTH[l], measured[l], result[l]))
        else:
            summary("[RESULT] %-3s: truth = %5.1f ms, infer = %5.2f ms "
                    "(未锚定; D/B 不产生新信息, 走兜底均值)"
                    % (l, TRUTH[l], result[l]))

    section("完成")
    net.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
