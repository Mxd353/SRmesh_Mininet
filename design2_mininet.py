#!/usr/bin/env python3
r"""design2_mininet.py -- SRmesh Design 2 + Mininet 端到端验证
================================================================

拓扑对应论文例子 S--M--Q--T:


    h1(S) --x1-- r1(M) --x2-- r3(Q) --x5-- h2(T)
                   \           /
                   x3-- r2 --x4

r1 到 h2::2 使用 Linux IPv6 multipath route, 在 x2 和 x3+x4 之间按 flow label 做
ECMP. 确定性链路观测使用点到点地址; 歧义观测使用不同 IPv6 flow label 的 h1->h2
探测. 最后把实际时延转成 Design 2 的 Observation, 分别运行论文式推断和作者
greedy_grouped_inference.

用法:

    sudo python3 design2_mininet.py --test
    sudo python3 design2_mininet.py --test --capture
"""
import argparse
import os
import re
import sys
import time

if os.geteuid() != 0:
    sys.exit("需要 root:sudo python3 design2_mininet.py --test")

from mininet.clean import cleanup
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node

from design2 import author_infer, choice, infer, link
from mnlog import attach_file_log, detail, summary
from common import Router, add6, enable_seg6, run_cmd as run, section


X1, X2, X3, X4, X5 = "x1", "x2", "x3", "x4", "x5"
H1 = "2001:db8:1::2"
R1_H = "2001:db8:1::1"
R1_R3 = "2001:db8:13::1"
R3_R1 = "2001:db8:13::3"
R1_R2 = "2001:db8:12::1"
R2_R1 = "2001:db8:12::2"
R2_R3 = "2001:db8:23::2"
R3_R2 = "2001:db8:23::3"
R3_H = "2001:db8:3::1"
H2_ECMP = "2001:db8:3::2"
H2_SR = "2001:db8:3::3"

# netem 的单向链路真值(TCLink 会在两端安装相同延迟)
TRUTH = {X1: 5.0, X2: 30.0, X3: 4.0, X4: 2.0, X5: 5.0}


def ping_ms(node, dst, flow=None, source=None, count=6):
    """预热后取 ping 平均 RTT/2,作为对称路径的单向时延观测."""
    flow_arg = " -F %d" % flow if flow is not None else ""
    src_arg = " -I %s" % source if source is not None else ""
    node.cmd("ping6 -c 2 -W 2%s%s %s >/dev/null 2>&1" %
             (flow_arg, src_arg, dst))
    out = node.cmd("ping6 -c %d -W 2%s%s %s" %
                   (count, flow_arg, src_arg, dst))
    m = re.search(r"rtt min/avg/max/mdev = [0-9.]+/([0-9.]+)/", out)
    if not m:
        summary("[WARN] ping failed: %s -> %s" % (node.name, dst))
        detail(out.strip())
        return None
    return float(m.group(1)) / 2.0


def choose_ecmp_samples(h1, h2, expected, samples=12):
    """采集 ECMP 样本并按测得时延聚成两组.

    使用单向 UDP 时间戳, 避免 ping RTT/2 被非对称回程污染. 这里只用测量值
    选择代表样本, 不把分支标签写入算法输入; 输入仍是
    同一个 choice([x1+x2+x5, x1+x3+x4+x5]) 约束.
    """
    values = []
    helper = os.path.join(os.path.dirname(os.path.abspath(__file__)), "design2_oneway.py")
    for i in range(samples):
        # WSL2 中 ping6 -F 可能没有 IPV6_FLOWLABEL_MGR 权限;改变源地址
        # 同样会改变 Linux ECMP 的 flow hash,且不需要特殊 capability.
        source = "2001:db8:1::%x" % (0x10 + i)
        port = 19000 + i
        h1.cmd("true")
        # 接收端时间戳减发送端时间戳,避免 RTT/2 被反向 ECMP 路径污染.
        h2.cmd("python3 %s recv %d 8 3 > /tmp/d2_recv_%d.txt 2>&1 &"
               % (helper, port, i))
        time.sleep(0.15)
        h1.cmd("python3 %s send %s %d %s 8 0.03 >/dev/null 2>&1"
               % (helper, H2_ECMP, port, source))
        time.sleep(0.4)
        out = h2.cmd("cat /tmp/d2_recv_%d.txt" % i)
        match = re.search(r"AVG_MS=([0-9.]+)", out)
        ms = float(match.group(1)) if match else None
        if ms is not None:
            values.append((source, ms))
            summary("[INFO] ECMP source = %s, one-way = %.2f ms" % (source, ms))
    if len(values) < 2:
        return values
    values.sort(key=lambda x: x[1])
    # 选低/高两个代表样本,实际分支由 flow hash 决定.
    return [values[0], values[-1]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--epsilon", type=float, default=3.0,
                    help="时延聚类阈值,默认 3ms")
    ap.add_argument("--log", default=None)
    args = ap.parse_args()
    setLogLevel("warning")
    logpath = attach_file_log("design2_mininet", args.log)
    summary(">>>>> log: %s" % logpath)

    cleanup()
    net = Mininet(controller=None, link=TCLink)
    h1 = net.addHost("h1", cls=Node, ip=None)
    r1 = net.addHost("r1", cls=Router, ip=None)
    r2 = net.addHost("r2", cls=Router, ip=None)
    r3 = net.addHost("r3", cls=Router, ip=None)
    h2 = net.addHost("h2", cls=Node, ip=None)

    net.addLink(h1, r1, intfName1="h1-eth0", intfName2="r1-eth1", delay="5ms")
    net.addLink(r1, r3, intfName1="r1-eth2", intfName2="r3-eth1", delay="30ms")
    net.addLink(r1, r2, intfName1="r1-eth3", intfName2="r2-eth1", delay="4ms")
    net.addLink(r2, r3, intfName1="r2-eth2", intfName2="r3-eth2", delay="2ms")
    net.addLink(r3, h2, intfName1="r3-eth3", intfName2="h2-eth0", delay="5ms")
    net.start()

    section("配置地址和基础路由")
    add6(h1, "h1-eth0", H1 + "/64")
    # 用多个源地址替代 flow label,触发不同 ECMP hash(兼容 WSL2).
    for i in range(0x10, 0x1c):
        add6(h1, "h1-eth0", "2001:db8:1::%x/64" % i, flush=False)
    add6(r1, "r1-eth1", R1_H + "/64")
    add6(r1, "r1-eth2", R1_R3 + "/64")
    add6(r1, "r1-eth3", R1_R2 + "/64")
    add6(r2, "r2-eth1", R2_R1 + "/64")
    add6(r2, "r2-eth2", R2_R3 + "/64")
    add6(r3, "r3-eth1", R3_R1 + "/64")
    add6(r3, "r3-eth2", R3_R2 + "/64")
    add6(r3, "r3-eth3", R3_H + "/64")
    add6(h2, "h2-eth0", H2_ECMP + "/64")
    add6(h2, "h2-eth0", H2_SR + "/64", flush=False)
    for node, ifaces in ((r1, ["r1-eth1", "r1-eth2", "r1-eth3"]),
                          (r2, ["r2-eth1", "r2-eth2"]),
                          (r3, ["r3-eth1", "r3-eth2", "r3-eth3"])):
        enable_seg6(node, ifaces)

    run(h1, "ip -6 route add default via %s dev h1-eth0" % R1_H)
    run(h2, "ip -6 route add default via %s dev h2-eth0" % R3_H)
    # 下一跳必须是对端地址,不能写成本机接口地址.
    run(r2, "ip -6 route add 2001:db8:1::/64 via %s dev r2-eth1" % R1_R2)
    run(r3, "ip -6 route add 2001:db8:1::/64 via %s dev r3-eth1" % R1_R3)
    run(r3, "ip -6 route add 2001:db8:12::/64 via %s dev r3-eth2" % R2_R3)
    run(r2, "ip -6 route add 2001:db8:3::/64 via %s dev r2-eth2" % R3_R2)

    # 回程也配置同构 multipath,避免用 RTT/2 时把正向分支和固定回程
    # 混在一起.Linux 的 IPv6 ECMP 使用对称 flow hash 时会倾向选择
    # 镜像路径:r3->r1 或 r3->r2->r1.
    run(r3, "ip -6 route replace 2001:db8:1::/64 "
        "nexthop via %s dev r3-eth1 nexthop via %s dev r3-eth2" %
        (R1_R3, R2_R3))

    # r1->h2::2 的普通 ECMP:直连 x2 或绕行 x3+x4.
    run(r1, "ip -6 route add %s/128 nexthop via %s dev r1-eth2 "
        "nexthop via %s dev r1-eth3" % (H2_ECMP, R3_R1, R2_R1))

    # 一个真实 SRv6 定向路径,用来证明"确定性观测"和 ECMP 观测不同.
    r3_sid = "2001:db8:100::3"
    run(r3, "ip -6 route add %s/128 encap seg6local action End.DX6 nh6 %s dev r3-eth3"
        % (r3_sid, H2_SR))
    run(r1, "ip -6 route add %s/128 via %s dev r1-eth2" % (r3_sid, R3_R1))
    run(h1, "ip -6 route add %s/128 encap seg6 mode encap segs %s dev h1-eth0"
        % (H2_SR, r3_sid))

    section("采集确定性链路观测(RTT/2)")
    measured = {}
    for name, node, dst in ((X1, h1, R1_H), (X2, r1, R3_R1),
                             (X3, r1, R2_R1), (X4, r2, R3_R2),
                             (X5, r3, H2_ECMP)):
        measured[name] = ping_ms(node, dst)
        summary("[INFO] %s: measured = %.2f ms, truth = %.2f ms" %
                (name, measured[name], TRUTH[name]))

    section("采集 SR 定向观测")
    sr_ms = ping_ms(h1, H2_SR)
    if sr_ms is None:
        summary("[WARN] SR directed probe failed; continue with link and ECMP observations")
    else:
        summary("[INFO] SR directed: one-way = %.2f ms, expected = %.2f ms" %
                (sr_ms, TRUTH[X1] + TRUTH[X2] + TRUTH[X5]))

    section("采集普通 ECMP 歧义观测")
    ecmp = choose_ecmp_samples(h1, h2, H2_ECMP)
    if len(ecmp) < 2:
        summary("[FAIL] fewer than two ECMP samples")
        net.stop()
        return 1

    # 将实际测量的代表值输入为两条同构的歧义约束;不告诉算法每个样本的真实分支.
    fixed = [
        (measured[X1], [link(X1)]),
        (measured[X5], [link(X5)]),
        (measured[X2], [link(X2)]),
        (measured[X3], [link(X3)]),
        (measured[X4], [link(X4)]),
    ]
    ambiguous = []
    for _, one_way in ecmp:
        ambiguous.append((one_way, [
            link(X1),
            choice([[X2], [X3, X4]]),
            link(X5),
        ]))
    observations = fixed + ambiguous

    section("Design 2 推断(epsilon=%.2fms)" % args.epsilon)
    ours = infer([X1, X2, X3, X4, X5], observations, epsilon=args.epsilon)
    author = author_infer(observations, epsilon=args.epsilon)
    for name in (X1, X2, X3, X4, X5):
        summary("[RESULT] %-2s: truth = %6.2f ms, measured = %6.2f ms, ours = %6.2f ms, author = %6.2f ms" %
                (name, TRUTH[name], measured[name], ours[name], author[name]))

    mae_ours = sum(abs(ours[x] - TRUTH[x]) for x in TRUTH) / len(TRUTH)
    mae_author = sum(abs(author[x] - TRUTH[x]) for x in TRUTH) / len(TRUTH)
    summary("[RESULT] MAE: ours = %.3f ms, author = %.3f ms" %
            (mae_ours, mae_author))
    bottleneck = [x for x in TRUTH if TRUTH[x] > 20]
    pred_ours = [x for x in TRUTH if ours[x] > 20]
    pred_author = [x for x in TRUTH if author[x] > 20]
    summary("[RESULT] bottleneck: truth = %s, ours = %s, author = %s" %
            (bottleneck, pred_ours, pred_author))

    section("完成")
    net.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
