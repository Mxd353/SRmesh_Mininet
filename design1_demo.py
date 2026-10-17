#!/usr/bin/env python3
r"""design1_demo.py -- SRmesh Design 1 确定性 SR 环回探测 (Mininet 实现)
================================================================

拓扑 (钻石):

    h1 -- r1 --<  r2  >-- r4 -- h2
                 \ r3 /

Design 1 机制:

    正向: h1 用内核 SRv6 route 封装 (SID 列表 = [r2_sid, r4_sid]), 经 r2, r4 解封装到 h2.
    反向: h1 把反向 SID 列表 [r3_sid, r1_sid] 藏在 payload 里, h2 的响应端取出反向列表, 重建 SRH, 经 r3, r1 解封装到 h1.
    结果: 双向路径都被钉死, 一个包只带一个 SRH.

用法:

    sudo python3 design1_demo.py            # 跑一次环回探测并展示
    sudo python3 design1_demo.py --capture  # 额外抓包对比正向/反向 SRH
"""
import argparse
import os
import re
import socket
import sys
import time

if os.geteuid() != 0:
    sys.exit("[FATAL] 需要 root 权限, 请用: sudo python3 design1_demo.py")

from mininet.net import Mininet
from mininet.node import Node
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.clean import cleanup

from mnlog import attach_file_log, detail, summary
from common import Router, add6, enable_seg6, print_topology, run_cmd as run, section

# ---- 地址 ----
H1_ADDR = '2001:db8:1::2/64'
H1_IP   = '2001:db8:1::2'
R1_E1   = '2001:db8:1::1/64'
R1_E1_IP = '2001:db8:1::1'
R1_E2   = '2001:db8:12::1/64'
R1_E2_IP = '2001:db8:12::1'
R2_E1   = '2001:db8:12::2/64'
R2_E2   = '2001:db8:24::2/64'
R4_E1_IP = '2001:db8:24::4'
R4_E1   = '2001:db8:24::4/64'
R1_E3   = '2001:db8:13::1/64'
R1_E3_IP = '2001:db8:13::1'
R3_E1   = '2001:db8:13::3/64'
R3_E2   = '2001:db8:34::3/64'
R4_E2_IP = '2001:db8:34::4'
R4_E2   = '2001:db8:34::4/64'
R4_E3   = '2001:db8:2::1/64'
H2_ADDR = '2001:db8:2::2/64'
H2_IP   = '2001:db8:2::2'

# 4 个 node SID
R1_SID = '2001:db8:100::1'
R2_SID = '2001:db8:100::2'
R3_SID = '2001:db8:100::3'
R4_SID = '2001:db8:100::4'

# 正向 / 反向 SID 列表
FWD_SEGS = [R2_SID, R4_SID]     # h1 -> r2 -> r4 -> h2   (低时延)
REV_SEGS = [R3_SID, R1_SID]     # h2 -> r3 -> r1 -> h1   (高时延, 反向)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--capture', action='store_true')
    ap.add_argument('--ebpf', action='store_true',
                    help='用内核态 TC eBPF 响应端 (替代用户态), 探测走协议 253')
    ap.add_argument('--proto', type=int, default=253)
    ap.add_argument('--port', type=int, default=9999)
    ap.add_argument('--count', type=int, default=4)
    ap.add_argument('--log', default=None)
    args = ap.parse_args()

    setLogLevel('warning')
    lp = attach_file_log('design1_demo', args.log)
    if lp:
        summary('>>>>> log: %s' % lp)

    here = os.path.dirname(os.path.abspath(__file__))
    probe_py = os.path.join(here, 'design1_probe.py')

    section('构建钻石拓扑')
    cleanup()
    net = Mininet(controller=None, link=TCLink)
    h1 = net.addHost('h1', cls=Node, ip=None)
    r1 = net.addHost('r1', cls=Router, ip=None)
    r2 = net.addHost('r2', cls=Router, ip=None)
    r3 = net.addHost('r3', cls=Router, ip=None)
    r4 = net.addHost('r4', cls=Router, ip=None)
    h2 = net.addHost('h2', cls=Node, ip=None)

    net.addLink(h1, r1, intfName1='h1-eth0', intfName2='r1-eth1', delay='1ms')
    net.addLink(r1, r2, intfName1='r1-eth2', intfName2='r2-eth1', delay='2ms')
    net.addLink(r2, r4, intfName1='r2-eth2', intfName2='r4-eth1', delay='2ms')
    net.addLink(r1, r3, intfName1='r1-eth3', intfName2='r3-eth1', delay='20ms')
    net.addLink(r3, r4, intfName1='r3-eth2', intfName2='r4-eth2', delay='20ms')
    net.addLink(r4, h2, intfName1='r4-eth3', intfName2='h2-eth0', delay='1ms')
    net.start()

    section('配置地址')
    add6(h1, 'h1-eth0', H1_ADDR)
    add6(r1, 'r1-eth1', R1_E1)
    add6(r1, 'r1-eth2', R1_E2)
    add6(r1, 'r1-eth3', R1_E3)
    add6(r2, 'r2-eth1', R2_E1)
    add6(r2, 'r2-eth2', R2_E2)
    add6(r3, 'r3-eth1', R3_E1)
    add6(r3, 'r3-eth2', R3_E2)
    add6(r4, 'r4-eth1', R4_E1)
    add6(r4, 'r4-eth2', R4_E2)
    add6(r4, 'r4-eth3', R4_E3)
    add6(h2, 'h2-eth0', H2_ADDR)

    for n, ifs in ((r1, ['r1-eth1', 'r1-eth2', 'r1-eth3']),
                   (r2, ['r2-eth1', 'r2-eth2']),
                   (r3, ['r3-eth1', 'r3-eth2']),
                   (r4, ['r4-eth1', 'r4-eth2', 'r4-eth3'])):
        enable_seg6(n, ifs)

    section('SID 行为 (End.X 中转 / End.DX6 端点)')
    # 端点: SID 命中后解封装, 交付给直连主机
    run(r4, 'ip -6 route add %s/128 encap seg6local action End.DX6 nh6 %s dev r4-eth3'
            % (R4_SID, H2_IP))
    run(r1, 'ip -6 route add %s/128 encap seg6local action End.DX6 nh6 %s dev r1-eth1'
            % (R1_SID, H1_IP))
    # 中转: SID 命中后 SL-- 并转发到下一跳
    run(r2, 'ip -6 route add %s/128 encap seg6local action End.X nh6 %s dev r2-eth2'
            % (R2_SID, R4_E1_IP))
    run(r3, 'ip -6 route add %s/128 encap seg6local action End.X nh6 %s dev r3-eth1'
            % (R3_SID, R1_E3_IP))

    section('转发路由 (非 SID 节点按 FIB 转发)')
    # r1 把去 r2_sid 的包送到 r2 (正向首段)
    run(r1, 'ip -6 route add %s/128 via %s dev r1-eth2' % (R2_SID, '2001:db8:12::2'))
    # r4 把去 r3_sid 的包送到 r3 (反向首段)
    run(r4, 'ip -6 route add %s/128 via %s dev r4-eth2' % (R3_SID, '2001:db8:34::3'))

    section('端点主机: 正向用内核 SRv6 封装')
    run(h1, 'ip -6 route add default via %s dev h1-eth0' % R1_E1_IP)
    run(h2, 'ip -6 route add default via 2001:db8:2::1 dev h2-eth0')
    # 到首段 SID 的路由 (封装后外层查 main 表)
    run(h1, 'ip -6 route add %s/128 via %s dev h1-eth0' % (R2_SID, R1_E1_IP))
    # 对 h2 的流量做 encap, SID 列表 = 正向列表
    run(h1, 'ip -6 route add %s/128 encap seg6 mode encap segs %s dev h1-eth0'
            % (H2_IP, ','.join(FWD_SEGS)))

    section('自检: h1 封装路由 / r1 的 SID')
    run(h1, 'ip -6 route get %s' % H2_IP)

    # NDP 预热
    h1.cmd('ping6 -c 2 -W 2 -I %s %s >/dev/null 2>&1' % (H1_IP, H2_IP))
    h2.cmd('ping6 -c 2 -W 2 2001:db8:2::1 >/dev/null 2>&1')

    h2_mac = h2.cmd('cat /sys/class/net/h2-eth0/address').strip()
    r4_mac = r4.cmd('cat /sys/class/net/r4-eth3/address').strip()
    detail('  h2-eth0 MAC = %s, r4-eth3 MAC = %s' % (h2_mac, r4_mac))

    print_topology(net, '拓扑 (钻石: h1-r1-(r2|r3)-r4-h2)')
    if args.ebpf:
        section('生成 eBPF 配置头并编译')
        cfg_path = os.path.join(here, 'design1_responder_cfg.h')
        with open(cfg_path, 'w') as f:
            f.write('#pragma once\n')
            f.write('#define CFG_H2_MAC { %s }\n'
                    % ','.join('0x%02x' % b for b in bytes.fromhex(h2_mac.replace(':', ''))))
            f.write('#define CFG_R4_MAC { %s }\n'
                    % ','.join('0x%02x' % b for b in bytes.fromhex(r4_mac.replace(':', ''))))
            f.write('#define CFG_H2_IP  { %s }\n'
                    % ','.join('0x%02x' % b for b in socket.inet_pton(socket.AF_INET6, H2_IP)))
            ifidx = h2.cmd('cat /sys/class/net/h2-eth0/ifindex').strip() or '2'
            f.write('#define CFG_IFINDEX %s\n' % ifidx)
        bpf_c = os.path.join(here, 'design1_responder.bpf.c')
        bpf_o = os.path.join(here, 'design1_responder.bpf.o')
        cc = ('clang -O2 -g -target bpf -I%s -I/usr/include/x86_64-linux-gnu '
              '-c %s -o %s' % (here, bpf_c, bpf_o))
        detail('  $ %s' % cc)
        if os.system(cc) != 0:
            summary('[FAIL] eBPF compile failed')
            net.stop()
            return
        summary('[OK] eBPF compiled: %s' % bpf_o)

        section('挂载 TC eBPF 到 h2-eth0 ingress')
        run(h2, 'tc qdisc add dev h2-eth0 clsact')
        run(h2, 'tc filter add dev h2-eth0 ingress bpf obj %s sec tc direct-action' % bpf_o)
        run(h2, 'tc filter show dev h2-eth0 ingress')

    caps = []
    if args.capture:
        section('启动抓包 (正向 r1-eth2 / 反向 r4-eth2)')
        for node, iface, tag, filt in (
                (r1, 'r1-eth2', 'fwd', '"ip6 proto 43"'),
                (r2, 'r2-eth1', 'r2in', ''),
                (r4, 'r4-eth3', 'r4e3', ''),
                (h2, 'h2-eth0', 'h2in', ''),
                (r4, 'r4-eth2', 'rev', '"ip6 proto 43"')):
            node.cmd('rm -f /tmp/d1_%s.txt' % tag)
            extra = (' ' + filt) if filt else ''
            node.cmd('tcpdump -l -i %s -n -c 3 -vv%s > /tmp/d1_%s.txt 2>&1 &'
                     % (iface, extra, tag))
            caps.append((node, tag))
        time.sleep(1.0)

    if args.ebpf:
        section('发起环回探测 (h1): 协议 %d, 由内核态 eBPF 重建反向 SRH' % args.proto)
        cmd = ('python3 %s probe-raw --dst %s --proto %d --count %d %s'
               % (probe_py, H2_IP, args.proto, args.count,
                  ' '.join('--rev-sid %s' % s for s in REV_SEGS)))
        detail('  $ [h1] %s' % cmd)
        detail(h1.cmd(cmd).strip())
        section('eBPF 命中计数')
        run(h2, 'tc -s filter show dev h2-eth0 ingress')
    else:
        section('启动响应端 (h2): userspace 从 payload 取反向列表并重建 SRH')
        h2.cmd('python3 %s respond --port %d --iface h2-eth0 --me %s '
               '--my-mac %s --gw-mac %s --duration 25 > /tmp/d1_resp.txt 2>&1 &'
               % (probe_py, args.port, H2_IP, h2_mac, r4_mac))
        time.sleep(1.0)

        section('发起环回探测 (h1): 正向走内核 encap, 反向列表藏在 payload')
        cmd = ('python3 %s probe --dst %s --port %d --count %d %s'
               % (probe_py, H2_IP, args.port, args.count,
                  ' '.join('--rev-sid %s' % s for s in REV_SEGS)))
        detail('  $ [h1] %s' % cmd)
        detail(h1.cmd(cmd).strip())

        time.sleep(0.5)
        section('响应端日志 (h2)')
        detail(h2.cmd('cat /tmp/d1_resp.txt').strip())

    if args.capture:
        time.sleep(1.5)
        section('抓包: 正向 vs 反向的 SRH (证明双向都被钉死)')
        for node, tag in caps:
            detail('  --- %s (/tmp/d1_%s.txt) ---' % (tag, tag))
            detail(node.cmd('cat /tmp/d1_%s.txt' % tag).strip())

    section('完成')
    net.stop()


if __name__ == '__main__':
    main()
