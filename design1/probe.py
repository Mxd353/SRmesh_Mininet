#!/usr/bin/env python3
r"""probe.py -- SRmesh Design 1 发起端与响应端 (用户态版)
================================================================

实现 SRmesh 的确定性 SR 环回探测:

    发起端 probe:

        * 正向路径: 交给内核 SRv6 route (encap seg6), 探测包走生产同款 SID 列表.
        * payload 里携带反向 SID 列表, 不占第二个 SRH, 规避 MTU.
        * 记录发送时刻, 收到回复后算 RTT.

    响应端 respond:

        * 收到探测 (已被上游 PE 解封装成内层包).
        * 从 payload 取出反向 SID 列表.
        * 现场重建反向 SRH, 逐字节构造整包, 用 AF_PACKET 原路发回.

payload 线格式 (24 字节头 + 16*n):

    magic(4) probe_id(4) seq(4) tx_ns(8) rev_cnt(1) pad(3) [rev_sid(16)]*n

响应端的回复在尾部追加 8 字节 (响应端收到探测的时刻, 单调时钟), 发起端据此算**单向
时延** (同一内核时钟, 无需对钟); 不需要单向时延的调用方忽略这 8 字节即可 (兼容).

用法 (在 Mininet 节点内):

    python3 design1/probe.py respond --port 9999 --iface h2-eth0 --me 2001:db8:2::2 \
        --my-mac <h2 mac> --gw-mac <r4 mac>
    python3 design1/probe.py probe --dst 2001:db8:2::2 --port 9999 \
        --rev-sid 2001:db8:100::3 --rev-sid 2001:db8:100::1 --count 3

多接口节点 (闭环集成用) 的两种扩展:

    * --nexthop-map <json>: {"<sid 前缀>": ["<出口 interface>", "<下一跳 mac>"]},
      响应端按反向首段 SID 做最长前缀匹配选出口, 不再写死单个接口;
    * --segs / --seg-dev: 发起端按 SID 列表临时装一条 encap seg6 路由, 支持任意节点对.
"""
import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time
from ipaddress import IPv6Address, IPv6Network

MAGIC = 0x53526D31          # "SRm1"
UDP_PROTO = 17
ETH_P_IPV6 = 0x86DD
PROBE_HDR = struct.Struct('!IIIQB3x')   # magic, probe_id, seq, tx_ns, rev_cnt  (24B)


# ---- 网络字节 ----
def a6(s):
    return socket.inet_pton(socket.AF_INET6, s)


def r6(b):
    return socket.inet_ntop(socket.AF_INET6, b)


def _csum16(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv6_hdr(src, dst, nxt, hlim, payload):
    vtf = 6 << 28
    return struct.pack('!IHBB', vtf, len(payload), nxt, hlim) + a6(src) + a6(dst) + payload


def srh(seg_list):
    """seg_list 是正向顺序 [S1, S2, ...]; SRH 内按 RFC 8754 逆序存."""
    n = len(seg_list)
    hel = (8 + 16 * n) // 8 - 1
    hdr = struct.pack('!BBBBBBH', 41, hel, 4, n - 1, n - 1, 0, 0)
    hdr += b''.join(a6(s) for s in reversed(seg_list))
    return hdr


def udp_hdr(src, dst, sport, dport, payload):
    length = 8 + len(payload)
    pseudo = a6(src) + a6(dst) + struct.pack('!I', length) + b'\x00\x00\x00' + bytes([UDP_PROTO])
    tmp = struct.pack('!HHHH', sport, dport, length, 0) + payload
    ck = _csum16(pseudo + tmp)
    return struct.pack('!HHHH', sport, dport, length, ck) + payload


def make_payload(probe_id, seq, tx_ns, rev_sids):
    p = PROBE_HDR.pack(MAGIC, probe_id, seq, tx_ns, len(rev_sids))
    p += b''.join(a6(s) for s in rev_sids)
    return p


def parse_payload(data):
    if len(data) < PROBE_HDR.size:
        return None
    magic, pid, seq, tx, cnt = PROBE_HDR.unpack(data[:PROBE_HDR.size])
    if magic != MAGIC:
        return None
    rev = []
    off = PROBE_HDR.size
    for _ in range(cnt):
        if off + 16 > len(data):
            break
        rev.append(r6(data[off:off + 16]))
        off += 16
    return pid, seq, tx, rev


# 回复末尾追加的 8 字节: 响应端收到探测的时刻 (单调时钟 ns)
TS = struct.Struct('!Q')


def parse_reply_ts(data):
    """取出回复里的响应端时间戳; 没有则返回 None (兼容不带时间戳的响应端)."""
    if parse_payload(data) is None:
        return None
    if len(data) < PROBE_HDR.size + TS.size:
        return None
    return TS.unpack(data[PROBE_HDR.size:PROBE_HDR.size + TS.size])[0]


# ---- 发起端 ----
def _set_encap_route(dst, segs, dev):
    """给目的地址装一条 encap seg6 的 /128 路由 (正向路径 = 这条 SID 列表).

    同一目的地址可能被不同探测对复用 (不同路径), 所以每探一次用 replace 覆盖.
    """
    cmd = ['ip', '-6', 'route', 'replace', '%s/128' % dst,
           'encap', 'seg6', 'mode', 'encap', 'segs', ','.join(segs)]
    if dev:
        cmd += ['dev', dev]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return (r.stderr or r.stdout).strip() or 'ip route replace 失败'
    return None


def cmd_probe(args):
    rev = args.rev_sid
    if args.segs:
        err = _set_encap_route(args.dst, args.segs, args.seg_dev)
        if err:
            print('PROBER 封装路由失败: %s' % err)
            return 1
    try:
        sk = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sk.bind(('::', args.port))
        sk.settimeout(args.timeout)
    except OSError as e:
        print('PROBER bind 失败: %s' % e)
        return 1

    pid = os.getpid() & 0xFFFF
    print('PROBER start: dst=%s rev=%s' % (args.dst, rev))
    ok = 0
    rtts, ows = [], []
    for i in range(args.count):
        tx = time.monotonic_ns()
        pl = make_payload(pid, i, tx, rev)
        try:
            sk.sendto(pl, (args.dst, args.port))
        except OSError as e:
            print('probe %d: send 失败 %s' % (i, e))
            continue
        # 等到与 pid 匹配的回复 (允许丢弃无关包)
        got = False
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            try:
                data, addr = sk.recvfrom(65535)
            except socket.timeout:
                break
            m = parse_payload(data)
            if m and m[0] == pid:
                rx = time.monotonic_ns()
                rtt = (rx - m[2]) / 1e6
                rtts.append(rtt)
                ok += 1
                got = True
                if args.oneway:
                    ts = parse_reply_ts(data)
                    if ts is None:
                        print('probe %d: RTT = %.3f ms (回复无时间戳)' % (i, rtt))
                    else:
                        ow = (ts - m[2]) / 1e6
                        ows.append(ow)
                        print('probe %d: RTT = %.3f ms, 单向 = %.3f ms'
                              % (i, rtt, ow))
                else:
                    print('probe %d: RTT = %.3f ms' % (i, rtt))
                break
        if not got:
            print('probe %d: TIMEOUT' % i)
        time.sleep(args.interval)

    if rtts:
        print('PROBER summary: %d/%d 成功, min/avg/max = %.3f/%.3f/%.3f ms'
              % (ok, args.count, min(rtts), sum(rtts) / len(rtts), max(rtts)))
    else:
        print('PROBER summary: 0/%d 成功 (全部超时)' % args.count)
    if ows:
        print('PROBER oneway summary: min/avg/max = %.3f/%.3f/%.3f ms'
              % (min(ows), sum(ows) / len(ows), max(ows)))
    return 0


# ---- 发起端 (原始套接字, 配合 eBPF 响应端) ----
def cmd_probe_raw(args):
    proto = args.proto
    try:
        sk = socket.socket(socket.AF_INET6, socket.SOCK_RAW, proto)
        sk.settimeout(args.timeout)
    except OSError as e:
        print('PROBER(raw) socket 创建失败: %s' % e)
        return 1

    pid = os.getpid() & 0xFFFF
    print('PROBER(raw) start: dst=%s proto=%d rev=%s' % (args.dst, proto, args.rev_sid))
    rtts = []
    ok = 0
    for i in range(args.count):
        tx = time.monotonic_ns()
        pl = make_payload(pid, i, tx, args.rev_sid)
        try:
            sk.sendto(pl, (args.dst, 0))
        except OSError as e:
            print('probe %d: send 失败 %s' % (i, e))
            continue
        got = False
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            try:
                data, addr = sk.recvfrom(65535)
            except socket.timeout:
                break
            m = parse_payload(data)
            if not m and len(data) > 40:          # 有的栈 raw 收包带 IPv6 头
                m = parse_payload(data[40:])
            if m and m[0] == pid:
                rx = time.monotonic_ns()
                rtt = (rx - m[2]) / 1e6
                rtts.append(rtt)
                ok += 1
                got = True
                print('probe %d: RTT = %.3f ms' % (i, rtt))
                break
        if not got:
            print('probe %d: TIMEOUT' % i)
        time.sleep(args.interval)

    if rtts:
        print('PROBER(raw) summary: %d/%d 成功, min/avg/max = %.3f/%.3f/%.3f ms'
              % (ok, args.count, min(rtts), sum(rtts) / len(rtts), max(rtts)))
    else:
        print('PROBER(raw) summary: 0/%d 成功 (全部超时)' % args.count)
    return 0


# ---- 响应端 ----
def _mac(s):
    return bytes.fromhex(s.replace(':', ''))


def _iface_mac(iface):
    """读接口自身 MAC (sysfs); 出口动态变化时不能再用固定 --my-mac."""
    with open('/sys/class/net/%s/address' % iface) as f:
        return _mac(f.read().strip())


def cmd_respond(args):
    if not args.nexthop_map and not (args.iface and args.gw_mac):
        print('RESPONDER: 需要 --iface/--gw-mac (静态) 或 --nexthop-map (多接口)')
        return 1
    rxsock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    rxsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rxsock.bind(('::', args.port))

    # 出口选择: 静态 (--iface/--gw-mac) 或按反向首段 SID 的最长前缀匹配 (--nexthop-map).
    # 后者让同一个响应端服务多接口节点上的任意反向路径.
    nets = {}
    if args.nexthop_map:
        with open(args.nexthop_map) as f:
            for pfx, (iface, gw) in json.load(f).items():
                nets[IPv6Network(pfx)] = (iface, _mac(gw))
    tx_socks = {}

    def egress(dst_sid):
        if not nets:
            return args.iface, _mac(args.gw_mac)
        addr = IPv6Address(dst_sid)
        best = None
        for net, hop in nets.items():
            if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, hop)
        return best[1] if best else (args.iface, _mac(args.gw_mac))

    def tx_pair(iface, gw_mac):
        """按 (出口, 下一跳 MAC) 复用 AF_PACKET 套接字, 并带上该出口自身的 MAC."""
        key = (iface, gw_mac)
        if key not in tx_socks:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((iface, 0))
            my = _mac(args.my_mac) if (args.my_mac and not nets) else _iface_mac(iface)
            tx_socks[key] = (s, my)
        return tx_socks[key]

    print('RESPONDER ready: me=%s, 出口=%s'
          % (args.me, '按 SID 前缀匹配' if nets else args.iface))
    sys.stdout.flush()
    t0 = time.time()
    n = 0
    while args.duration <= 0 or time.time() - t0 < args.duration:
        rxsock.settimeout(1.0)
        try:
            data, addr = rxsock.recvfrom(65535)
        except socket.timeout:
            continue
        rx_ns = time.monotonic_ns()         # 响应端收到探测的时刻 (算单向时延)
        m = parse_payload(data)
        if not m:
            continue
        pid, seq, tx_ns, rev = m
        peer = addr[0]
        if not rev:
            print('probe %d: payload 无反向列表, 跳过' % seq)
            continue
        # 重建反向 SRv6 包: 外层(me -> rev[0]) + SRH(rev) + 内层(me -> peer) + UDP
        reply = make_payload(pid, seq, tx_ns, []) + TS.pack(rx_ns)
        inner = udp_hdr(args.me, peer, args.port, args.port, reply)
        pkt = ipv6_hdr(args.me, peer, UDP_PROTO, 64, inner)
        outer = ipv6_hdr(args.me, rev[0], 43, 64, srh(rev) + pkt)
        iface, gw_mac = egress(rev[0])
        txsock, my_mac = tx_pair(iface, gw_mac)
        eth = gw_mac + my_mac + struct.pack('!H', ETH_P_IPV6)
        try:
            txsock.send(eth + outer)
            n += 1
            print('probe %d: 已重建反向 SRH %s 回发 -> %s (出口 %s)'
                  % (seq, rev, peer, iface))
            sys.stdout.flush()
        except OSError as e:
            print('probe %d: 回发失败 %s' % (seq, e))
            sys.stdout.flush()
    print('RESPONDER done: 共回发 %d' % n)
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='mode', required=True)

    p = sub.add_parser('probe')
    p.add_argument('--dst', required=True)
    p.add_argument('--port', type=int, required=True)
    p.add_argument('--rev-sid', action='append', default=[], required=True)
    p.add_argument('--segs', default=None,
                   help='正向 SID 列表 (逗号分隔); 给了就临时装 encap seg6 路由')
    p.add_argument('--seg-dev', default=None, help='封装路由的出口接口')
    p.add_argument('--oneway', action='store_true',
                   help='用响应端时间戳额外算单向时延')
    p.add_argument('--count', type=int, default=4)
    p.add_argument('--interval', type=float, default=0.3)
    p.add_argument('--timeout', type=float, default=2.0)
    p.set_defaults(func=cmd_probe)

    q = sub.add_parser('probe-raw')
    q.add_argument('--dst', required=True)
    q.add_argument('--proto', type=int, default=253)
    q.add_argument('--rev-sid', action='append', default=[], required=True)
    q.add_argument('--count', type=int, default=4)
    q.add_argument('--interval', type=float, default=0.3)
    q.add_argument('--timeout', type=float, default=2.0)
    q.set_defaults(func=cmd_probe_raw)

    r = sub.add_parser('respond')
    r.add_argument('--port', type=int, required=True)
    r.add_argument('--iface', default=None, help='静态模式下的出口接口')
    r.add_argument('--me', required=True)
    r.add_argument('--my-mac', default=None)
    r.add_argument('--gw-mac', default=None)
    r.add_argument('--nexthop-map', default=None,
                   help='JSON: {sid 前缀: [出口接口, 下一跳 mac]}, 多接口节点按此选出口')
    r.add_argument('--duration', type=float, default=0, help='0=一直跑')
    r.set_defaults(func=cmd_respond)

    args = ap.parse_args()
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
