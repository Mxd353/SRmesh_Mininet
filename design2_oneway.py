#!/usr/bin/env python3
r"""design2_oneway.py -- SRmesh Design 2 单向 UDP 时间戳探测工具
================================================================

用发送端时间戳减接收端时间戳得到单向时延, 避免 ping RTT/2 被非对称回程污染.
依赖仅 Python 标准库.

用法 (在 Mininet 节点内):

    python3 design2_oneway.py recv <port> <count> <timeout>
    python3 design2_oneway.py send <dst> <port> <source> <count> <interval>
"""
import socket
import struct
import sys
import time

MAGIC = 0x44324F4E  # D2ON


def recv(port, count, timeout):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("::", port))
    s.settimeout(timeout)
    vals = []
    while len(vals) < count:
        try:
            data, _ = s.recvfrom(2048)
        except socket.timeout:
            break
        if len(data) != 16:
            continue
        magic, tx = struct.unpack("!QQ", data)
        if magic != MAGIC:
            continue
        vals.append((time.monotonic_ns() - tx) / 1e6)
    if vals:
        print("AVG_MS=%.6f COUNT=%d" % (sum(vals) / len(vals), len(vals)))
    else:
        print("AVG_MS=NONE COUNT=0")


def send(dst, port, source, count, interval):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    if source:
        s.bind((source, 0))
    payload = b""
    for _ in range(count):
        payload = struct.pack("!QQ", MAGIC, time.monotonic_ns())
        s.sendto(payload, (dst, port))
        time.sleep(interval)


if __name__ == "__main__":
    if sys.argv[1] == "recv":
        recv(int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]))
    else:
        send(sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), float(sys.argv[6]))
