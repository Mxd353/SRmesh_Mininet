#!/usr/bin/env python3
r"""common.py -- Mininet / SRv6 共享工具
================================================================

提供多个仿真脚本共用的基础函数: Router 节点类,IPv6 地址配置,SRv6 使能,
命令执行,段落标题. 避免各脚本重复实现.

用法:
    from common import Router, add6, enable_seg6, run_cmd, section
"""
from mininet.node import Node

from mnlog import detail, summary


class Router(Node):
    """开启 IPv4/IPv6 转发的 Linux 命名空间路由器节点."""

    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1")
        self.cmd("sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1")
        self.cmd("sysctl -w net.ipv6.conf.all.accept_ra=0 >/dev/null 2>&1")


def add6(node, iface, addr, flush=True):
    """给 Mininet 接口配置一个跳过 DAD 的 global IPv6 地址."""
    node.cmd("ip link set %s up" % iface)
    node.cmd("sysctl -w net.ipv6.conf.%s.accept_dad=0 >/dev/null 2>&1" % iface)
    if flush:
        node.cmd("ip -6 addr flush dev %s scope global 2>/dev/null" % iface)
    node.cmd("ip -6 addr add %s dev %s nodad" % (addr, iface))


def enable_seg6(node, ifaces):
    """在节点全局及指定接口上开启 SRv6 接收处理."""
    node.cmd("sysctl -w net.ipv6.conf.all.seg6_enabled=1 >/dev/null 2>&1")
    for iface in ifaces:
        node.cmd("sysctl -w net.ipv6.conf.%s.seg6_enabled=1 >/dev/null 2>&1" % iface)


def section(title):
    """打印一个段落标题到终端和日志."""
    summary("\n== %s ==" % title)


def run_cmd(node, cmd):
    """在节点上执行命令, 命令与输出只写入日志."""
    out = node.cmd(cmd)
    detail("  $ [%s] %s" % (node.name, cmd))
    if out.strip():
        detail("    %s" % out.strip().replace("\n", "\n    "))
    return out
