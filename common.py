#!/usr/bin/env python3
r"""common.py -- Mininet / SRv6 共享工具
================================================================

提供多个仿真脚本共用的基础函数: Router 节点类,IPv6 地址配置,SRv6 使能,
命令执行,段落标题. 避免各脚本重复实现.

用法:
    from common import Router, add6, enable_seg6, run_cmd, section, print_topology
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


# 拓扑打印时展示的链路参数键 (按顺序)
_TOPO_PARAM_KEYS = ('delay', 'jitter', 'loss', 'bw', 'max_queue_size')


def _link_param_text(intf):
    """从接口 params 里取出链路的展示参数文本 (delay=5ms, bw=10mbit ...)."""
    params = getattr(intf, 'params', None) or {}
    return ', '.join('%s=%s' % (k, params[k]) for k in _TOPO_PARAM_KEYS
                     if params.get(k) is not None)


def print_topology(net, title='拓扑'):
    """打印当前拓扑: 节点清单 + 链路表 + 邻接表.

    一般在地址/路由配置完成之后, 开始测量之前调用. 直接读 Link 的接口名, 以及
    接口 params(getattr(intf, 'params')) 里的链路参数 (delay / bw / loss 等) 来展示.
    """
    hosts = list(net.hosts)
    links = list(net.links)

    section(title)
    summary('节点 (%d): %s'
            % (len(hosts), ' '.join(sorted(n.name for n in hosts))))

    summary('链路 (%d):' % len(links))
    adj = {}
    for lk in links:
        param = _link_param_text(lk.intf1) or _link_param_text(lk.intf2)
        tail = ('  (%s)' % param) if param else ''
        summary('  %-14s <-> %-14s%s'
                % (lk.intf1.name, lk.intf2.name, tail))
        # Link 不保存 node1/node2, 节点名从接口的 .node 取
        n1, n2 = lk.intf1.node.name, lk.intf2.node.name
        adj.setdefault(n1, []).append((n2, param))
        adj.setdefault(n2, []).append((n1, param))

    summary('邻接:')
    for name in sorted(adj):
        peers = ', '.join('%s%s' % (n, ('[%s]' % p) if p else '')
                          for n, p in sorted(adj[name]))
        summary('  %-6s -> %s' % (name, peers))
