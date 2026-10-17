#!/usr/bin/env python3
r"""srnet.py -- 闭环集成用的 8 节点 SRv6 网络 (拓扑 + SID 规划 + 探测器)
================================================================

给 Design 1/2/3 的闭环提供"真实网元": 拓扑, 寻址, SRv6 SID 行为, 逐跳钉死的探测.

拓扑 (两个三角形 + 一条边 + 三条桥, 天然 3 个社区, 给 Design 3 的模块度分区用):

        a1 --- a2          b1 --- b2          c1 --- c2
        |  \  /  |          |  \  /  |             |
        |   \/   |          |   \/   |             |
        a3 ------+--(桥)----+----- b3 ----(桥)-----+
             桥: a1-b1, a2-b2, b3-c1        8 路由器 10 链路

每台路由器后面再挂一台**探测端点主机** (a1h ... c2h), 探针地址在主机上:

    h1 -- r1 -- ... -- rk -- hk        探测 = 主机到主机的 SR 环回
      ^ 主机链路 0 ms                   ^

为什么要有主机: SRv6 端点 SID 在工程上用 End.DX6 把包**交付给直连主机**(CE); 实测本
内核上 `action End`(弹 SRH 后本地交付给路由器自身地址) 会把包弹回上游, 不可用. 主机
链路不加 netem 时延, 所以单向时延仍然等于"路由器链路时延之和", 与 Design 2/3 的链路
模型完全一致.

寻址:

    路由器链路  第 i 条链路 2001:db8:<i>::/64, 两端 ::1 / ::2
    主机链路    接着编号, 路由器侧 ::1, 主机侧 ::2 (探针地址就是它)
    SID         node SID  2001:db8:100:<k>::ff   行为 End.DX6 nh6 <主机地址>
                邻接 SID  2001:db8:100:<u>::<v>  行为 End.X (SL-- 后从 u->v 转发)

    同一节点的 SID 都落在 2001:db8:100:<k>::/64 里, 每个节点只要一条聚合路由就能把
    外层包送到任意节点拥有的 SID.

探测 (Design 1):

    正向 SID 列表逐跳钉死: [adj(p1->p2), ..., adj(p_{k-1}->d), node_sid(d)];
    发起主机 s 不出现在列表里 —— 封装后外层目的地址就是 segs[0], 由 s 的默认路由送到 r_s.
    反向 SID 列表按同样规则编译反转路径, 藏在 payload 里由响应端重建;
    响应端把收包时刻追加在回复尾部, 发起端据此算**单向时延** (Design 2 需要).

链路时延由 tc netem 注入 (单向 = 发送侧出口), 故障注入 = 把链路两端各调一次.
"""
import json
import os
import random
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from design3.plan import Graph
from lib.mnlog import detail

# ---- 拓扑: 从 fiti.json 读 (节点用 abbr, 链路时延 = weight ms) ----
FITI = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fiti.json')


def load_topology(path=FITI):
    """读 fiti.json, 返回 (nodes, edges); edges 是 (u, v, 基准单向时延 ms).

    节点名用 abbr (bj/sh/xa ...), weight 直接当 netem 时延 (1/2/4 ms).
    """
    with open(path, encoding='utf-8') as f:
        d = json.load(f)
    abbr = {n['id']: n['abbr'] for n in d['nodes']}
    nodes = tuple(sorted(abbr[n['id']] for n in d['nodes']))
    edges = tuple((abbr[l['src']], abbr[l['dst']], float(l['weight']))
                  for l in d['links'])
    if len(set(nodes)) != len(nodes):
        raise ValueError('abbr 有重复, 不能直接当节点名')
    return nodes, edges


NODES, EDGES = load_topology()
HOST_SUFFIX = 'h'       # 探测端点主机: bj -> bjh


class NetPlan(object):
    """地址 / SID / 下一跳规划. 纯计算, 不需要 root, 也不依赖 Mininet."""

    def __init__(self, nodes, edges):
        self.nodes = tuple(sorted(nodes))
        self.edges = tuple((u, v, float(ms)) for u, v, ms in edges)
        self.num = {n: i for i, n in enumerate(self.nodes, 1)}
        self.host = {n: n + HOST_SUFFIX for n in self.nodes}
        self.nbr = {n: {} for n in self.nodes}          # n -> {邻居: 基准时延}
        for u, v, ms in self.edges:
            self.nbr[u][v] = ms
            self.nbr[v][u] = ms
        # 路由器链路地址: 按 (u, v) 排序编号, 两端 ::1 / ::2
        self.link = {}                                  # (u, v) -> (u 端, v 端)
        for i, (u, v, _) in enumerate(sorted(self.edges), 1):
            self.link[(u, v)] = ('2001:db8:%d::1' % i, '2001:db8:%d::2' % i)
        # 主机链路地址: 接着编号, 路由器侧 ::1, 主机侧 ::2 (= 探针地址)
        self.hostlink = {}                              # n -> (路由器侧, 主机侧)
        for k, n in enumerate(self.nodes, 1):
            i = len(self.edges) + k
            self.hostlink[n] = ('2001:db8:%d::1' % i, '2001:db8:%d::2' % i)
        self.iface = {}                                 # (u, v) -> u 侧接口 (build 时填)
        self.hiface = {}                                # n -> 主机侧接口
        self.riface = {}                                # n -> 主机链路的路由器侧接口
        self.hop = {n: self._hops(n) for n in self.nodes}

    # ---- 拓扑 ----
    def _hops(self, src):
        """src 到其他路由器的下一跳: {目标: 下一跳邻居} (BFS, 邻居按名字排序)."""
        prev = {src: (None, 0)}
        queue = [src]
        while queue:
            cur = queue.pop(0)
            for nb in sorted(self.nbr[cur]):
                if nb not in prev:
                    nxt = nb if cur == src else prev[cur][0]
                    prev[nb] = (nxt, prev[cur][1] + 1)
                    queue.append(nb)
        return {dst: nxt for dst, (nxt, _) in prev.items() if dst != src}

    def neighbors(self, n):
        return sorted(self.nbr[n])

    def directed_delay(self):
        """有向链路基准时延 {u>v: ms} (故障注入前的真值; 只含路由器链路)."""
        d = {}
        for u, v, ms in self.edges:
            d['%s>%s' % (u, v)] = ms
            d['%s>%s' % (v, u)] = ms
        return d

    def directed_links(self, path):
        """路由器路径 -> 有向链路 id 列表 (Design 2 的未知量粒度)."""
        return ['%s>%s' % (path[i], path[i + 1]) for i in range(len(path) - 1)]

    def graph(self):
        """给 Design 3 的无向图 (链路 id = 'u|v', 一条物理链路两个方向同 id)."""
        return Graph.from_edges([(u, v) for u, v, _ in self.edges])

    # ---- 地址 ----
    def addr(self, u, v):
        """u 在路由器链路 u-v 上的地址."""
        a, b = (u, v) if (u, v) in self.link else (v, u)
        au, av = self.link[(a, b)]
        return au if u == a else av

    def iface_of(self, u, v):
        return self.iface[(u, v)]

    def probe_addr(self, n):
        """n 的探针地址 = 挂在 n 后面的端点主机地址."""
        return self.hostlink[n][1]

    def router_host_addr(self, n):
        return self.hostlink[n][0]

    def node_sid(self, n):
        return '2001:db8:100:%d::ff' % self.num[n]

    def adj_sid(self, u, v):
        return '2001:db8:100:%d::%d' % (self.num[u], self.num[v])

    def sid_prefix(self, n):
        return '2001:db8:100:%d::/64' % self.num[n]

    # ---- 路径 <-> SID 列表 ----
    def seg_list(self, path):
        """把路由器路径编译成正向 SID 列表.

        path = [s, p1, ..., d]: 对 p1..d 的每一跳取 p_i -> p_{i+1} 的邻接 SID,
        末尾换成 d 的 node SID (End.DX6: 弹 SRH 并交付给 d 后面的端点主机).
        """
        path = list(path)
        segs = [self.adj_sid(path[i], path[i + 1]) for i in range(1, len(path) - 1)]
        segs.append(self.node_sid(path[-1]))
        return segs

    def rev_segs(self, path):
        """反向 SID 列表 = 反转路径的正向列表 (藏在 payload 里)."""
        return self.seg_list(list(reversed(path)))


# ---- Mininet 侧 ----
def _iface_pairs(u, v, lk):
    """把一条 Link 的两个接口映射成 {(u, v): u 侧接口, (v, u): v 侧接口}.

    Link 的 intf1/intf2 不保证与 addLink 的参数顺序一致, 所以按 intf.node 判定归属.
    """
    out = {}
    for intf in (lk.intf1, lk.intf2):
        node = intf.node.name
        if node == u:
            out[(u, v)] = intf.name
        elif node == v:
            out[(v, u)] = intf.name
        else:
            raise ValueError('接口 %s 不属于 %s/%s' % (intf.name, u, v))
    if len(out) != 2:
        raise ValueError('链路 %s-%s 的接口归属有误: %s' % (u, v, out))
    return out


def build_mininet(plan, port=9999, timeout=3.0, logdir=None):
    """建拓扑 + 配地址/SID/路由 + 预热, 返回 ProbeExecutor.

    只有这个函数依赖 Mininet 和 root; --simulate 模式不走到这里.
    """
    from mininet.net import Mininet
    from mininet.link import TCLink
    from mininet.node import Node
    from mininet.clean import cleanup

    from lib.common import Router

    cleanup()
    net = Mininet(controller=None, link=TCLink)
    for n in plan.nodes:
        net.addHost(n, cls=Router, ip=None)
        net.addHost(plan.host[n], cls=Node, ip=None)        # 探测端点主机
    for u, v, ms in plan.edges:
        lk = net.addLink(net[u], net[v], delay='%gms' % ms)
        plan.iface.update(_iface_pairs(u, v, lk))
    for n in plan.nodes:
        # 主机链路不加时延: 单向时延 = 路由器链路之和, 与链路模型一致
        lk = net.addLink(net[n], net[plan.host[n]])
        pair = _iface_pairs(n, plan.host[n], lk)
        plan.riface[n] = pair[(n, plan.host[n])]
        plan.hiface[n] = pair[(plan.host[n], n)]
    if len(plan.iface) != 2 * len(plan.edges):
        raise RuntimeError('接口映射不完整: %d 条, 应为 %d 条'
                           % (len(plan.iface), 2 * len(plan.edges)))
    net.start()
    try:
        _configure(net, plan)
        macs = _macs(net, plan)
        warmup(net, plan)
        return ProbeExecutor(net, plan, macs, port=port, timeout=timeout,
                             logdir=logdir)
    except Exception:
        net.stop()                  # 配置中途失败也要回收命名空间, 不留残留
        raise


def _batch(node, cmds):
    """把多条命令合成一次 shell 调用 (41 节点时每条 cmd 的 mnexec 开销很可观)."""
    if not cmds:
        return ''
    detail('  $ [%s] %d 条命令' % (node.name, len(cmds)))
    for c in cmds:
        detail('    %s' % c)
    out = node.cmd(' ; '.join(cmds))
    if out.strip():
        detail('    => %s' % out.strip())
    return out


def _configure(net, plan):
    """配探针主机 / 链路地址 / SRv6 SID 行为 / SID 聚合路由."""
    from lib.common import add6, enable_seg6

    # 端点主机: 探针地址 + 默认路由 (只有一条上行, 不用选路)
    for n in plan.nodes:
        h = plan.host[n]
        add6(net[h], plan.hiface[n], plan.probe_addr(n) + '/64')
        net[h].cmd('ip -6 route add default via %s dev %s'
                   % (plan.router_host_addr(n), plan.hiface[n]))
    # 路由器: SRv6 接收处理 + 链路地址
    for n in plan.nodes:
        ifs = [plan.iface_of(n, v) for v in plan.neighbors(n)] + [plan.riface[n]]
        enable_seg6(net[n], ifs)
    for (u, v), (au, av) in plan.link.items():
        add6(net[u], plan.iface_of(u, v), au + '/64')
        add6(net[v], plan.iface_of(v, u), av + '/64')
    # 主机链路的路由器侧地址
    for n in plan.nodes:
        net[n].cmd('ip -6 addr add %s/64 dev %s nodad'
                   % (plan.router_host_addr(n), plan.riface[n]))
        net[n].cmd('ip link set %s up' % plan.riface[n])

    # SID 行为 + 聚合路由: 每个路由器一次批量装完, 再校验条数
    for n in plan.nodes:
        node = net[n]
        cmds = ['ip -6 route add %s/128 encap seg6local action End.DX6 nh6 %s dev %s'
                % (plan.node_sid(n), plan.probe_addr(n), plan.riface[n])]
        for peer in plan.neighbors(n):
            cmds.append('ip -6 route add %s/128 encap seg6local action End.X nh6 %s '
                        'dev %s' % (plan.adj_sid(n, peer), plan.addr(peer, n),
                                    plan.iface_of(n, peer)))
        for dst, hop in plan.hop[n].items():
            cmds.append('ip -6 route add %s via %s dev %s'
                        % (plan.sid_prefix(dst), plan.addr(hop, n),
                           plan.iface_of(n, hop)))
        _batch(node, cmds)
        want = len(cmds)
        got = node.cmd('ip -6 route show | grep -c "2001:db8:100:"').strip()
        if got != str(want):
            raise RuntimeError('%s 的 SID 路由只装上 %s/%d 条' % (n, got, want))


def _macs(net, plan):
    """(n, 'host') -> n 在主机链路上的 MAC; 响应端构造以太头要用."""
    return {n: net[n].cmd('cat /sys/class/net/%s/address'
                          % plan.riface[n]).strip() for n in plan.nodes}


def warmup(net, plan):
    """每条链路双向各 ping 一次, 把正向和反向每一跳的 NDP 都焐热.

    只预热"一条路径"不够: 首个探测包曾在反向路径的中间路由器上排队等 NDP, 凭空
    多出约 80 ms (详见 design1/demo.py 的关键坑第 8 条). 闭环里任意节点对都可能
    被探, 所以每条链路都要预热 —— 也顺带把 SID 聚合路由的下一跳解析出来.
    """
    ping = 'ping6 -c 1 -i 0.2 -W 1 %s >/dev/null 2>&1'
    for n in plan.nodes:
        _batch(net[n], [ping % plan.addr(v, n) for v in plan.neighbors(n)]
               + [ping % plan.probe_addr(n)])
        _batch(net[plan.host[n]], [ping % plan.router_host_addr(n)])


class ProbeExecutor(object):
    """在真实拓扑上逐条执行探测: 探测主机 -> ... -> 探测主机."""

    def __init__(self, net, plan, macs, port=9999, timeout=3.0, logdir=None,
                 retries=1):
        self.net = net
        self.plan = plan
        self.macs = macs
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.logdir = logdir or os.path.join(ROOT, 'logs')
        self.probe_py = os.path.join(ROOT, 'design1', 'probe.py')
        self.responders = []

    def start_responders(self):
        """每个端点主机起一个响应端 (主机只有一条上行, 出口固定)."""
        os.makedirs(self.logdir, exist_ok=True)
        for n in self.plan.nodes:
            h = self.plan.host[n]
            log = os.path.join(self.logdir, 'responder_%s.log' % n)
            self.net[h].cmd(
                'python3 %s respond --port %d --me %s --iface %s --gw-mac %s '
                '--duration 0 > %s 2>&1 &'
                % (self.probe_py, self.port, self.plan.probe_addr(n),
                   self.plan.hiface[n], self.macs[n], log))
            self.responders.append(h)
        time.sleep(1.0)

    def stop_responders(self):
        for h in self.responders:
            self.net[h].cmd('pkill -f "probe.py respond" >/dev/null 2>&1')

    def probe(self, path):
        """探一条路由器路径, 返回 (单向时延 ms, RTT ms); 失败返回 None."""
        src, dst = path[0], path[-1]
        host = self.plan.host[src]
        segs = self.plan.seg_list(path)
        rev = self.plan.rev_segs(path)
        cmd = ('python3 %s probe --dst %s --port %d --segs %s --seg-dev %s %s '
               '--oneway --count 1 --interval 0 --timeout %g'
               % (self.probe_py, self.plan.probe_addr(dst), self.port,
                  ','.join(segs), self.plan.hiface[src],
                  ' '.join('--rev-sid %s' % s for s in rev), self.timeout))
        m = r = None
        for _ in range(self.retries + 1):        # 第一次可能撞上路由缓存/NDP, 重试一次
            detail('  $ [%s] %s' % (host, cmd))
            out = self.net[host].cmd(cmd).strip()
            detail('    ' + out.replace('\n', '\n    '))
            m = re.search(r'单向 = ([\d.]+) ms', out)
            if m:
                r = re.search(r'RTT = ([\d.]+) ms', out)
                break
        if not m:
            return None
        return float(m.group(1)), (float(r.group(1)) if r else None)

    def set_link_delay(self, u, v, ms):
        """把路由器链路 (u, v) 两个方向的出口时延都设成 ms (故障注入 / 恢复)."""
        for a, b in ((u, v), (v, u)):
            self.net[a].cmd('tc qdisc replace dev %s root netem delay %gms'
                            % (self.plan.iface_of(a, b), ms))

    def close(self):
        self.stop_responders()
        self.net.stop()


class ModelHarness(object):
    """--simulate 用: 用链路时延模型代替真实探测 (免 root, 完全可复现).

    模型与 design3/eval.py 一致: 单向时延 = 路径上各"发送侧出口"时延之和.
    set_link_delay() 收到的是**单向**绝对时延, 故障注入时两个方向一起设.
    """

    def __init__(self, plan, delay=None, noise=0.0):
        self.plan = plan
        self.delay = dict(delay or plan.directed_delay())
        self.noise = noise
        self._rng = random.Random(7)

    def probe(self, path):
        val = sum(self.delay[l] for l in self.plan.directed_links(path))
        if self.noise:
            val += self._rng.uniform(-self.noise, self.noise)
        return val, 2 * val

    def set_link_delay(self, u, v, ms):
        self.delay['%s>%s' % (u, v)] = ms
        self.delay['%s>%s' % (v, u)] = ms

    def close(self):
        pass
