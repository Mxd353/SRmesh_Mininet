#!/usr/bin/env python3
r"""srnet.py -- 闭环集成用的 8 节点 SRv6 网络 (拓扑 + SID 规划 + 探测器)
================================================================

给 Design 1/2/3 的闭环提供"真实网元": 拓扑, 寻址, SRv6 SID 行为, 逐跳钉死的探测.

拓扑 (两个三角形 + 一条边 + 三条桥, 天然 3 个社区, 给 Design 3 的模块度分区用):

        a1 --- a2          b1 --- b2          c1 --- c2
        |  \  /  |          |  \  /  |             |
        |   \/   |          |   \/   |             |
        a3 ------+--(桥)----+----- b3 ----(桥)-----+
             桥: a1-b1, a2-b2, b3-c1        8 节点 10 链路

寻址:

    链路    第 i 条链路用 2001:db8:<i>::/64, 两端 ::1 / ::2
    探针    每个节点 2001:db8:ff::<k>/128 (挂 lo); 探测的内层目的地址就是它
    SID     node SID  2001:db8:100:<k>::ff    行为 End   (弹 SRH, 内层包本地交付)
            邻接 SID  2001:db8:100:<u>::<v>   行为 End.X (SL-- 后从 u->v 转发)

    同一节点的 SID 都落在 2001:db8:100:<k>::/64 里, 所以每个节点只要一条聚合路由
    就能把外层包送到任意节点拥有的 SID (10 条链路不用配 20 条逐 SID 路由).

探测 (Design 1):

    正向 SID 列表逐跳钉死: [adj(p1->p2), ..., adj(p_{k-1}->d), node_sid(d)];
    发起端 s 自己不出现在列表里 —— 封装后外层目的地址就是 segs[0], 由 s 的聚合路由
    送到 p1, 之后的每一跳都由邻接 SID 的 End.X 指定.
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

# ---- 拓扑: (u, v, 基准单向时延 ms) ----
NODES = ('a1', 'a2', 'a3', 'b1', 'b2', 'b3', 'c1', 'c2')
EDGES = (
    ('a1', 'a2', 1), ('a2', 'a3', 1), ('a1', 'a3', 1),      # 社区 a
    ('b1', 'b2', 1), ('b2', 'b3', 1), ('b1', 'b3', 1),      # 社区 b
    ('c1', 'c2', 1),                                        # 社区 c
    ('a1', 'b1', 2), ('a2', 'b2', 2), ('b3', 'c1', 2),      # 三条桥
)


class NetPlan(object):
    """地址 / SID / 下一跳规划. 纯计算, 不需要 root, 也不依赖 Mininet."""

    def __init__(self, nodes, edges):
        self.nodes = tuple(sorted(nodes))
        self.edges = tuple((u, v, float(ms)) for u, v, ms in edges)
        self.num = {n: i for i, n in enumerate(self.nodes, 1)}
        self.nbr = {n: {} for n in self.nodes}          # n -> {邻居: 基准时延}
        for u, v, ms in self.edges:
            self.nbr[u][v] = ms
            self.nbr[v][u] = ms
        # 链路地址: 按 (u, v) 排序编号, 两端 ::1 / ::2
        self.link = {}                                  # (u, v) 有序 -> (u 端地址, v 端地址)
        for i, (u, v, _) in enumerate(sorted(self.edges), 1):
            self.link[(u, v)] = ('2001:db8:%d::1' % i, '2001:db8:%d::2' % i)
        self.iface = {}                                 # (u, v) -> u 侧接口名 (build 时填)
        self.hop = {n: self._hops(n) for n in self.nodes}

    # ---- 拓扑 ----
    def _hops(self, src):
        """src 到其他节点的下一跳: {目标: 下一跳邻居} (BFS, 邻居按名字排序)."""
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
        """有向链路基准时延 {u>v: ms} (故障注入前的真值)."""
        d = {}
        for u, v, ms in self.edges:
            d['%s>%s' % (u, v)] = ms
            d['%s>%s' % (v, u)] = ms
        return d

    def directed_links(self, path):
        """节点路径 -> 有向链路 id 列表 (Design 2 的未知量粒度)."""
        return ['%s>%s' % (path[i], path[i + 1]) for i in range(len(path) - 1)]

    def graph(self):
        """给 Design 3 的无向图 (链路 id = 'u|v', 一条物理链路两个方向同 id)."""
        return Graph.from_edges([(u, v) for u, v, _ in self.edges])

    # ---- 地址 ----
    def addr(self, u, v):
        """u 在链路 u-v 上的地址."""
        a, b = (u, v) if (u, v) in self.link else (v, u)
        au, av = self.link[(a, b)]
        return au if u == a else av

    def iface_of(self, u, v):
        return self.iface[(u, v)]

    def probe_addr(self, n):
        return '2001:db8:ff::%d' % self.num[n]

    def node_sid(self, n):
        return '2001:db8:100:%d::ff' % self.num[n]

    def adj_sid(self, u, v):
        return '2001:db8:100:%d::%d' % (self.num[u], self.num[v])

    def sid_prefix(self, n):
        return '2001:db8:100:%d::/64' % self.num[n]

    # ---- 路径 <-> SID 列表 ----
    def seg_list(self, path):
        """把节点路径编译成正向 SID 列表.

        path = [s, p1, ..., d]: 对 p1..d 的每一跳取 p_i -> p_{i+1} 的邻接 SID,
        末尾换成 d 的 node SID (End: 弹 SRH 并本地交付). s 自己不出现在列表里.
        """
        path = list(path)
        segs = [self.adj_sid(path[i], path[i + 1]) for i in range(1, len(path) - 1)]
        segs.append(self.node_sid(path[-1]))
        return segs

    def rev_segs(self, path):
        """反向 SID 列表 = 反转路径的正向列表 (藏在 payload 里)."""
        return self.seg_list(list(reversed(path)))

    def nexthop_map(self, n, macs):
        """响应端的出口表: {对端节点 SID 的 /64: [出口接口, 下一跳 MAC]}."""
        return {self.sid_prefix(dst): [self.iface_of(n, hop), macs[(n, hop)]]
                for dst, hop in self.hop[n].items()}


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


# ---- Mininet 侧 ----
def build_mininet(plan, port=9999, timeout=3.0):
    """建拓扑 + 配地址/SID/路由 + 预热, 返回 ProbeExecutor.

    只有这个函数依赖 Mininet 和 root; --simulate 模式不走到这里.
    """
    from mininet.net import Mininet
    from mininet.link import TCLink
    from mininet.clean import cleanup

    from lib.common import Router, add6, enable_seg6, run_cmd

    cleanup()
    net = Mininet(controller=None, link=TCLink)
    for n in plan.nodes:
        net.addHost(n, cls=Router, ip=None)
    for u, v, ms in plan.edges:
        lk = net.addLink(net[u], net[v], delay='%gms' % ms)
        plan.iface.update(_iface_pairs(u, v, lk))
    if len(plan.iface) != 2 * len(plan.edges):
        raise RuntimeError('接口映射不完整: %d 条, 应为 %d 条'
                           % (len(plan.iface), 2 * len(plan.edges)))
    net.start()
    try:
        _configure(net, plan)
        macs = _macs(net, plan)
        warmup(net, plan)
        return ProbeExecutor(net, plan, macs, port=port, timeout=timeout)
    except Exception:
        net.stop()                  # 配置中途失败也要回收命名空间, 不留残留
        raise


def _configure(net, plan):
    """配探针地址 / 链路地址 / SRv6 SID 行为 / SID 聚合路由."""
    from lib.common import add6, enable_seg6, run_cmd

    # 探针地址 (内层目的地址) + SRv6 接收处理
    for n in plan.nodes:
        net[n].cmd('ip -6 addr add %s/128 dev lo nodad' % plan.probe_addr(n))
        enable_seg6(net[n], [plan.iface_of(n, v) for v in plan.neighbors(n)])
    # 链路地址
    for (u, v), (au, av) in plan.link.items():
        add6(net[u], plan.iface_of(u, v), au + '/64')
        add6(net[v], plan.iface_of(v, u), av + '/64')

    # SID 行为: node SID 用 End, 邻接 SID 用 End.X (逐跳钉死的核心)
    for n in plan.nodes:
        run_cmd(net[n], 'ip -6 route add %s/128 encap seg6local action End dev lo'
                % plan.node_sid(n))
        for peer in plan.neighbors(n):
            run_cmd(net[n], 'ip -6 route add %s/128 encap seg6local action End.X '
                    'nh6 %s dev %s'
                    % (plan.adj_sid(n, peer), plan.addr(peer, n),
                       plan.iface_of(n, peer)))

    # SID 聚合路由: 每个节点到其他节点的 SID 前缀都有一条下一跳
    for n in plan.nodes:
        for dst, hop in plan.hop[n].items():
            run_cmd(net[n], 'ip -6 route add %s via %s dev %s'
                    % (plan.sid_prefix(dst), plan.addr(hop, n),
                       plan.iface_of(n, hop)))


def _macs(net, plan):
    """读每条有向链路发送侧的接口 MAC (响应端构造以太头要用)."""
    out = {}
    for u, v, _ in plan.edges:
        out[(u, v)] = net[u].cmd('cat /sys/class/net/%s/address'
                                 % plan.iface_of(u, v)).strip()
        out[(v, u)] = net[v].cmd('cat /sys/class/net/%s/address'
                                 % plan.iface_of(v, u)).strip()
    return out


def warmup(net, plan):
    """每条链路双向各 ping 一次, 把正向和反向每一跳的 NDP 都焐热.

    只预热"一条路径"不够: 首个探测包曾在反向路径的中间路由器上排队等 NDP, 凭空
    多出约 80 ms (详见 design1/demo.py 的关键坑第 8 条). 闭环里任意节点对都可能
    被探, 所以每条链路都要预热 —— 也顺带把 SID 聚合路由的下一跳解析出来.
    """
    for (u, v), (au, av) in plan.link.items():
        net[u].cmd('ping6 -c 2 -i 0.2 -W 1 -I %s %s >/dev/null 2>&1'
                   % (plan.iface_of(u, v), av))
        net[v].cmd('ping6 -c 2 -i 0.2 -W 1 -I %s %s >/dev/null 2>&1'
                   % (plan.iface_of(v, u), au))


class ProbeExecutor(object):
    """在真实拓扑上逐条执行探测: 正向 SID 列表 + 反向列表藏 payload."""

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
        """每个节点起一个响应端: 按反向首段 SID 查表选出口 (多接口节点必需)."""
        os.makedirs(self.logdir, exist_ok=True)
        for n in self.plan.nodes:
            nh = os.path.join(self.logdir, 'nexthop_%s.json' % n)
            with open(nh, 'w') as f:
                json.dump(self.plan.nexthop_map(n, self.macs), f)
            log = os.path.join(self.logdir, 'responder_%s.log' % n)
            self.net[n].cmd(
                'python3 %s respond --port %d --me %s --nexthop-map %s '
                '--duration 0 > %s 2>&1 &'
                % (self.probe_py, self.port, self.plan.probe_addr(n), nh, log))
            self.responders.append(n)
        time.sleep(1.0)

    def stop_responders(self):
        for n in self.responders:
            self.net[n].cmd('pkill -f "probe.py respond" >/dev/null 2>&1')

    def probe(self, path):
        """探一条节点路径, 返回 (单向时延 ms, RTT ms); 失败返回 None."""
        src, dst = path[0], path[-1]
        segs = self.plan.seg_list(path)
        rev = self.plan.rev_segs(path)
        cmd = ('python3 %s probe --dst %s --port %d --segs %s --seg-dev %s %s '
               '--oneway --count 1 --interval 0 --timeout %g'
               % (self.probe_py, self.plan.probe_addr(dst), self.port,
                  ','.join(segs), self.plan.iface_of(src, path[1]),
                  ' '.join('--rev-sid %s' % s for s in rev), self.timeout))
        m = r = None
        for _ in range(self.retries + 1):        # 第一次可能撞上路由缓存/NDP, 重试一次
            detail('  $ [%s] %s' % (src, cmd))
            out = self.net[src].cmd(cmd).strip()
            detail('    ' + out.replace('\n', '\n    '))
            m = re.search(r'单向 = ([\d.]+) ms', out)
            if m:
                r = re.search(r'RTT = ([\d.]+) ms', out)
                break
        if not m:
            return None
        return float(m.group(1)), (float(r.group(1)) if r else None)

    def set_link_delay(self, u, v, ms):
        """把链路 (u, v) 两个方向的出口时延都设成 ms (故障注入 / 恢复)."""
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
