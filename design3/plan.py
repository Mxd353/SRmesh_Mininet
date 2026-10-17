#!/usr/bin/env python3
r"""plan.py -- SRmesh Design 3 拓扑无关的渐进式诊断 (探测规划)
================================================================

Design 3 不碰数据面, 只回答两件事: 探哪些节点对? 按什么顺序探? 三层剪枝叠乘:

    Step 1 分区探测 (论文式 (11) / Algorithm 2)
        模块度最大化把切片切成内部连接更密的子网; 各分区内全互联, 跨分区再选
        代表节点做一次全互联; 最后按论文式 (6) 的覆盖约束补齐漏掉的边, 保证全覆盖.

    Step 2 渐进探测 (Algorithm 3)
        长路径正常 => 它包含的所有短路径都正常; 被已验证正常路径包含的待探路径
        直接免探, 通常两轮收敛.

    Step 3 跨切片故障传播优先
        别的切片里已故障的链路优先探; 还没被别的切片探过的链路优先探.

用法:

    from design3.plan import Graph, partition, plan_partitioned, progressive

    g = Graph.from_edges([('A', 'B', 'eAB'), ('B', 'D', 'eBD')])
    plan = plan_partitioned(g, g.nodes(), partition(g))
    abnormal, normal, rounds, n = progressive(plan, probe_fn)

模型假设 (与论文测试床的差异, 见 README): 探测对的路径取拓扑里的最短路; 分区内
探测把路径限制在分区诱导子图内, 对应论文里 SR-TE 把路径约束在分区内; 链路级时延
仍由 Design 2 反解, 本模块只负责"探哪些、什么顺序".
"""
import itertools
from collections import namedtuple

# 探测对: src/dst 为节点名 (src < dst, 对应论文式 (9) 一个节点对只取一个方向),
# path 为节点序列, links 为路径经过的链路 id 集合 (免探判据用它做子集比较).
Probe = namedtuple('Probe', 'src dst path links')


# ---- 图 ----
class Graph(object):
    """无向图: 邻接表 {node: {neighbor: link_id}}.

    链路 id 可显式给 (便于把推断结果对回物理链路), 不给则按端点名排序生成 'u|v'.
    """

    def __init__(self):
        self.adj = {}
        self.lid = {}                       # link_id -> (u, v) (端点已排序)

    def add_edge(self, u, v, lid=None):
        if u == v:
            raise ValueError('自环不受支持: %s' % u)
        if lid is None:
            lid = '%s|%s' % tuple(sorted((u, v)))
        self.adj.setdefault(u, {})[v] = lid
        self.adj.setdefault(v, {})[u] = lid
        self.lid[lid] = tuple(sorted((u, v)))
        return lid

    @classmethod
    def from_edges(cls, edges):
        """edges: [(u, v)] 或 [(u, v, link_id)]."""
        g = cls()
        for e in edges:
            g.add_edge(*e)
        return g

    def sub(self, nodes):
        """切片诱导子图: 只保留两端都在 nodes 里的边 (链路 id 保持不变)."""
        keep = set(nodes)
        g = Graph()
        for u, v, lid in self.edge_list():
            if u in keep and v in keep:
                g.add_edge(u, v, lid)
        return g

    def nodes(self):
        return sorted(self.adj)

    def neighbors(self, v):
        return sorted(self.adj.get(v, {}))

    def degree(self, v):
        return len(self.adj.get(v, {}))

    def edge_list(self):
        """[(u, v, link_id)] 按链路 id 排序, 结果可复现."""
        return [(u, v, lid) for lid, (u, v) in sorted(self.lid.items())]

    @property
    def n_edges(self):
        return len(self.lid)

    def links_of(self, path):
        """路径经过的链路 id 集合."""
        return frozenset(self.adj[path[i]][path[i + 1]]
                         for i in range(len(path) - 1))

    def shortest_path(self, src, dst, allowed=None):
        """BFS 最短路 (邻居按名字排序, 平局可复现); allowed 限制可经过的节点集合."""
        if src == dst:
            return [src]
        seen = {src}
        queue = [(src, [src])]
        while queue:
            cur, path = queue.pop(0)
            for nb in self.neighbors(cur):
                if nb in seen or (allowed is not None and nb not in allowed):
                    continue
                if nb == dst:
                    return path + [nb]
                seen.add(nb)
                queue.append((nb, path + [nb]))
        return None


# ---- Step 1: 模块度最大化分区 (论文式 (11) / Algorithm 2) ----
def modularity(g, part):
    """论文式 (11): Q = 1/(2m) * sum_ij [A_ij - k_i*k_j/(2m)] * delta(c_i, c_j).

    按分区直接求和, 复杂度 O(E), 用作 delta_q_move() 的校验基准.
    """
    m = g.n_edges
    if m == 0:
        return 0.0
    q = 0.0
    for comm in set(part.values()):
        members = [v for v in g.nodes() if part[v] == comm]
        deg_sum = sum(g.degree(v) for v in members)
        inner2 = sum(1 for v in members for nb in g.neighbors(v)
                     if part[nb] == comm)
        q += inner2 / (2.0 * m) - (deg_sum / (2.0 * m)) ** 2
    return q


def delta_q_move(g, v, part, tot, to_comm):
    """把节点 v 从当前分区移到 to_comm 的模块度增量 (增量式, 不重算 Q).

        dQ = (k_in(to) - k_in(from)) / m - k_v * (tot[to] - tot[from] + k_v) / (2m^2)

    其中 k_in(C) 是 v 到 C 内节点的边数, tot[C] 是 C 的度数之和, m 是边数.
    与 modularity() 的一致性由 test_modularity_delta() 数值校验.
    """
    m = g.n_edges
    if m == 0:
        return 0.0
    kv = g.degree(v)
    frm = part[v]
    k_in_from = sum(1 for nb in g.neighbors(v) if part[nb] == frm)
    k_in_to = sum(1 for nb in g.neighbors(v) if part[nb] == to_comm)
    return ((k_in_to - k_in_from) / float(m)
            - kv * (tot.get(to_comm, 0) - tot.get(frm, 0) + kv) / float(2 * m * m))


def partition(g):
    """论文 Algorithm 2: 模块度最大化分区 (单层 Louvain 贪心移动).

    初始每节点独立成区 (line 1); 反复扫描节点, 把它移到"相邻分区"里使 dQ 最大且
    为正的那个 (line 4-9); 直到一整轮没有任何节点移动 (line 3). 节点按名字排序
    遍历, 因此结果可复现.
    """
    part = {v: v for v in g.nodes()}
    tot = {v: g.degree(v) for v in g.nodes()}
    moved = True
    while moved:
        moved = False
        for v in g.nodes():
            # "相邻分区": 只考虑含 v 的邻居的分区 (不含 v 当前所在分区)
            cands = sorted({part[nb] for nb in g.neighbors(v)} - {part[v]})
            best, best_dq = None, 0.0
            for comm in cands:
                dq = delta_q_move(g, v, part, tot, comm)
                if dq > best_dq + 1e-12:
                    best, best_dq = comm, dq
            if best is not None:
                old = part[v]
                part[v] = best
                tot[old] -= g.degree(v)
                tot[best] = tot.get(best, 0) + g.degree(v)
                moved = True
    return part


def partition_groups(part):
    """把 {node: comm} 整理成 [[node, ...], ...] (组内按名字排序, 组间按首节点排序)."""
    groups = {}
    for v, comm in part.items():
        groups.setdefault(comm, []).append(v)
    return [sorted(groups[c]) for c in sorted(groups)]


# ---- Step 1: 分区探测计划 ----
def _probe(g, u, v, allowed=None):
    """按最短路构造一个探测对 (u < v), 不可达返回 None."""
    if u == v:
        return None
    a, b = sorted((u, v))
    path = g.shortest_path(a, b, allowed)
    if path is None or len(path) < 2:
        return None
    return Probe(a, b, tuple(path), g.links_of(path))


def cover_completion(g, plan):
    """覆盖补齐: 把没被任何探测路径覆盖的边, 用两端点直连探测补上 (论文式 (6)).

    对应论文 ILP 里的覆盖约束 Y_si(u, v) >= 1: 每条边至少要落在一条探测路径上.
    只用直连对补, 保证可终止且开销可统计. 另外, 若探测对 (u, v) 已经计划里, 它的
    路径必然是直连边 (BFS 见到邻居就返回), 该边不会漏; 所以补齐用的对一定是新对.
    """
    covered = set()
    for p in plan:
        covered |= p.links
    extra = []
    for lid, (u, v) in sorted(g.lid.items()):
        if lid not in covered:
            extra.append(Probe(u, v, (u, v), frozenset([lid])))
    return extra


def plan_partitioned(g, nodes, part):
    """论文 Design 3 Step 1: 分区内全互联 + 代表节点跨分区全互联 + 覆盖补齐.

    参数:
        g:     物理拓扑 (Graph)
        nodes: 本切片的节点集合
        part:  分区结果 (可来自 partition(g.sub(nodes)) 或复用的物理分区)

    返回 Probe 列表: 先是分区内探测, 再是跨分区代表节点探测, 最后是覆盖补齐.
    """
    sub = g.sub(nodes)
    keep = set(nodes)
    groups = [[v for v in grp if v in keep] for grp in partition_groups(part)]
    groups = [grp for grp in groups if grp]      # 分区可能落在切片外变成空组

    plan, seen = [], set()

    def add(u, v, allowed=None):
        if u == v or tuple(sorted((u, v))) in seen:
            return
        p = _probe(sub, u, v, allowed)
        if p is None:
            return
        seen.add((p.src, p.dst))
        plan.append(p)

    # 分区内全互联: 路径限制在本分区诱导子图内, 这样分区内的边才可能被覆盖
    for grp in groups:
        for u, v in itertools.combinations(grp, 2):
            add(u, v, allowed=set(grp))

    # 跨分区: 每个分区选代表节点 (分区内度最大), 代表节点之间全互联
    reps = [sorted(grp, key=lambda v: (-sub.degree(v), v))[0]
            for grp in groups if grp]
    for u, v in itertools.combinations(sorted(set(reps)), 2):
        add(u, v)

    return plan + cover_completion(sub, plan)


def plan_stats(g, nodes, plan):
    """计划的统计: 探测对数, 覆盖情况, 以及全互联基线."""
    sub = g.sub(nodes)
    covered = set()
    for p in plan:
        covered |= p.links
    n = len(set(nodes))
    return {'probes': len(plan),
            'covered': len(covered & set(sub.lid)),
            'edges': sub.n_edges,
            'baseline': n * (n - 1) // 2}


# ---- Step 2: 渐进探测 (Algorithm 3) ----
def maximal_paths(probes):
    """取 probes 中"极大"的路径 (不被同集合内其他路径的链路集合包含).

    先按链路数降序处理, 用一个已接受的极大集合去重: 被已接受集合包含的必非极大.
    """
    out = []
    for p in sorted(probes, key=lambda q: (-len(q.links), q.src, q.dst)):
        if not any(p.links <= m.links for m in out):
            out.append(p)
    return out


def progressive(probes, probe, order=None, stop=None, trace=None):
    """论文 Algorithm 3: 渐进探测.

    论文正文的语义是"长路径正常 => 它包含的短路径都正常", 于是被正常路径包含的
    待探路径可以直接免探. 但 Algorithm 3 的字面写法 (line 4-8 只在正常集 N 里查
    包含关系) 在第一轮 N 为空时会把所有待探路径都选进 S, 退化成全量探测, 拿不到
    论文声称的剪枝. 本函数按正文语义实现, 保证剪枝存在:

        * 每轮只探 U 中的极大路径 (不被 U 内其他路径包含);
        * 路径被探为正常后, 立刻把被它包含的待探路径从 U 里删掉 (免探);
        * 异常路径不产生任何免探 (它包含的短路径仍要探, 才能定位).

    参数:
        probes: Probe 列表 (待探路径集合 P)
        probe:  callable(Probe) -> bool, True 表示正常, False 表示异常
        order:  可选, callable(Probe) -> 排序键, 决定每轮批次内的探测顺序
                (默认按路径长度降序; Step 3 传入跨切片优先键)
        stop:   可选, callable() -> bool, 每条探完询问一次是否提前终止
        trace:  可选 list, 逐条记录 (轮次, src->dst, 结果)

    返回 (abnormal, normal, rounds, n_probed).
    """
    U = list(probes)
    normal, abnormal = [], []
    normal_links = []                   # 已验证正常路径的链路集合
    rounds, n_probed = 0, 0
    while U:
        rounds += 1
        batch = maximal_paths(U)
        if order is None:
            batch.sort(key=lambda p: (-len(p.links), p.src, p.dst))
        else:
            batch.sort(key=order)
        for p in batch:
            # 本轮内已被更长的正常路径覆盖 => 免探
            if any(p.links <= nl for nl in normal_links):
                if trace is not None:
                    trace.append((rounds, '%s->%s' % (p.src, p.dst), '免探'))
                continue
            n_probed += 1
            ok = probe(p)
            if trace is not None:
                trace.append((rounds, '%s->%s' % (p.src, p.dst),
                              '正常' if ok else '异常'))
            if ok:
                normal.append(p)
                normal_links.append(p.links)
            else:
                abnormal.append(p)
            if stop is not None and stop():
                return abnormal, normal, rounds, n_probed
        done = set(batch)
        U = [p for p in U if p not in done]
        U = [p for p in U if not any(p.links <= nl for nl in normal_links)]
    return abnormal, normal, rounds, n_probed


def localize(abnormal, normal=()):
    """候选瓶颈链路 = 所有异常路径的链路交集, 再减去所有正常路径走过的链路.

    在"路径异常 <=> 它含故障链路"的确定性模型下, 这一步就能把候选收敛到具体链路
    (论文正文的 "A-D 正常 => A-B、B-D 都正常" 同一个道理); 有噪声时再交给 Design 2
    做链路级反解.
    """
    if not abnormal:
        return frozenset()
    cand = set(abnormal[0].links)
    for p in abnormal[1:]:
        cand &= set(p.links)
    for p in normal:
        cand -= set(p.links)
    return frozenset(cand)


# ---- Step 3: 跨切片故障传播优先 ----
def priority_key(p, failed_links, probed_links):
    """跨切片故障传播的两条优先规则 (论文 Design 3 Step 3).

    规则 1: 覆盖了"别的切片里已故障链路"的路径优先 (故障可能已经传播过来);
    规则 2: 覆盖了"还没被别的切片探过的链路"的路径优先 (信息量更大).
    """
    return (0 if p.links & failed_links else 1,
            0 if (p.links - probed_links) else 1)


def prioritize(probes, failed_links, probed_links):
    """按跨切片优先规则重排探测顺序 (只改顺序, 不改集合)."""
    return sorted(probes, key=lambda p: (priority_key(p, failed_links, probed_links),
                                         -len(p.links), p.src, p.dst))


# ---- 输出 ----
def _section(title):
    print("\n== %s ==" % title)


# ---- 自测 ----
def _sample_graph():
    """自测用的小 ISP 拓扑: 核心 c1-c2, 两个汇聚各挂一串接入."""
    g = Graph()
    g.add_edge('c1', 'c2')
    g.add_edge('c1', 'a1')
    g.add_edge('c2', 'a2')
    g.add_edge('a1', 'a2')
    for agg in ('a1', 'a2'):
        acc = ['%s%d' % (agg, k) for k in (1, 2, 3)]
        g.add_edge(agg, acc[0])
        g.add_edge(acc[0], acc[1])
        g.add_edge(acc[1], acc[2])
    return g


def test_modularity_delta():
    """式 (11) 直接求和 vs 增量 dQ: 逐个候选移动对比, 两者必须一致."""
    _section('模块度增量校验 (式 (11) 直接求和 vs 增量公式)')
    g = _sample_graph()
    part = {v: v for v in g.nodes()}
    tot = {v: g.degree(v) for v in g.nodes()}
    worst, cases = 0.0, 0
    for v in g.nodes():
        for comm in sorted({part[nb] for nb in g.neighbors(v)} - {part[v]}):
            cases += 1
            dq = delta_q_move(g, v, part, tot, comm)
            before = modularity(g, part)
            old = part[v]
            part[v] = comm
            after = modularity(g, part)
            part[v] = old
            worst = max(worst, abs((after - before) - dq))
    print('  对比 %d 次候选移动, 最大偏差 = %.3e' % (cases, worst))
    return worst < 1e-9


def test_partition():
    """两个三角形 + 一条桥: 模块度分区应恰好切成两个社区."""
    _section('模块度分区 (两个三角形 + 一条桥)')
    g = Graph.from_edges([('A', 'B'), ('B', 'C'), ('A', 'C'),
                          ('D', 'E'), ('E', 'F'), ('D', 'F'), ('A', 'D')])
    part = partition(g)
    groups = partition_groups(part)
    q = modularity(g, part)
    print('  分区: %s' % ' | '.join(','.join(grp) for grp in groups))
    print('  Q = %.4f  (最优两社区 0.3571, 单区 0.0000)' % q)
    ok = len(groups) == 2 and q > 0.3
    print('  %s' % ('OK' if ok else 'X'))
    return ok


def test_plan_coverage():
    """分区计划必须覆盖切片内所有边 (论文式 (6) 的全覆盖约束)."""
    _section('分区计划的覆盖完整性 (式 (6))')
    g = _sample_graph()
    nodes = g.nodes()
    plan = plan_partitioned(g, nodes, partition(g.sub(nodes)))
    st = plan_stats(g, nodes, plan)
    print('  节点=%d 边=%d 探测对=%d (全互联 %d) 覆盖=%d/%d'
          % (len(nodes), st['edges'], st['probes'], st['baseline'],
             st['covered'], st['edges']))
    ok = st['covered'] == st['edges']
    print('  %s' % ('OK' if ok else 'X 有边未被覆盖'))
    return ok


def test_progressive():
    """渐进探测: 正常时一轮剪完; 有故障时异常路径不剪枝并逐步收敛到具体链路."""
    chain = Graph.from_edges([('A', 'B', 'AB'), ('B', 'C', 'BC'), ('C', 'D', 'CD')])
    pairs5 = (('A', 'D'), ('A', 'B'), ('B', 'C'), ('B', 'D'), ('C', 'D'))
    plan5 = [_probe(chain, u, v) for u, v in pairs5]
    print('  待探路径 (5 条): %s'
          % ', '.join('%s->%s' % (p.src, p.dst) for p in plan5))

    _section('渐进探测: 全部正常 (长路径 A->D 覆盖其余 4 条)')
    a, n, rounds, probed = progressive(plan5, lambda p: True)
    print('  探测 %d/%d 条, 轮数 %d, 异常 %d' % (probed, len(plan5), rounds, len(a)))
    ok1 = probed == 1 and rounds == 1
    print('  %s (A->D 正常 => 其余 4 条免探)' % ('OK' if ok1 else 'X'))

    _section('渐进探测: B-C 故障 (异常路径不剪枝, 由短路径收敛到 B-C)')
    plan3 = [_probe(chain, u, v) for u, v in (('A', 'D'), ('A', 'B'), ('C', 'D'))]
    faults = {'BC'}

    def probe(p):
        return not (p.links & faults)

    a, n, rounds, probed = progressive(plan3, probe)
    loc = localize(a, n)
    print('  探测 %d/%d 条, 轮数 %d, 异常 %s, 正常 %s'
          % (probed, len(plan3), rounds,
             ', '.join('%s->%s' % (p.src, p.dst) for p in a),
             ', '.join('%s->%s' % (p.src, p.dst) for p in n)))
    print('  定位(异常链路交集 - 正常路径) = %s' % sorted(loc))
    ok2 = probed == 3 and rounds == 2 and loc == frozenset(['BC'])
    print('  %s (第一轮长路径异常 -> 第二轮短路径排除, 收敛到 B-C)'
          % ('OK' if ok2 else 'X'))
    return ok1 and ok2


def test_priority():
    """跨切片优先: 覆盖了别的切片故障链路的路径排到最前面."""
    g = Graph.from_edges([('A', 'B', 'AB'), ('B', 'C', 'BC'),
                          ('C', 'D', 'CD'), ('A', 'D', 'AD')])
    probes = [_probe(g, u, v) for u, v in
              (('A', 'B'), ('B', 'C'), ('C', 'D'), ('A', 'D'))]
    failed = {'AD'}                      # 别的切片里已故障的链路
    probed = {'AB'}                      # 别的切片已经探过的链路
    ordered = prioritize(probes, failed, probed)
    _section('跨切片优先 (别的切片故障链路 = AD, 已探链路 = AB)')
    print('  顺序: %s' % ', '.join('%s->%s' % (p.src, p.dst) for p in ordered))
    ok = ordered[0].src == 'A' and ordered[0].dst == 'D'
    print('  %s (A->D 同时命中规则 1 与规则 2, 排第一)' % ('OK' if ok else 'X'))
    return ok


def main():
    tests = [test_modularity_delta, test_partition, test_plan_coverage,
             test_progressive, test_priority]
    passed = sum(1 for t in tests if t())
    print('\n[RESULT] plan.py 自测: %d/%d 通过' % (passed, len(tests)))
    return 0 if passed == len(tests) else 1


if __name__ == '__main__':
    raise SystemExit(main())
