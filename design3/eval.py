#!/usr/bin/env python3
r"""eval.py -- Design 3 三层剪枝的离线评测 (合成拓扑, 免 root)
================================================================

用合成拓扑复现论文 Table III 的分阶段削减量级:

    Step 1 分区剪枝   (模块度分区 + 代表节点跨分区)  -> 论文平均 50.6%
    Step 2 路径感知剪枝 (Algorithm 3 渐进探测)       -> 论文平均 66.2%
    Step 3 故障感知剪枝 (跨切片优先 + 提前终止)      -> 论文平均 51.4%
    三层叠乘总体                                     -> 论文平均 91.9%

模型 (与论文测试床的差异见 README):
    * 探测对的路径取拓扑里的最短路; 分区内探测把路径限制在分区诱导子图内, 对应论文
      里 SR-TE 把路径约束在分区内.
    * 链路时延: 正常链路 BASE_MS, 注入故障的链路 FAULT_MS; 路径时延为各链路之和,
      超过阈值即判异常 => "路径异常 <=> 它含故障链路".
    * 切片 = 随机取 70% 节点且保证连通; 每切片随机注入若干故障链路; 跨切片故障传播
      按论文的 3% 概率, 只影响后续切片的探测优先级.
    * 削减口径: Step 2 在健康网络 (无故障) 上衡量"路径感知剪枝"; Step 3 才注入故障,
      并按跨切片优先 + 提前终止衡量"故障感知剪枝".
    * Step 3 的削减 = "所有故障链路都已被异常路径覆盖"之后的提前终止所省下的探测.

用法:

    python3 design3/eval.py
    python3 design3/eval.py --slices 256 --repeat 5
    python3 design3/eval.py --help
"""
import argparse
import os
import random
import sys

# 脚本在 design3/ 下, 把仓库根加入 sys.path 以便 import design3.plan
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from design3.plan import (Graph, localize, partition, plan_partitioned,
                          plan_stats, priority_key, progressive)

BASE_MS = 1.0            # 正常链路单向时延
FAULT_MS = 100.0         # 故障链路单向时延
THRESHOLD_MS = 50.0      # 异常判定阈值 E (论文 Fig.12 的 threshold E)
PROPAGATE_P = 0.03       # 论文的跨切片故障传播概率


# ---- 合成拓扑 ----
def gen_isp():
    """ISP 分层拓扑: 核心 - 汇聚 - 接入 (接入串成链), 模块度高."""
    g = Graph()
    g.add_edge('c1', 'c2')
    for i, agg in enumerate(('a1', 'a2', 'a3', 'a4')):
        g.add_edge(agg, ('c1', 'c2')[i % 2])
        acc = ['%s%d' % (agg, k) for k in (1, 2, 3)]
        g.add_edge(agg, acc[0])
        g.add_edge(acc[0], acc[1])
        g.add_edge(acc[1], acc[2])
    g.add_edge('a1', 'a2')
    g.add_edge('a3', 'a4')
    return g


def gen_sdwan(sites=6, per_site=2):
    """SD-WAN: 站点内 PE + 主机星型, 站点 PE 之间连成骨干环, 模块度中等."""
    g = Graph()
    pes = ['pe%d' % i for i in range(1, sites + 1)]
    for i, pe in enumerate(pes):
        g.add_edge(pe, pes[(i + 1) % len(pes)])
        for k in range(1, per_site + 1):
            g.add_edge(pe, '%s_h%d' % (pe, k))
    return g


def gen_dc(racks=4, per_rack=3):
    """DC 叶脊拓扑: 2 脊 + 每机架 1 叶 + 主机, 再跨机架直连削弱社区结构.

    对应论文里 "DC 拓扑没有清晰的分区结构, Step 1 收益有限".
    """
    g = Graph()
    g.add_edge('s1', 's2')
    for r in range(1, racks + 1):
        leaf = 'l%d' % r
        g.add_edge(leaf, 's1')
        g.add_edge(leaf, 's2')
        hosts = ['h%d%d' % (r, k) for k in range(1, per_rack + 1)]
        for h in hosts:
            g.add_edge(leaf, h)
        g.add_edge(hosts[0], hosts[1])
    g.add_edge('h11', 'h21')
    g.add_edge('h31', 'h41')
    return g


def gen_random(n=20, extra=8, seed=7):
    """随机图: 随机生成树 + 若干随机加边, 无社区结构."""
    rng = random.Random(seed)
    g = Graph()
    nodes = ['n%02d' % i for i in range(1, n + 1)]
    for i in range(1, n):
        g.add_edge(nodes[i], nodes[rng.randrange(i)])
    for _ in range(extra):
        u, v = rng.sample(nodes, 2)
        g.add_edge(u, v)
    return g


def topologies():
    """评测用的合成拓扑集: (名字, 生成函数, 结构说明)."""
    return [
        ('ISP-2tier', gen_isp, '核心-汇聚-接入, 模块度高'),
        ('SDWAN-6site', gen_sdwan, '站点星型 + 骨干环, 模块度中'),
        ('DC-leafspine', gen_dc, '叶脊 + 跨机架直连, 模块度低'),
        ('random-20', lambda: gen_random(20, 8, seed=7), '随机树 + 加边, 无结构'),
    ]


# ---- 切片与故障 ----
def connected_slice(g, ratio, rng):
    """随机取一个连通节点子集: BFS 序前缀必然连通, 取前 k 个."""
    nodes = g.nodes()
    k = max(2, int(round(len(nodes) * ratio)))
    start = rng.choice(nodes)
    seen, order, queue = {start}, [], [start]
    while queue:
        v = queue.pop(0)
        order.append(v)
        for nb in g.neighbors(v):
            if nb not in seen:
                seen.add(nb)
                queue.append(nb)
    return sorted(order[:k])


def slice_faults(g, nodes, count, rng):
    """在切片子图里随机注入 count 条故障链路."""
    sub = g.sub(nodes)
    links = sorted(sub.lid)
    if not links or count <= 0:
        return set()
    return set(rng.sample(links, min(count, len(links))))


def delay_probe(faults):
    """路径时延模型: 正常链路 BASE_MS, 故障链路 FAULT_MS; 超阈值即异常."""
    def probe(p):
        bad = len(p.links & faults)
        delay = bad * FAULT_MS + (len(p.links) - bad) * BASE_MS
        return delay <= THRESHOLD_MS
    return probe


# ---- 单切片评测 ----
def eval_slice(g, nodes, faults, other_failed, other_probed):
    """在一条切片上跑三层剪枝, 返回各级探测数与正确性指标.

    削减口径与论文一致: Step 2 衡量"路径感知剪枝"本身, 因此跑在健康网络上;
      Step 3 才注入故障 (故障感知剪枝). 正确性 (漏探/漏检) 一律按有故障时的那次
      探测来判: 有故障时异常路径不剪枝, 所以判断最严格.
    """
    sub = g.sub(nodes)
    plan = plan_partitioned(g, nodes, partition(sub))
    st = plan_stats(g, nodes, plan)

    # Step 2: 渐进探测, 健康网络 (长路径正常 => 被它包含的路径全部免探)
    _, _, rounds_ok, step2 = progressive(plan, lambda p: True)

    # 有故障时的渐进探测: 用于正确性检查 (异常路径不允许产生任何免探)
    probe = delay_probe(faults)
    a2, n2, rounds2, _ = progressive(plan, probe)

    # Step 3: 跨切片故障优先 + 所有故障链路都可见后提前终止
    covered = set()

    def stop():
        return bool(faults) and faults <= covered

    def probe3(p):
        ok = probe(p)
        if not ok:
            covered.update(p.links & faults)
        return ok

    order = lambda p: (priority_key(p, other_failed, other_probed)
                       + (-len(p.links), p.src, p.dst))
    a3, n3, rounds3, step3 = progressive(plan, probe3, order=order, stop=stop)

    # 正确性 1: 被剪掉的路径里不能含故障链路 (只剪被正常路径包含的路径)
    probed2 = set(a2) | set(n2)
    hidden = [p for p in plan if (p.links & faults) and p not in probed2]
    # 正确性 2: 每条故障链路都要被某条被探的异常路径覆盖
    visible = set()
    for p in a2:
        visible |= (p.links & faults)
    loc = localize(a2, n2)

    return {'baseline': st['baseline'], 'step1': st['probes'],
            'step2': step2, 'step3': step3,
            'rounds': rounds2, 'rounds3': rounds3, 'rounds_ok': rounds_ok,
            'hidden': len(hidden), 'missed': len(faults - visible),
            'loc': len(loc), 'nfault': len(faults),
            'probed_links': set().union(*[set(p.links) for p in (a3 + n3)]
                                        ) if (a3 or n3) else set(),
            'cov_bad': 0 if st['covered'] == st['edges'] else 1}


def eval_topology(name, gen, desc, args, seed):
    """一个拓扑上重复若干轮: 每轮重新采样切片与故障, 汇总平均."""
    tot = {k: 0.0 for k in ('baseline', 'step1', 'step2', 'step3', 'rounds',
                            'rounds3', 'rounds_ok', 'hidden', 'missed',
                            'loc', 'nfault', 'cov_bad')}
    n_slices = 0
    nodes_n = edges_n = 0
    other_failed, other_probed = set(), set()
    for rep in range(args.repeat):
        rng = random.Random(seed + 1000 * rep)
        g = gen()
        nodes_n, edges_n = len(g.nodes()), g.n_edges
        other_failed, other_probed = set(), set()
        for _ in range(args.slices):
            nodes = connected_slice(g, args.ratio, rng)
            faults = slice_faults(g, nodes, args.faults, rng)
            res = eval_slice(g, nodes, faults, other_failed, other_probed)
            for k in tot:
                tot[k] += res[k]
            n_slices += 1
            for lid in faults:
                if rng.random() < PROPAGATE_P:
                    other_failed.add(lid)      # 3% 概率波及别的切片
            other_failed |= faults
            other_probed |= res['probed_links']
    avg = {k: v / max(1, n_slices) for k, v in tot.items()}
    # 计数类指标用原始和打印 (均值会是 0.0x 这种看不出规模的小数)
    avg['hidden'] = tot['hidden']
    avg['missed'] = tot['missed']
    avg['cov_bad'] = tot['cov_bad']
    avg['n_slices'] = n_slices
    avg.update(name=name, desc=desc, nodes=nodes_n, edges=edges_n)
    # 削减比例: 每层相对上一层 (与论文 Table III 的口径一致)
    avg['r1'] = 100.0 * (1 - avg['step1'] / max(1e-9, avg['baseline']))
    avg['r2'] = 100.0 * (1 - avg['step2'] / max(1e-9, avg['step1']))
    avg['r3'] = 100.0 * (1 - avg['step3'] / max(1e-9, avg['step2']))
    avg['rt'] = 100.0 * (1 - avg['step3'] / max(1e-9, avg['baseline']))
    # 链路级定位的宽度: 异常路径交集 - 正常路径 得到的候选链路数 / 注入故障数
    avg['loc_ratio'] = avg['loc'] / max(1e-9, avg['nfault'])
    return avg


# ---- 输出 ----
def _head():
    print('')
    print('  %-13s %4s %4s %7s | %6s %6s | %7s %6s | %8s %6s | %7s %5s %4s %4s %7s'
          % ('拓扑', '节点', '边', '全互联',
             'Step1', '削减1', 'Step1+2', '削减2', 'Step1+2+3', '削减3',
             '总削减', '轮数', '漏探', '漏检', '候选/故障'))


def _row(r):
    print('  %-13s %4d %4d %7d | %6.1f %5.1f%% | %7.1f %5.1f%% | %8.1f %5.1f%% | %6.1f%% %5.2f %4d %4d %6.2fx'
          % (r['name'], r['nodes'], r['edges'], r['baseline'],
             r['step1'], r['r1'], r['step2'], r['r2'], r['step3'], r['r3'],
             r['rt'], r['rounds'], r['hidden'], r['missed'], r['loc_ratio']))


def main():
    ap = argparse.ArgumentParser(description='Design 3 三层剪枝离线评测')
    ap.add_argument('--slices', type=int, default=64, help='每轮每拓扑的切片数')
    ap.add_argument('--repeat', type=int, default=3, help='重复轮数 (论文 10 次取均值)')
    ap.add_argument('--ratio', type=float, default=0.7, help='切片包含的节点比例')
    ap.add_argument('--faults', type=int, default=1,
                    help='每切片注入的故障链路数 (论文的 Step 3 才引入故障)')
    ap.add_argument('--seed', type=int, default=2026)
    args = ap.parse_args()

    print('== Design 3 三层剪枝离线评测 (合成拓扑) ==')
    print('  切片: 每拓扑 %d 片 x %d 轮, 节点比例 %.0f%%, 每切片故障 %d 条'
          % (args.slices, args.repeat, args.ratio * 100, args.faults))
    print('  模型: 最短路为探测路径; 正常链路 %.0fms / 故障链路 %.0fms, 阈值 E = %.0fms'
          % (BASE_MS, FAULT_MS, THRESHOLD_MS))
    _head()
    rows = []
    for i, (name, gen, desc) in enumerate(topologies()):
        r = eval_topology(name, gen, desc, args, args.seed + i)
        rows.append(r)
        _row(r)
    n_all = sum(r['n_slices'] for r in rows)
    print('')
    for r in rows:
        print('  %-13s %s' % (r['name'], r['desc']))
    print('')
    print('  论文 Table III 参考: Step1 50.6%%, Step2 66.2%%, Step3 51.4%%, 总体 91.9%%')
    print('  (削减口径: 每层相对上一层; 总体 = 相对全互联 Pingmesh 基线)')
    print('  Step2 在健康网络上衡量 (无故障); Step3 注故障 (每切片 %d 条) 并按'
          '跨切片故障优先 + 提前终止' % args.faults)
    print('  渐进探测轮数: 健康网络 %.2f, 有故障 %.2f, Step3 提前终止 %.2f'
          ' (论文称通常两轮)'
          % (sum(r['rounds_ok'] * r['n_slices'] for r in rows) / n_all,
             sum(r['rounds'] * r['n_slices'] for r in rows) / n_all,
             sum(r['rounds3'] * r['n_slices'] for r in rows) / n_all))
    print('  覆盖与正确性 (共 %d 片切片): 覆盖有遗漏 %d 片, 漏探 %d 条, 漏检 %d 条'
          ' (应全为 0)'
          % (n_all, sum(r['cov_bad'] for r in rows),
             sum(r['hidden'] for r in rows), sum(r['missed'] for r in rows)))
    print('  候选/故障: 异常路径交集减正常路径后的候选链路数 / 注入故障数,'
          ' 1.00x 表示链路级定位恰好收敛 (链路级时延由 Design 2 反解)')
    print('')
    print('[RESULT] 总体削减 平均 %.1f%% (论文 91.9%%), 最大 %s %.1f%%, 最小 %s %.1f%%'
          % (sum(r['rt'] for r in rows) / len(rows),
             max(rows, key=lambda r: r['rt'])['name'],
             max(r['rt'] for r in rows),
             min(rows, key=lambda r: r['rt'])['name'],
             min(r['rt'] for r in rows)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
