#!/usr/bin/env python3
r"""closed_loop.py -- Design 1 + 2 + 3 在 Mininet 上的闭环诊断
================================================================

三个 Design 在一次运行里各司其职 (论文里它们本来就是一个系统):

    Design 3  规划: 模块度分区 -> Step 1 计划 (分区内全互联 + 代表节点跨分区)
    Design 1  执行: 每条计划路径编译成逐跳钉死的正向/反向 SID 列表, 真包探测
    Design 2  反解: 单向时延 -> 链路时延 (nnls), 定位超过阈值 E 的链路
    Design 3  渐进: 长路径正常 => 它包含的短路径免探; 异常路径 -> 下一轮继续定位
    Design 3  优先: 已知故障链路 / 未探链路优先, 故障全部可见后提前终止

两个阶段:

    基线阶段: 全互联探一遍 (Pingmesh 式常态基线), Design 2 解出各条有向链路的时延,
              作为锚点, 也用来核对"解出来的是不是 netem 真值";
    诊断阶段: 注入故障后只探 Design 3 剪枝后剩下的路径, 用基线做参照判异常,
              再由 Design 2 把异常归因到具体链路.

为什么基线要全互联: Design 3 的稀疏探测保证的是"每条故障链路都落在某条异常路径上"
(可见性), 而"每条链路时延都能唯一反解"需要足够的方程; 8 节点 10 链路有 20 条有向
链路, Step 1 的 11 条探测解不出全部 —— 这是论文两个 Design 的分工, 不是实现缺陷.

拓扑来自 integration/fiti.json (41 节点 / 43 链路, 节点用 abbr 命名, weight 当链
路时延). 用法:

    sudo python3 integration/closed_loop.py                    # 真实 Mininet
    sudo python3 integration/closed_loop.py --fault bj tjn     # 指定注故障的链路
    python3 integration/closed_loop.py --simulate              # 链路时延模型, 免 root
"""
import argparse
import itertools
import os
import sys
import time

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from design2.infer import infer, link
from design3.plan import (Probe, localize, partition, partition_groups,
                          plan_partitioned, plan_stats, priority_key,
                          progressive)
from integration.srnet import EDGES, NODES, ModelHarness, NetPlan, build_mininet
from lib.mnlog import attach_file_log, detail, summary
from lib.common import section


def full_mesh(graph):
    """全互联基线: 每个节点对都探一次 (Pingmesh 的做法)."""
    out = []
    for u, v in itertools.combinations(graph.nodes(), 2):
        path = graph.shortest_path(u, v)
        out.append(Probe(u, v, tuple(path), graph.links_of(path)))
    return out


def print_plan_topology(plan, groups):
    """拓扑文字版 + 分区结果 (必须在任何测量之前打印)."""
    section('拓扑与分区 (测量之前)')
    summary('节点 (%d): %s' % (len(plan.nodes), ' '.join(plan.nodes)))
    summary('链路 (%d):' % len(plan.edges))
    row = []
    for u, v, ms in plan.edges:
        row.append('%s-%s(%gms)' % (u, v, ms))
        if len(row) == 4:
            summary('  ' + ', '.join(row))
            row = []
    if row:
        summary('  ' + ', '.join(row))
    summary('邻接:')
    for n in plan.nodes:
        summary('  %-4s -> %s' % (n, ', '.join('%s(%g)' % (m, plan.nbr[n][m])
                                              for m in plan.neighbors(n))))
    summary('探测端点主机 (%d): %s (探针地址在主机上, 路由器 SID 用 End.DX6 交付)'
            % (len(plan.nodes), ' '.join(plan.host[n] for n in plan.nodes)))
    summary('Design 3 分区 (%d 个): %s'
            % (len(groups), ' | '.join(','.join(grp) for grp in groups)))


def pairs_of_directed(lids):
    """有向链路 id ('u>v') -> 无向链路对 ('u|v'), 便于和 Design 3 的候选集比较."""
    return sorted({tuple(sorted(lid.split('>'))) for lid in lids})


def identifiability(observations, link_ids):
    """设计矩阵的秩, 以及"可唯一辨识"的链路集合.

    链路 l 能唯一反解 <=> 设计矩阵零空间里第 l 个分量恒为 0. 秩不够时, 环路上的
    链路只能确定到"整体平移"上 —— 这就是论文里 SID 对之间仍有 ECMP 歧义的线性
    代数形态, 需要 Design 2 的歧义解析或更多锚点来消掉.
    """
    idx = {l: i for i, l in enumerate(link_ids)}
    a = np.zeros((len(observations), len(link_ids)))
    for r, (_, segs) in enumerate(observations):
        for _, lid in segs:
            a[r, idx[lid]] = 1.0
    _, s, vt = np.linalg.svd(a, full_matrices=True)
    tol = max(a.shape) * (s[0] if len(s) else 0.0) * 1e-12
    rank = int((s > tol).sum())
    null = vt[rank:]
    loose = {link_ids[j] for j in range(len(link_ids))
             if null.size and np.abs(null[:, j]).max() > 1e-9}
    return rank, set(link_ids) - loose


def main():
    ap = argparse.ArgumentParser(description='Design 1+2+3 闭环诊断')
    ap.add_argument('--simulate', action='store_true',
                    help='用链路时延模型代替真实探测 (免 root, 可复现)')
    ap.add_argument('--fault', nargs=2, metavar=('U', 'V'), default=None,
                    help='注入故障的链路端点 (默认自动选被计划覆盖最多的一条)')
    ap.add_argument('--fault-ms', type=float, default=40.0, help='故障链路额外时延')
    ap.add_argument('--thresh', type=float, default=15.0,
                    help='异常阈值 E (ms): 路径相对基线、链路绝对时延都用它')
    ap.add_argument('--noise', type=float, default=0.1,
                    help='--simulate 下的测量噪声幅度 (ms)')
    ap.add_argument('--port', type=int, default=9999)
    ap.add_argument('--timeout', type=float, default=3.0, help='单次探测超时 (s)')
    ap.add_argument('--logdir', default=None,
                    help='响应端日志/出口表的目录 (默认 <仓库>/logs)')
    ap.add_argument('--log', default=None)
    args = ap.parse_args()
    if not args.simulate and os.geteuid() != 0:
        sys.exit('[FATAL] 真实拓扑需要 root: sudo python3 integration/closed_loop.py '
                 '(或用 --simulate 免 root 跑模型)')

    logdir = args.logdir or os.path.join(ROOT, 'logs')
    os.makedirs(logdir, exist_ok=True)
    lp = attach_file_log('closed_loop',
                         args.log or os.path.join(
                             logdir,
                             'closed_loop_%s.log' % time.strftime('%Y%m%d_%H%M%S')))
    if lp:
        summary('>>>>> log: %s' % lp)

    # ---- Design 3 的规划部分 (纯计算) ----
    plan = NetPlan(NODES, EDGES)
    graph = plan.graph()
    part = partition(graph)
    groups = partition_groups(part)
    probes = plan_partitioned(graph, plan.nodes, part)
    st = plan_stats(graph, plan.nodes, probes)
    mesh = full_mesh(graph)
    print_plan_topology(plan, groups)
    summary('[INFO] Design 3 Step 1: 计划 %d 条探测 (全互联 %d 条), 覆盖 %d/%d 条边'
            % (st['probes'], st['baseline'], st['covered'], st['edges']))
    if args.simulate:
        summary('[INFO] 模拟模式: 用链路时延模型代替真实探测 (免 root)')

    truth = plan.directed_delay()
    harness = None
    try:
        if args.simulate:
            harness = ModelHarness(plan, truth, noise=args.noise)
        else:
            harness = build_mininet(plan, port=args.port, timeout=args.timeout,
                                    logdir=logdir)
            harness.start_responders()

        # ---- 基线: 全互联 + Design 2 反解 ----
        section('基线阶段: 全互联探测 (Design 1) + 链路时延锚点 (Design 2)')
        summary('[INFO] 基线 %d 条探测 (每条 ~0.2 s, 预计 %.0f 分钟)'
                % (len(mesh), len(mesh) * 0.2 / 60.0))
        link_ids = sorted(truth)
        obs, base_ow, n_base = [], {}, 0
        for p in mesh:
            r = harness.probe(p.path)
            n_base += 1
            if r is None:
                summary('[WARN] 探测失败: %s -> %s' % (p.src, p.dst))
                continue
            base_ow[(p.src, p.dst)] = r[0]
            obs.append((r[0], [link(l) for l in plan.directed_links(p.path)]))
        if not obs:
            summary('[FAIL] 基线探测全部失败, 先看日志里的 probe 命令/输出, '
                    '以及 logs/responder_*.log')
            return 1
        links = infer(link_ids, obs)
        rank, ident = identifiability(obs, link_ids)
        errs = [abs(links[l] - truth[l]) for l in ident if links.get(l) is not None]
        summary('[RESULT] Design 2 基线: %d 条探测, 设计矩阵秩 %d/%d -> 可唯一辨识 %d 条'
                '链路, 平均偏差 %.3f ms, 最大 %.3f ms'
                % (len(obs), rank, len(link_ids), len(ident),
                   sum(errs) / len(errs) if errs else -1.0,
                   max(errs) if errs else -1.0))
        if len(ident) < len(link_ids):
            summary('[INFO] 其余 %d 条有向链路只能确定到"环路上的等量平移", 对应论文里'
                    ' SID 对之间仍有 ECMP 歧义: 需要更多锚点或 Design 2 的歧义解析'
                    % (len(link_ids) - len(ident)))
        detail('  ' + ', '.join('%s=%.2f(真值 %.2f)%s'
                                % (l, links[l], truth[l],
                                   '' if l in ident else '[不可唯一辨识]')
                                for l in link_ids if links.get(l) is not None))

        # ---- 健康诊断: 单独衡量"路径感知剪枝" (Step 2) 本身 ----
        section('健康诊断: Design 3 Step 2 渐进探测 (无故障)')

        def delta_of(p, r):
            """相对基线的超额时延; 探不到/没基线时返回 None (按异常处理, 不剪枝)."""
            base = base_ow.get((p.src, p.dst))
            return None if (r is None or base is None) else r[0] - base

        def probe_ok(p):
            d = delta_of(p, harness.probe(p.path))
            return d is not None and d <= args.thresh

        _, _, r_ok, n_ok = progressive(probes, probe_ok)
        summary('[RESULT] 渐进探测: 探测 %d/%d 条, %d 轮 '
                '(长路径正常 => 被它包含的短路径免探)'
                % (n_ok, len(probes), r_ok))

        # ---- 注入故障 (两端各 +fault_ms, 双向都变慢) ----
        if args.fault:
            fu, fv = args.fault
        else:
            cov = {}
            for p in probes:
                for lid in p.links:
                    cov[lid] = cov.get(lid, 0) + 1
            fu, fv = sorted(max(cov, key=lambda l: (cov[l], l)).split('|'))
            summary('[INFO] 未指定 --fault, 自动选被计划覆盖最多的链路 %s-%s (%d 条路径)'
                    % (fu, fv, cov['%s|%s' % (fu, fv)]))
        if fu not in plan.nbr or fv not in plan.nbr[fu]:
            summary('[FAIL] %s-%s 不是拓扑里的链路' % (fu, fv))
            return 1
        section('注入故障: 链路 %s-%s 两个方向各 +%g ms' % (fu, fv, args.fault_ms))
        base_ms = truth['%s>%s' % (fu, fv)]
        harness.set_link_delay(fu, fv, base_ms + args.fault_ms)
        truth['%s>%s' % (fu, fv)] = base_ms + args.fault_ms
        truth['%s>%s' % (fv, fu)] = base_ms + args.fault_ms
        fault_u = {'%s|%s' % tuple(sorted((fu, fv)))}
        cover = [p for p in probes if p.links & fault_u]
        summary('[INFO] 该链路被 %d/%d 条计划路径经过' % (len(cover), len(probes)))

        # ---- 诊断: Design 3 渐进探测 + Design 2 归因 ----
        section('诊断阶段: Design 3 渐进探测 (设计划 + 长路径优先)')
        d_obs = []                  # (相对基线的超额, 该路径的有向链路)
        trace = []

        def probe_fn(p):
            d = delta_of(p, harness.probe(p.path))
            if d is None:
                return False                  # 探不到按异常处理: 不剪枝, 保守
            d_obs.append((d, plan.directed_links(p.path)))
            return d <= args.thresh

        abnormal, normal, rounds, n_diag = progressive(probes, probe_fn, trace=trace)
        cand = localize(abnormal, normal)
        summary('[RESULT] Design 3 Step 2: 探测 %d/%d 条, %d 轮, 异常 %d 条, 正常 %d 条'
                % (n_diag, len(probes), rounds, len(abnormal), len(normal)))
        summary('[RESULT] 候选瓶颈链路 (异常路径交集 - 正常路径) = %s'
                % (sorted(cand) or '无'))
        for row in trace:
            detail('  [轮 %d] %s: %s' % row)

        # Design 2 只对"候选集合"反解超额时延: 基线与故障期是不同时刻, 不能混在一个
        # 最小二乘里; 候选之外的链路按"没变"处理 (稀疏故障假设).
        cand_d = sorted({l for c in cand
                         for l in ('%s>%s' % tuple(c.split('|')),
                                   '%s>%s' % tuple(reversed(c.split('|'))))})
        obs_r = []
        for delta, dl in d_obs:
            sub = [link(l) for l in dl if l in cand_d]
            if sub:
                obs_r.append((delta, sub))
        excess = infer(cand_d, obs_r) if (cand_d and obs_r) else {}
        # 只报"本轮观测真正覆盖到"的候选链路: infer 会对没方程的链路做均值兜底,
        # 那个值是猜的, 不能当证据.
        touched = sorted({lid for _, segs in obs_r for _, lid in segs})
        est = {l: excess[l] for l in touched if excess.get(l) is not None}
        delta_ms = truth['%s>%s' % (fu, fv)] - base_ms
        summary('[RESULT] Design 2 归因: 候选链路超额 = %s (真值 +%g ms, 阈值 %g ms)'
                % (', '.join('%s=%.2f' % (l, v) for l, v in sorted(est.items())) or '无',
                   delta_ms, args.thresh))
        pred_u = pairs_of_directed([l for l, v in est.items() if v > args.thresh])
        true_u = [tuple(sorted((fu, fv)))]
        summary('[RESULT] Design 2 诊断: 瓶颈链路 = %s, netem 真值 = %s, %s'
                % (sorted(pred_u), true_u,
                   '命中' if pred_u == true_u else '不一致'))
        if pred_u != true_u:
            summary('[INFO] 链路级反解受方程数限制, 以 Design 3 的候选集为准'
                    ' (可见性 != 可唯一反解)')

        # ---- Step 3: 跨切片故障优先 + 提前终止 ----
        section('诊断阶段: Design 3 Step 3 (跨切片故障优先 + 提前终止)')
        covered = set()

        def stop():
            return fault_u <= covered

        def probe3(p):
            d = delta_of(p, harness.probe(p.path))
            if d is None:
                covered.update(p.links & fault_u)
                return False
            ok = d <= args.thresh
            if not ok:
                covered.update(p.links & fault_u)
            return ok

        probed_links = set()
        for p in abnormal + normal:
            probed_links |= set(p.links)
        order = lambda p: (priority_key(p, set(cand), probed_links)
                           + (-len(p.links), p.src, p.dst))
        a3, n3, rounds3, n_pri = progressive(probes, probe3, order=order, stop=stop)
        summary('[RESULT] Step 3: 探测 %d 条, %d 轮, %s; 候选 = %s'
                % (n_pri, rounds3,
                   '故障链路全部可见 (提前终止)' if fault_u <= covered
                   else '仍有故障链路未覆盖',
                   sorted(localize(a3, n3)) or '无'))

        # ---- 端到端小结 ----
        section('端到端')
        summary('[RESULT] 探测数: 全互联 %d / 计划 %d / 健康诊断 %d / 故障诊断 %d / '
                '跨切片优先 %d'
                % (st['baseline'], st['probes'], n_ok, n_diag, n_pri))
        summary('[RESULT] 剪枝: 计划相对全互联 %.1f%%; 健康诊断 %.1f%%; '
                '故障诊断 %.1f%% (异常路径不剪枝)'
                % (100.0 * (1 - st['probes'] / float(st['baseline'])),
                   100.0 * (1 - n_ok / float(st['baseline'])),
                   100.0 * (1 - n_diag / float(st['baseline']))))
        summary('[RESULT] 故障定位: 候选 %s vs 真值 %s, %s'
                % (sorted(cand), [fu + '|' + fv],
                   '正确' if cand == fault_u else '未收敛到单条链路 (需结合 Design 2)'))
        return 0
    finally:
        if harness is not None:
            harness.close()


if __name__ == '__main__':
    sys.exit(main())
