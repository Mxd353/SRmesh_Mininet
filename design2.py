#!/usr/bin/env python3
r"""design2.py -- SRmesh Design 2 基于时延的多路径推断
================================================================

SR 把路径钉到 SID 粒度, 但 SID 对之间仍有 ECMP. 观测到端到端时延 d, 却不知道
内部走了哪条分支, 无法把 d 拆到具体链路, 定位瓶颈.

本模块把走了哪条分支当作未知量, 用少量观测反解链路时延. 对应论文式 (1)-(4)
与 Algorithm 1 (确定性消元 -> 阈值聚类 -> 迭代 -> 均值兜底).

数据模型:

    - 链路: 字符串 id (如 'x1').
    - 观测: Observation(delay, segments).
        segments 是列表, 每项为:
          ('link', id)                      -- 确定经过链路 id.
          ('choice', [ [ids], [ids], ... ]) -- 歧义段, 走其中一个分支.

用法:

    from design2 import infer
    links = infer(link_ids, observations, epsilon=10.0)
"""
import numpy as np


# ---- nnls ----
def nnls(A, b, max_iter=None, tol=1e-12):
    """非负最小二乘 min ||Ax - b||_2, s.t. x >= 0 (Lawson-Hanson).

    论文代码用 scipy.optimize.nnls; 这里用 numpy 手写等价实现, 避免依赖 scipy.
    """
    A = np.asarray(A, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64).reshape(-1)
    m, n = A.shape
    if max_iter is None:
        max_iter = 3 * n

    x = np.zeros(n)
    P = np.zeros(n, dtype=bool)      # passive set (x > 0)
    R = np.ones(n, dtype=bool)       # active set (x == 0)
    w = A.T @ (b - A @ x)            # 对偶变量

    for _ in range(max_iter):
        if not R.any():
            break
        j = int(np.argmax(np.where(R, w, -np.inf)))
        if w[j] <= tol:
            break
        P[j] = True
        R[j] = False
        while True:
            Pidx = np.where(P)[0]
            s = np.zeros(n)
            if Pidx.size:
                s[Pidx] = np.linalg.lstsq(A[:, Pidx], b, rcond=None)[0]
            if Pidx.size == 0 or np.all(s[Pidx] > tol):
                x = s
                break
            # 找到会导致 s 变负的系数, 步进 alpha 使 x 保持非负
            neg = Pidx[s[Pidx] <= tol]
            alpha = (x[neg] / (x[neg] - s[neg])).min()
            x = x + alpha * (s - x)
            remove = np.where(P & (x <= tol))[0]
            P[remove] = False
            R[remove] = True
        w = A.T @ (b - A @ x)
    return x


# ---- 数据模型 ----
def link(lid):
    """确定经过的链路."""
    return ('link', lid)


def choice(branches):
    """歧义段, branches 是若干分支(每个分支是链路 id 列表)."""
    return ('choice', [list(b) for b in branches])


def expand(segments):
    """展开一条观测的所有可能路径组合 -> list of (链路 id 列表)."""
    combos = [[]]
    for kind, val in segments:
        if kind == 'link':
            for c in combos:
                c.append(val)
        else:  # choice
            combos = [c + list(b) for c in combos for b in val]
    return combos


# ---- 推断 ----
def infer(link_ids, observations, epsilon=10.0, max_iters=30):
    """推断每条链路的时延.

    link_ids:      所有链路的 id 列表
    observations:  [(delay, segments), ...]
    epsilon:       歧义分支的可区分阈值 (论文建议取网络时延经验标准差)
    max_iters:     消元/解析的迭代上限

    返回 dict: link_id -> 时延
    """
    links = {lid: None for lid in link_ids}
    resolved = []          # 已解析出分支的确定路径 (delay, [ids])
    resolved_keys = set()

    for _ in range(max_iters):
        changed = False

        # ---- Phase 1: 确定性观测 -> nnls (论文: 代数消元拿锚点) ----
        det = [(d, [l for _, l in segs]) for d, segs in observations
               if all(k == 'link' for k, _ in segs)]
        det += resolved

        rows, rhs = [], []
        for d, lids in det:
            known = sum(links[l] for l in lids if links[l] is not None)
            unk = [l for l in lids if links[l] is None]
            if unk:                       # 只保留含未知链路的行
                rows.append(unk)
                rhs.append(d - known)
        if rows:
            unks = sorted({l for r in rows for l in r})
            A = np.zeros((len(rows), len(unks)))
            b = np.zeros(len(rows))
            for i, r in enumerate(rows):
                for l in r:
                    A[i, unks.index(l)] = 1.0
                b[i] = rhs[i]
            x = nnls(A, b)
            for l, xi in zip(unks, x):
                if links[l] is None or abs(links[l] - xi) > 1e-9:
                    links[l] = float(xi)
                    changed = True

        # ---- Phase 2: 歧义解析 (选误差最小的分支; 单未知链路可反解) ----
        for d, segs in observations:
            if not any(k == 'choice' for k, _ in segs):
                continue
            combos = expand(segs)
            scored = []
            for combo in combos:
                known_sum = sum(links[l] for l in combo if links[l] is not None)
                unk = [l for l in combo if links[l] is None]
                residual = d - known_sum
                if len(unk) == 0:
                    err = abs(residual)                        # 分支已知, 预测误差
                elif len(unk) == 1:
                    err = 0.0 if residual >= 0 else abs(residual)  # 单未知, 可完美解释
                else:
                    err = abs(residual)                        # 多未知, 欠定近似
                scored.append((err, combo, unk, residual))
            scored.sort(key=lambda x: x[0])
            best_err, combo, unk, residual = scored[0]
            # 唯一性: 次优误差需比最优明显更大(> epsilon)
            if len(scored) > 1 and scored[1][0] - best_err <= epsilon:
                continue
            if len(unk) == 1 and residual >= 0:
                l = unk[0]
                if links[l] is None or abs(links[l] - residual) > 1e-9:
                    links[l] = float(residual)
                    changed = True
            elif len(unk) == 0:
                key = (d, tuple(sorted(combo)))
                if key not in resolved_keys:
                    resolved.append((d, list(combo)))
                    resolved_keys.add(key)
                    changed = True

        if not changed:
            break

    # ---- 兜底: 仍未知的链路取已知链路均值 ----
    vals = [v for v in links.values() if v is not None]
    default = float(np.mean(vals)) if vals else 0.0
    for l in links:
        if links[l] is None:
            links[l] = default
    return links


# ---- 作者算法 ----
def author_infer(observations, epsilon=10.0):
    """复现作者 greedy_grouped_inference (目标 = 最少异常链路, 工程版).

    与论文式(1) 的差异: 求解用 nnls(非代数消元), 目标 = abnormal*100 +
    very_high*200 + error(非最小化总绝对偏差), epsilon 硬编码(此处参数化).

    注意: 作者原始代码初始化 link_delays = zeros, 未先用确定性约束解出锚点,
    导致首轮迭代 estimates 全 0, 无法区分 ECMP 分支, delay 较小的歧义观测被
    错误解析. 这里修复为先用确定性约束求解锚点, 使对照聚焦于目标函数本身.
    """
    constraints = [{'paths': expand(segs), 'delay': d} for d, segs in observations]
    deterministic = []
    uncertain = []
    for c in constraints:
        if len(c['paths']) == 1:
            c['selected'] = 0
            deterministic.append(c)
        else:
            uncertain.append(c)

    all_links = sorted({l for c in constraints for p in c['paths'] for l in p})
    link_index = {l: i for i, l in enumerate(all_links)}
    n = len(all_links)

    def solve(det):
        if not det:
            return np.zeros(n)
        A = np.zeros((len(det), n))
        b = np.zeros(len(det))
        for i, c in enumerate(det):
            for l in c['paths'][c['selected']]:
                A[i, link_index[l]] = 1
            b[i] = c['delay']
        return nnls(A, b)

    # 修复: 先用确定性约束解出锚点, 而非作者原版的 zeros 初始化
    link_delays = solve(deterministic)

    updated = True
    while updated:
        updated = False
        new_det = []
        for c in uncertain:
            if 'selected' in c:
                continue
            estimates = [sum(link_delays[link_index[l]] for l in p) for p in c['paths']]
            groups = []
            for idx, val in enumerate(estimates):
                placed = False
                for g in groups:
                    if abs(val - g['rep']) <= epsilon:
                        g['indices'].append(idx)
                        g['rep'] = np.mean([estimates[i] for i in g['indices']])
                        placed = True
                        break
                if not placed:
                    groups.append({'indices': [idx], 'rep': val})
            best_group, best_score = None, float('inf')
            for g in groups:
                error = abs(c['delay'] - g['rep'])
                if error <= epsilon * 2:
                    test_path = c['paths'][g['indices'][0]]
                    temp = deterministic + [{'paths': [test_path], 'delay': c['delay'], 'selected': 0}]
                    x = solve(temp)
                    pos = x[x > 0]
                    avg = float(np.mean(pos)) if pos.size else 10.0
                    thr = max(avg * 2, 30.0)
                    score = float(np.sum(x > thr)) * 100.0 + float(np.sum(x > 100.0)) * 200.0 + error
                    if score < best_score:
                        best_score, best_group = score, g
            if best_group is not None:
                c['selected'] = best_group['indices'][0]
                updated = True
                new_det.append(c)
            else:
                mine = min(groups, key=lambda g: abs(c['delay'] - g['rep']))
                if abs(c['delay'] - mine['rep']) <= epsilon * 3:
                    c['selected'] = mine['indices'][0]
                    updated = True
                    new_det.append(c)
        if new_det:
            deterministic.extend(new_det)
            link_delays = solve(deterministic)

    for c in uncertain:
        if 'selected' in c:
            continue
        estimates = [sum(link_delays[link_index[l]] for l in p) for p in c['paths']]
        mean_val = float(np.mean(estimates))
        if abs(c['delay'] - mean_val) <= epsilon:
            c['selected'] = int(min(range(len(estimates)), key=lambda i: abs(estimates[i] - mean_val)))
        else:
            c['selected'] = int(min(range(len(estimates)), key=lambda i: abs(estimates[i] - c['delay'])))

    link_delays = solve(constraints)
    return {l: float(link_delays[link_index[l]]) for l in all_links}


# ---- 对照实验 ----
def _mae(links, truth):
    return float(np.mean([abs(links[l] - truth[l]) for l in truth]))


def _section(title):
    print("\n== %s ==" % title)


def _bottleneck_report(links, truth, threshold=50.0):
    """按真值判定瓶颈链路, 看两算法是否检出/误报."""
    gt = {l for l, v in truth.items() if v > threshold}
    pred = {l for l, v in links.items() if v > threshold}
    tp = gt & pred
    fn = gt - pred
    fp = pred - gt
    return '检出 %s 漏检 %s 误报 %s' % (
        ('OK' + str(sorted(tp))) if tp else '无',
        ('X' + str(sorted(fn))) if fn else '无',
        ('X' + str(sorted(fp))) if fp else '无')


def compare():
    """同一组观测, 对照两个算法的链路推断与瓶颈定位."""
    TH = 50.0
    scenarios = [
        # (名称, 链路列表, 真值, 观测, 瓶颈链路)
        ('论文例子(无噪)', ['x1', 'x2', 'x3', 'x4', 'x5'],
         {'x1': 5, 'x2': 80, 'x3': 4, 'x4': 2, 'x5': 5},
         [(5,  [link('x1')]), (5, [link('x5')]), (80, [link('x2')]),
          (4,  [link('x3')]), (2, [link('x4')]),
          (80, [choice([['x2'], ['x3', 'x4']])]),
          (90, [link('x1'), choice([['x2'], ['x3', 'x4']]), link('x5')])],
         ['x2']),

        ('菱形ECMP(歧义指瓶颈)', ['SA', 'AT', 'SB', 'BT'],
         {'SA': 5, 'AT': 100, 'SB': 5, 'BT': 5},
         [(5,   [link('SA')]), (5, [link('SB')]), (5, [link('BT')]),
          (110, [choice([['SA', 'AT'], ['SB', 'BT']])]),   # 走了 A
          (10,  [choice([['SA', 'AT'], ['SB', 'BT']])])],  # 走了 B
         ['AT']),

        ('菱形ECMP+噪声', ['SA', 'AT', 'SB', 'BT'],
         {'SA': 5, 'AT': 100, 'SB': 5, 'BT': 5},
         [(5.3, [link('SA')]), (4.7, [link('SB')]), (5.1, [link('BT')]),
          (98.0, [choice([['SA', 'AT'], ['SB', 'BT']])]),
          (12.0, [choice([['SA', 'AT'], ['SB', 'BT']])]),
          (103.0, [choice([['SA', 'AT'], ['SB', 'BT']])])],
         ['AT']),
    ]

    for name, link_ids, truth, obs, bn in scenarios:
        mine = infer(link_ids, obs, epsilon=10.0)
        author = author_infer(obs, epsilon=10.0)
        _section(name)
        print('  真值瓶颈: %s' % bn)
        for l in link_ids:
            print('  %-4s 真值=%5.1f  |  论文式(我)=%6.2f  |  作者(最少异常)=%6.2f'
                  % (l, truth[l], mine[l], author[l]))
        print('  论文式 MAE=%.2f  瓶颈[%s]' % (_mae(mine, truth), _bottleneck_report(mine, truth, TH)))
        print('  作者式 MAE=%.2f  瓶颈[%s]' % (_mae(author, truth), _bottleneck_report(author, truth, TH)))


# ---- 测试 ----
def _report(links, truth):
    ok = True
    for l, t in truth.items():
        v = links.get(l)
        err = abs(v - t) if v is not None else float('inf')
        flag = 'OK' if err < 1e-6 else 'X'
        if flag != 'OK':
            ok = False
        print('  %-4s 真值=%5.1f  推断=%s  %s' % (l, t, ('%5.2f' % v) if v is not None else 'None', flag))
    return ok


def test_paper_example():
    """论文数值例子: S --x1-- M =={x2 | x3+x4}== Q --x5-- T"""
    _section('论文数值例子')
    truth = {'x1': 5, 'x2': 30, 'x3': 4, 'x4': 2, 'x5': 5}
    obs = [
        (5,  [link('x1')]),                                     # P1 S->M
        (5,  [link('x5')]),                                     # P2 Q->T
        (30, [link('x2')]),                                     # P3 M->Q (SR 定向直连)
        (4,  [link('x3')]),                                     # P4 M->R
        (2,  [link('x4')]),                                     # P5 R->Q
        (30, [choice([[ 'x2'], ['x3', 'x4']])]),                # P6 M->Q (ECMP)
        (16, [link('x1'), choice([['x2'], ['x3', 'x4']]), link('x5')]),  # P7 S->T (ECMP)
    ]
    links = infer(list(truth.keys()), obs, epsilon=10.0)
    print('  (确定性 P1-P5 直接解出, P6/P7 解析出分支归属)')
    print('  结果: ' + '全部正确' if _report(links, truth) else '  结果: 有偏差')


def test_disambiguation():
    """歧义反解: 观测值偏离已知分支 -> 推断走了未知分支并反解其值"""
    _section('歧义反解 (观测 8 偏离锚点 x=5 -> 走 y, y=8)')
    truth = {'x': 5, 'y': 8}
    obs = [
        (5, [link('x')]),                        # 锚点 x=5
        (8, [choice([['x'], ['y']])]),           # 观测 8 -> 走 y -> y=8
    ]
    links = infer(['x', 'y'], obs, epsilon=1.0)
    _report(links, truth)


def test_unidentifiable():
    """不可辨识: 观测值无法区分分支 -> 兜底(均值), 有偏差"""
    _section('不可辨识 (观测 5 对 x=5 / y=7 都一致 -> 兜底)')
    truth = {'x': 5, 'y': 7}
    obs = [
        (5, [link('x')]),
        (5, [choice([['x'], ['y']])]),           # 观测 5, 走 x 或 y 都"合理"
    ]
    links = infer(['x', 'y'], obs, epsilon=1.0)
    for l, t in truth.items():
        print('  %-4s 真值=%5.1f  推断=%5.2f' % (l, t, links[l]))
    print('  (y 不可辨识 -> 兜底取均值 5, 不等于真值 7, 属预期)')


if __name__ == '__main__':
    test_paper_example()
    test_disambiguation()
    test_unidentifiable()
    compare()
