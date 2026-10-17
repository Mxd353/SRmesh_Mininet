#!/usr/bin/env python3
r"""integration -- Design 1 + 2 + 3 的闭环集成
================================================================

    integration.srnet        8 节点 SRv6 网元: 拓扑 / SID 规划 / 探测器 (真实 + 模型)
    integration.closed_loop  闭环编排: 基线锚定 -> 注入故障 -> 渐进探测 -> 归因

真实运行需要 root (Mininet + tc netem); closed_loop.py --simulate 用链路时延模型
代替探测, 免 root 且完全可复现, 用来验证闭环逻辑本身.
"""
