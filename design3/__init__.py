#!/usr/bin/env python3
r"""design3 -- SRmesh Design 3 拓扑无关的渐进式诊断 (探测规划)
================================================================

    design3.plan   探测规划算法: 模块度分区 (式 (11) / Algorithm 2) + 渐进探测
                   (Algorithm 3) + 跨切片故障优先, 附内置自测
    design3.eval   合成拓扑上的三层剪枝离线评测 (对齐论文 Table III 的量级)

Design 3 是纯控制面算法, 不碰数据面: 输入拓扑与切片, 输出"探哪些节点对、按什么
顺序探"; 具体探测由 Design 1 执行, 链路级时延由 Design 2 反解.
"""
