#!/usr/bin/env python3
r"""design2 -- SRmesh Design 2 基于时延的多路径推断
================================================================

    design2.infer               推断算法 (论文式 1-4 + Algorithm 1), 附自测
    design2.oneway              单向 UDP 时间戳探测工具 (由端到端脚本以子进程调用)
    design2.single_mininet      端到端: 单 ECMP 点
    design2.ambiguous_mininet   端到端: 两个 ECMP 点串联 (4 种路径组合)
    design2.states_mininet      端到端: 三个 ECMP 点, 覆盖 A/B/C/D 四种分支状态
"""
