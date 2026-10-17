#!/usr/bin/env python3
r"""lib -- SRmesh@Mininet 共享库
================================================================

    lib.common  Mininet / SRv6 共享工具 (Router / add6 / enable_seg6 / run_cmd / print_topology)
    lib.mnlog   日志落盘 (attach_file_log / summary / detail)

各实验脚本先把自己所在目录的上一级(仓库根)加入 sys.path, 再:

    from lib.common import Router, add6, enable_seg6, print_topology, run_cmd, section
    from lib.mnlog import attach_file_log, detail, summary
"""
