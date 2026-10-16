#!/usr/bin/env python3
r"""mnlog.py -- 给 SRmesh@Mininet 脚本加日志落盘能力
================================================================

背景: Mininet 的 info()/output() 通过 logging.StreamHandler 输出到 stderr
(不是 stdout), 所以 `cmd | tee out.txt` 抓到的是空文件. 本模块给 Mininet 的
logger 挂一个 FileHandler, 让终端上看到的所有内容同时写进日志文件.

用法:

    from mnlog import attach_file_log
    logpath = attach_file_log('design1_demo')            # 自动命名到 logs/
    logpath = attach_file_log('design1_demo', '/tmp/x')  # 指定路径
"""
import os
import time
import logging
import sys


def attach_file_log(script, logfile=None):
    """给 Mininet 的 logger 挂 FileHandler, 返回日志文件路径."""
    try:
        from mininet.log import lg
    except Exception as e:  # pragma: no cover
        print('[mnlog] 无法导入 mininet.log: %s' % e)
        return None

    if logfile is None:
        d = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
        os.makedirs(d, exist_ok=True)
        logfile = os.path.join(
            d, '%s_%s.log' % (script, time.strftime('%Y%m%d_%H%M%S')))

    fh = logging.FileHandler(logfile, mode='w', encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(message)s'))
    fh.setLevel(logging.DEBUG)      # 由 logger 自身 level 过滤
    lg.addHandler(fh)
    lg._mnlog_file_handler = fh
    return logfile


def summary(message):
    """打印简洁的用户可见输出, 并写同一条到日志."""
    print(message, flush=True)
    handler = getattr(logging.getLogger("mininet"), "_mnlog_file_handler", None)
    if handler is not None:
        record = logging.LogRecord("mnlog", logging.INFO, __file__, 0, message, (), None)
        handler.handle(record)


def detail(message):
    """写详细输出到日志文件, 不打印到终端."""
    handler = getattr(logging.getLogger("mininet"), "_mnlog_file_handler", None)
    if handler is not None:
        record = logging.LogRecord("mnlog", logging.INFO, __file__, 0, message, (), None)
        handler.handle(record)
