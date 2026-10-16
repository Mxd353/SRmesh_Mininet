# SRmesh @ Mininet -- Design 1: 确定性 SR 环回探测

在 **WSL2 + Mininet** 上复现 *SRmesh: Deterministic and Efficient Diagnosis of
Latency Bottleneck Links in SRv6 Networks*(ICNP 2025, CCF-B)的 **Design 1**:
确定性 SR 环回探测(deterministic SR loopback probing).

核心思想:探测包用 SRv6 把**双向路径都钉死**,从而把端到端 RTT 精确归因到指定路径.

## 机制

```
h1(发起) --正向 [r2_sid, r4_sid] 经 r2--► r4 -(End.DX6)-> h2(响应)
   ▲                                                      |
   +--反向 [r3_sid, r1_sid] 经 r3◄-- r1 ◄-(重建 SRH 回发)-+
```

1. **正向**:探测包用内核 `encap seg6` 走与生产流量同款的 SID 列表(探测 = 业务)
2. **反向列表藏 payload**:反向 SID 列表写进 payload,不占第二个 SRH(规避 MTU)
3. **响应端重建 SRH**:从 payload 取出反向列表,现场构造反向 SRH 原路回发
4. **结果**:正向经 r2,反向经 r3,双向独立钉死;实测正向 6ms,反向 42ms,RTT ~ 48ms

## 文件

| 文件 | 作用 |
| --- | --- |
| `design1_demo.py` | 编排:钻石拓扑 + SID 行为(End.X/End.DX6)+ 按模式启动探测/响应 |
| `design1_probe.py` | Design 1 的**发起端 + 用户态响应端**(3 个子命令,见下)|
| `design1_responder.bpf.c` | 内核态 TC eBPF 响应端(`bpf_skb_adjust_room` 扩包 + 构造 SRH + `bpf_redirect`)|
| `mnlog.py` | 日志落盘(Mininet 的 info 输出走 stderr,直接重定向会丢)|
| `common.py` | 共享 Mininet/SRv6 工具: `Router`, `add6`, `enable_seg6`, `run_cmd`, `section` |
| `design2.py` | Design 2 推断算法,以及作者实现的对照版本 |
| `design2_mininet.py` | Design 2 + Mininet:netem 真值,IPv6 ECMP 观测,SRv6 定向观测与推断 |
| `design2_oneway.py` | Design 2 单向 UDP 时间戳探测工具 |

### Design 1 的两条实现路径

`design1_probe.py` 承载发起端与**用户态**响应端,`design1_responder.bpf.c` 是**内核态**响应端.
`design1_demo.py` 按开关选择路径:

```
design1_demo.py --ebpf   ->  design1_responder.bpf.c(内核态响应)  +  design1_probe.py probe-raw(发起)
design1_demo.py (默认)   ->  design1_probe.py respond(用户态响应) +  design1_probe.py probe(发起)
```

`design1_probe.py` 的三个子命令:

| 子命令 | 角色 | 使用方 |
| --- | --- | --- |
| `probe-raw` | 发起端(协议 253 原始套接字)| `--ebpf` 模式 |
| `probe` | 发起端(UDP)| 默认(用户态)模式 |
| `respond` | 用户态响应端(AF_PACKET 重建反向 SRH)| 默认(用户态)模式 |

> 用户态路径(`probe` + `respond`)不依赖 eBPF 工具链(无需 bpftool/clang),
> 可独立验证"反向列表藏 payload + 重建 SRH"机制;内核态路径(`probe-raw` +
> eBPF)是论文的最终方案.

## 运行

```bash
# 用户态响应端
sudo python3 design1_demo.py --capture

# 内核态 eBPF 响应端(需 bpftool + libbpf-dev + clang)
sudo python3 design1_demo.py --ebpf --capture

# Design 2:Mininet + ECMP + netem 真值
sudo python3 design2_mininet.py --test
```

`--ebpf` 会**自动**:读取 MAC/ifindex 生成 `design1_responder_cfg.h` -> clang 编译 ->
`tc filter add` 挂到 `h2-eth0` ingress.

## 环境

- WSL2, kernel 6.18,内核内置 SRv6(`IPV6_SEG6_LWTUNNEL=y` / `NET_CLS_BPF=y`)
- Mininet 2.3.0,iproute2 6.19,clang 21,bpftool 7.7

## 关键坑(复现必读)

1. 地址要 `nodad`,否则停在 `tentative`,IPv6 通信全废
2. `seg6_enabled=1`,否则内核**静默丢弃**收到的 SRv6 包
3. 端点 SID 用专用 node SID + `seg6local End.DX6`(不要拿接口链路地址当 SID)
4. eBPF:`bpf_skb_adjust_room` 之后要**在每次迭代内做显式边界检查**,verifier 才可证
5. eBPF 读 payload 的 magic 用 `bpf_ntohl()`(探测端是大端 `!I` 打包)
