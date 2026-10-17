# SRmesh @ Mininet

在 **WSL2 + Mininet** 上复现论文 *SRmesh: Deterministic and Efficient Diagnosis of
Latency Bottleneck Links in SRv6 Networks*（**ICNP 2025, CCF-B**）的核心设计。
全部跑在真实 Linux 数据面上（内核 SRv6 / IPv6 ECMP / netem），不依赖模拟器；
算法在本仓**独立实现**，不复用作者源码。

复现内容分两部分：

- **Design 1 — 确定性 SR 环回探测**：用 SRv6 把探测包的**正向和反向路径都钉死**，
  把一个包的端到端 RTT 精确归因到指定路径。
- **Design 2 — 基于时延的多路径推断**：SR 的 SID 之间仍有 ECMP 歧义，用少量端到端
  观测反解每条链路的时延，定位瓶颈。

---

## 目录结构

| 文件 | 作用 |
| --- | --- |
| `common.py` | 共享 Mininet/SRv6 工具：`Router`、`add6`、`enable_seg6`、`run_cmd`、`section`、`print_topology` |
| `mnlog.py` | 日志落盘（Mininet 的 info 输出走 stderr，直接重定向会丢） |
| `design1_demo.py` | Design 1 编排：钻石拓扑 + SID 行为（End.X/End.DX6）+ 按模式启动探测/响应 |
| `design1_probe.py` | Design 1 的**发起端 + 用户态响应端**（3 个子命令，见下） |
| `design1_responder.bpf.c` | Design 1 的**内核态** TC eBPF 响应端（`bpf_skb_adjust_room` 扩包 + 构造 SRH + `bpf_redirect`） |
| `design2.py` | Design 2 推断算法（论文式 1–4 + Algorithm 1），附内置自测与合成场景评估 |
| `design2_mininet.py` | Design 2 端到端：单 ECMP 点，netem 真值 + IPv6 ECMP 观测 + SRv6 定向观测 |
| `design2_ambiguous_mininet.py` | Design 2 端到端：两个 ECMP 点串联，理论 4 种路径组合 |
| `design2_states_mininet.py` | Design 2 端到端：三个 ECMP 点，一次运行覆盖 A/B/C/D 四种分支状态 |
| `design2_oneway.py` | 单向 UDP 时间戳探测工具（避免 ping RTT/2 被非对称回程污染） |

运行产物：`logs/` 存放每次 Mininet 脚本的完整日志；`design1_responder.bpf.o` 与
`design1_responder_cfg.h` 是 `--ebpf` 模式的编译/生成物（均已被 `.gitignore` 忽略）。

---

## Design 1：确定性 SR 环回探测

核心思想：探测包用 SRv6 把**正向和反向路径都注好 SID**，让一个探测包只走一条
确定路径，从而把 RTT 精确归因到该路径。

```
h1(发起) --正向 [r2_sid, r4_sid] 经 r2--► r4 -(End.DX6)-> h2(响应)
   ▲                                                      |
   +--反向 [r3_sid, r1_sid] 经 r3◄-- r1 ◄-(重建 SRH 回发)-+
```

1. **正向**：探测包用内核 `encap seg6` 走与生产流量同款的 SID 列表（探测 = 业务）。
2. **反向列表藏 payload**：反向 SID 列表写进 payload，不占第二个 SRH（规避 MTU）。
3. **响应端重建 SRH**：从 payload 取出反向列表，现场构造反向 SRH 原路回发。
4. **结果**：正向经 r2、反向经 r3，双向独立钉死。钻石拓扑各链路时延为正向
   1+2+2+1 = 6 ms、反向 1+20+20+1 = 42 ms，故 RTT 约 48 ms——两个方向被可测量地
   区分开。

### 两条实现路径

`design1_probe.py` 承载发起端与**用户态**响应端，`design1_responder.bpf.c` 是
**内核态**响应端。`design1_demo.py` 按开关选择路径：

```
design1_demo.py --ebpf   ->  design1_responder.bpf.c (内核态响应) + design1_probe.py probe-raw(发起)
design1_demo.py (默认)   ->  design1_probe.py respond (用户态响应) + design1_probe.py probe (发起)
```

`design1_probe.py` 的三个子命令：

| 子命令 | 角色 | 使用方 |
| --- | --- | --- |
| `probe-raw` | 发起端（协议 253 原始套接字） | `--ebpf` 模式 |
| `probe` | 发起端（UDP） | 默认（用户态）模式 |
| `respond` | 用户态响应端（AF_PACKET 重建反向 SRH） | 默认（用户态）模式 |

> 用户态路径（`probe` + `respond`）不依赖 eBPF 工具链（无需 bpftool/clang），
> 可独立验证「反向列表藏 payload + 重建 SRH」机制；内核态路径（`probe-raw` +
> eBPF）是论文的最终方案。

### payload 线格式

用户态与 eBPF 共用同一线格式（24 字节头 + 16×n），magic `0x53526D31`（"SRm1"），
网络字节序（探测端 `!I` 打包，eBPF 端用 `bpf_ntohl()` 读取）：

```
magic(4) probe_id(4) seq(4) tx_ns(8) rev_cnt(1) pad(3) [rev_sid(16)]*n
```

---

## Design 2：基于时延的多路径推断

SR 把路径钉到 SID 粒度，但 SID 对之间仍有 ECMP。观测到端到端时延 d，却不知道
内部走了哪条分支，就无法把 d 拆到具体链路、定位瓶颈。Design 2 把「走了哪条分支」
当作未知量，用少量观测反解链路时延。

### 数据模型（`design2.py`）

- **链路**：字符串 id（如 `x1`）。
- **观测**：`Observation(delay, segments)`，`segments` 每项为：
  - `('link', id)`：确定经过链路 id；
  - `('choice', [[ids], [ids], ...])`：歧义段，走其中一个分支。

### 算法阶段（`infer`）

1. **确定性消元**：对纯 `link` 观测（含已解析分支）做 NNLS，解出锚点链路时延。
2. **歧义解析**：对含 `choice` 的观测枚举所有分支组合，选误差最小者；若次优误差与
   最优之差不超过 `epsilon`（歧义阈值）则跳过。单未知链路可直接反解。
3. **迭代**：以上两步交替，直到不再变化。
4. **均值兜底**：仍未知的链路取已知链路均值。

### Mininet 端到端验证

- `design2_mininet.py`：拓扑 `S--M--Q--T`，r1→h2 按 flow hash 做 ECMP（直连 x2 或
  绕行 x3+x4）。确定性链路观测用点到点 ping 的 RTT/2；歧义观测用单向 UDP 时间戳，
  并用不同源地址触发不同 ECMP 分支。
- `design2_ambiguous_mininet.py`：两个 ECMP 点串联，h1→h2 理论 2×2 = 4 种路径组合，
  用 32 个单向样本聚成代表时延喂给推断算法。
- `design2_states_mininet.py`：链式三个 ECMP 点，锚点配置各不相同，一次运行同时覆盖
  Phase 2 的四种分支状态。

> 输入**只**包含测量值，不把样本的真实分支标签泄漏给算法：歧义观测统一表示为同一
> 条 `choice` 约束，分支归属完全由推断算法反解。

### Phase 2 分支状态（`infer(trace=...)`）

对一条含 ECMP 歧义的观测，Phase 2 对每个候选分支算 `(known_sum, unk, residual, err)`，
取 `err` 最小者；若次优与最优之差 ≤ `epsilon` 判为不可辨识。`infer` 的 `trace`
参数记录每次解析落在哪一类：

| 分支状态 | 判据 | 是否产生新信息 |
| --- | --- | --- |
| A 全已知 | `unk = 0` | 否，幂等空转（仅确认分支归属） |
| C 单未知 | `unk = 1` | 是，反解该链路 = residual |
| D 多未知 | `unk ≥ 2` | 部分，只能给“和”，不落具体链路 |
| B 两分支都无锚点 | 次优 err − 最优 err ≤ `epsilon` | 否，不可辨识，跳过 |

`design2_states_mininet.py` 三个 ECMP 点的锚点配置分别对应 A+C、D、B，一次运行即可
全部命中（终端与日志会打印覆盖报告）。

---

## 运行

```bash
# --- Design 1 ---
sudo python3 design1_demo.py --capture          # 用户态响应端
sudo python3 design1_demo.py --ebpf --capture   # 内核态 eBPF 响应端（需 bpftool + libbpf-dev + clang）

# --- Design 2 ---
python3 design2.py                              # 算法自测 + 合成场景（无需 root）
sudo python3 design2_mininet.py --test          # 单 ECMP 点：Mininet + netem 真值
sudo python3 design2_ambiguous_mininet.py --test # 两个 ECMP 点（4 种路径组合）
sudo python3 design2_states_mininet.py --test   # 三个 ECMP 点：覆盖 A/B/C/D 四种分支状态
```

`design1_demo.py --ebpf` 会**自动**：读取 MAC/ifindex 生成 `design1_responder_cfg.h`
→ clang 编译 → `tc filter add` 挂到 `h2-eth0` ingress。所有 Mininet 脚本都会把终端
输出同时写入 `logs/<脚本名>_<时间戳>.log`，并在**开始测量前**打印一份文字拓扑
（`print_topology`：节点清单 + 链路表 + 邻接表）：

```
sudo python3 design2_states_mininet.py --test
# 终端: == 拓扑 == 节点/链路/邻接表
```

---

## 结果

### 算法层自测（`python3 design2.py`，确定性、可复现）

| 场景 | MAE | 瓶颈定位 |
| --- | ---: | --- |
| 论文数值例子（无噪） | 0.00 | 检出 x2 |
| 菱形 ECMP（歧义指向瓶颈） | 1.25 | 检出 AT |
| 菱形 ECMP + 噪声 | 2.00 | 检出 AT |

内置自测：论文数值例子全部正确；歧义反解正确（观测偏离锚点 → 反解未知分支）；
不可辨识场景按预期走均值兜底（推断 5，真值 7，属设计内偏差）。

### Mininet 端到端（`logs/` 实测）

**单 ECMP 点**：MAE 0.069–0.119 ms；瓶颈 x2 正确检出。SRv6 定向观测实测
40.2–40.4 ms（理论 40 ms）。

**两个 ECMP 点**：9 条链路全部推断到真值附近，MAE ≈ 0.10 ms；瓶颈 x2 检出
（x6 = 20 ms 处于阈值边缘，属阈值选择问题）。

**分支状态覆盖**（`design2_states_mininet.py`）：一次运行命中 A/B/C/D 全部四种；
其中只有 C 会反解出未锚定链路（x3），D/B 信息不足，按设计走均值兜底。

> 说明：Mininet 场景里每条链路都有确定性观测直接测出，端到端 ECMP 样本主要用于
> **一致性校验**（验证歧义观测与已解链路自洽），而非在完全盲的条件下定位瓶颈。

---

## 环境

- WSL2，kernel 6.18，内核内置 SRv6（`IPV6_SEG6_LWTUNNEL=y` / `NET_CLS_BPF=y`）
- Mininet 2.3.0、iproute2 6.19、Python 3.14（`numpy` 2.4）、clang 21、bpftool 7.7
- 用户态路径与 `design2.py` 仅需 Python 标准库 + numpy

---

## 关键坑（复现必读）

1. 地址要 `nodad`，否则停在 `tentative`，IPv6 通信全废。
2. `seg6_enabled=1`，否则内核**静默丢弃**收到的 SRv6 包。
3. 端点 SID 用专用 node SID + `seg6local End.DX6`（不要拿接口链路地址当 SID）。
4. eBPF：`bpf_skb_adjust_room` 之后要**在每次迭代内做显式边界检查**，verifier 才可
   证；变长索引要用掩码夹进常量范围。
5. eBPF 读 payload 的 magic 用 `bpf_ntohl()`（探测端是大端 `!I` 打包）。
6. WSL2 上 `ping6 -F`（flow label）常无 `IPV6_FLOWLABEL_MGR` 权限，改用**多源地址**
   触发不同 ECMP hash。
7. 用 `ping` 的 RTT/2 做单向估计会被非对称回程污染，歧义观测改用
   `design2_oneway.py` 的单向时间戳。

---

## 已知局限

- WSL2 的 IPv6 ECMP hash 分布不均：两个 ECMP 点场景实测只出现 4 种组合中的 2 种
  （两个 ECMP 点倾向于同时选直连或同时选绕行），另外 2 种组合未被观测到。
- 端到端脚本仍依赖逐链路确定性观测；纯粹「只用端到端观测」的盲推断有待进一步验证。
- Design 1 的 eBPF 响应端仅支持最多 8 段（`MAX_SIDS`），且需外部注入 MAC/ifindex 配置。
