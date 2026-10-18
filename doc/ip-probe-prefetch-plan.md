# IP 池探测排序（启动预择优）技术规划

> 状态：P0/P1/P2 已全部实施并验证（2026-10-18）
> 关联代码：`crates/watt-core/src/outbound.rs`、`fallback.rs`、`connect_test.rs`、`engine.rs`

## 1. 背景与需求

用户反馈：「一键加速后似乎会一个 IP 一个地去尝试能否连接成功，希望点击一键加速时自动把 IP 池 ping 一下、根据连接时长排序、然后择优尝试代理。」

拆解为三个诉求：
1. **提前探测**：启动时（而非首个请求时）掌握各候选 IP 的可用性与延迟；
2. **量化排序**：按「连接时长」对候选排序，而非盲赛；
3. **择优代理**：让最快的候选优先承载流量。

## 2. 现状核实（代码事实，全部已验证）

| 环节 | 现状 | 位置 |
|---|---|---|
| 候选地址解析 | 覆盖 IP → 转发目标域名 → 原始 host DNS → 备用 IP 池，去重合并为单一列表 | `outbound.rs:443` `resolve_candidates` |
| 竞速机制 | **已是并发竞速**：`JoinSet` 同时跑全部候选的「TCP + TLS 握手」，首个完成 TLS 者胜出，胜出后 abort 落败者 | `outbound.rs:358` `race_tls_once` |
| 降权机制 | 竞速胜出但请求失败的 IP 降权 60s；健康候选全灭才尝试降权候选 | `outbound.rs:138-176` `CandidateHealth` |
| 备用 IP 池 | 静态表：Google 翻译段、Figma 全系、Microsoft 服务等 | `fallback.rs:111` `fallback_ips` |
| 现成探测能力 | `probe_https`（系统解析 + 系统根证书 + GET /）、`probe_https_all`（并发） | `connect_test.rs:146/244` |
| 引擎启动入口 | `ProxyEngine::start(config)`，config.rules 含勾选项目的域名与覆盖 IP | `engine.rs:272` |

**结论：候选之间已经是并发竞速，不是串行逐个尝试。** 用户感知的「逐个试」来自三个真实缺口：

1. **首请求盲赛**：每个新域名的第一次访问都是「无先验」竞速——若候选集体不可达，要等满超时才报错；若处于「TLS 可达但 HTTP 死亡」的抖动窗口（实测 github.com 11 候选中 4 个此类），请求层才失败重试；
2. **无量化数据**：竞速只回答「谁先连上」，不回答「谁一贯最快」——本次最快的候选下次仍与最慢的候选同权参赛；
3. **覆盖 IP 单候选盲连**：云端静态覆盖 IP 可能已失效，首次访问要等它失败才能被 DNS/fallback 候选接替。

## 3. 关键决策：不用 ICMP ping，改用同层握手探测

用户原话是「ping 一下」。**建议放弃 ICMP ping，改用 TCP + TLS 握手 RTT**——这才是用户要的「连接时长」的正确度量。三个理由：

| 问题 | 说明 |
|---|---|
| **特权门槛** | macOS raw socket 需 root/entitlement；Windows 需 `IcmpSendEcho` FFI；跨平台实现与签名成本高（Tauri 默认无 App Sandbox 也不够，需单独处理） |
| **禁 ping 普遍** | GitHub / Google / Steam CDN 大部分禁用 ICMP。ping 不通的 IP 往往 TLS 完全可用——按 ping 排序等于**误杀可用候选** |
| **判据不一致**（本项目铁律） | TCP 握手成功 ≠ 服务可用（实测 github.com 12 候选 11 个 TCP 秒连但 TLS 全卡）；同理 **ping 成功 ≠ HTTPS 可用**。用 ICMP 延迟排序 = 用无关指标排序，竞速胜出条件必须与可用性判据一致 |

**探测深度定为 TCP connect + TLS 握手（带 SNI、系统根证书验证），不发 HTTP 请求**：
- 与 `race_tls_once` 的胜出判据**完全同层**（探测通过的 IP = 竞速必然可通过的 IP）；
- 探测开销 ≈ 一次完整 TLS 握手（~20-50ms/候选），不打上游业务接口、不计入流量统计。

## 4. 方案设计

### 4.1 数据流总览

```
点击一键加速
   └─ ProxyEngine::start() 完成（监听就绪、hosts/系统代理接入）
        └─ spawn 后台探测任务（不阻塞启动）
             ├─ 域名清单 ← config.rules（勾选项目的全部域名）
             ├─ 候选全集 ← resolve_candidates()（覆盖 IP + forward DNS + host DNS + fallback 池）
             ├─ 逐候选：TCP+TLS 握手，记录 rtt_ms（失败记 None）
             └─ 写入 ProbeCache（内存，TTL 5min）
                      │
  浏览器请求 ──► race_tls_once(addrs)
                      ├─ ProbeCache 排序：非降权优先 → rtt 升序 → 未探测沉底
                      ├─ CandidateHealth 分区（现有机制不动）
                      └─ JoinSet 并发竞速（现有机制不动，只改传入顺序）
```

### 4.2 组件：`ProbeCache`（新，`crates/watt-core/src/probe_cache.rs`）

```rust
pub struct ProbeCache {
    // key: (host, ip) → (rtt_ms, 探测时间)
    entries: Mutex<HashMap<(String, IpAddr), ProbeEntry>>,
}
pub struct ProbeEntry { pub rtt_ms: u64, pub at: Instant }
```

- 挂在 `OutboundConnector` 上（与 `CandidateHealth` 同位置，`outbound.rs:181` 附近），`None` = 不探测（隧道/测试场景）；
- TTL 5 分钟，过期条目读取时视为未探测；
- 容量上限 4096 条，`retain` 时顺带清过期。

### 4.3 排序分（与健康度融合的纯函数）

```rust
/// 竞速候选排序：健康优先（由 CandidateHealth.partition 保证）→ 探测 RTT 升序 → 未探测沉底
pub fn sort_by_probe(addrs: &mut Vec<SocketAddr>, cache: &ProbeCache, host: &str) {
    addrs.sort_by_key(|a| {
        cache.get(host, a.ip())
            .map(|e| e.rtt_ms as i64)      // 已探测：按 RTT
            .unwrap_or(i64::MAX)           // 未探测：沉底（仍参赛，不丢候选）
    });
}
```

- **纯函数 + 单元测试**（Windows 上直接跑，对齐 netparse 模式）；
- 降权候选由 `CandidateHealth::partition` 沉底，本排序只在健康区内排先后；
- 并发竞速语义不变（正确性不依赖顺序），排序的收益见 4.5。

### 4.4 探测器（新，`crates/watt-core/src/probe.rs`）

```rust
/// 对指定 host 的单个候选 IP 做 TCP+TLS 握手探测（与 race_tls 同层判据）
pub async fn probe_candidate(host: &str, addr: SocketAddr, timeout: Duration) -> Option<u64>;

/// 批量探测：有界并发（信号量 32）、逐候选超时 3s、整体预算 8s
pub async fn probe_host_candidates(host: &str, addrs: &[SocketAddr]) -> Vec<(IpAddr, Option<u64>)>;
```

实现要点：
- 复用 `OutboundConnector::tls_parts()` 拿 connector + SNI name，保证与竞速同一 TLS 配置；
- 只握手、不发应用数据；握手成功即记 RTT（含 TCP+TLS 全链路）；
- 探测地址不经过 `resolve_candidates` 的系统 DNS（必须指定 IP），因此是 `connect_test::probe_https` 之外的新函数，但证书验证逻辑可参考其 `build_tls_config`；
- **候选上限保护**：每域名最多探测前 16 个候选（fallback 池通常 3-12 个，DNS 通常 1-4 个，16 足够覆盖且防异常大列表）。

### 4.5 与竞速的融合点（改一处）

`outbound.rs` 中 `race_tls`（`:336`）入口处，`partition` 之后、`race_tls_once` 之前：

```rust
let (mut healthy, demoted) = self.health.partition(addrs);   // 现有
self.probe.sort_by(&target.host, &mut healthy);              // 新增一行
```

**并发竞速保留不动**，排序带来三项收益：
1. **最快候选最先 spawn**：并发下连接建立的先后确定性强，首个 TLS 完成者大概率就是全局最快者；
2. **可选 top-K 裁剪**（P2，默认关）：只放 RTT 最优的 K=4 个候选参赛，12 个候选的握手资源开销降为 1/3；被裁候选在 top-K 全灭时经现有「降级路径」补入；
3. **可观测**：探测结果可直接展示给用户（见 4.6）。

### 4.6 触发时机

| 时机 | 行为 | 说明 |
|---|---|---|
| `start()` 成功 | spawn 后台全量探测 | 一键加速点击 → 引擎就绪即开始，**不阻塞启动路径**（spawn + JoinHandle 存 engine，`stop()` 时 abort） |
| 周期刷新（P2） | 每 60s 重探 TTL 过期条目 | 与 `DEMOTE_SECS=60` 对齐；网络切换（Wi-Fi→蜂窝）后 1 分钟内自愈 |
| 落盘缓存（P2） | `probe-cache.json` 随设置目录 | 重启后热启动，首请求即有排序（探测是进程重启后重新做的，落盘只是锦上添花，默认关） |

### 4.7 前端展示（P1，让用户「看见择优」）

| 位置 | 内容 | i18n |
|---|---|---|
| 加速页启动按钮区 | 探测中：「正在探测网络节点…」；完成：「已择优 N/M 个节点，最快 Xms」 | `accel.probe.running` / `accel.probe.done` |
| 引擎状态徽标（侧栏） | 运行中显示当前域名最快候选 RTT（可选） | — |

实现：后端经现有 `watt://engine-state-changed` 事件通道或新 `watt://probe-finished` 事件推送探测摘要；前端 `proxy` store 接收。

### 4.8 分期与工作量

| 期 | 内容 | 工作量 | 风险 |
|---|---|---|---|
| **P0** | `probe_cache.rs` + `probe.rs` + `race_tls` 排序融合 + start 后台探测（纯函数单测 + diag 集成测试） | 1.5 天 | 低（不改竞速正确性，探测 best-effort） |
| **P1** | 前端探测状态展示 + 五语文案 | 1 天 | 低 |
| **P2** | 周期刷新 + 落盘缓存 + top-K 裁剪（默认关） | 0.5 天 | 中（top-K 有裁掉慢但可用候选的理论风险，靠降级路径兜底） |

## 5. 风险与边界

| 风险 | 缓解 |
|---|---|
| 探测流量被上游视为扫描（每域名 12-16 次 443 握手） | 信号量限并发 32 + 候选间 10-50ms 抖动；只探勾选项目域名（通常 5-20 个），总量 <300 握手/次，且与正常加速流量同目标 |
| 探测结果时效性（网络切换后 RTT 失真） | TTL 5min + 周期刷新 60s + `CandidateHealth` 仍以真实请求失败为准降权（探测只影响顺序，不决定可用性） |
| 探测与真实请求判据漂移 | 探测复用 `tls_parts()` 同一 TLS 配置与 SNI；探测通过的 IP 竞速必然可通过 |
| 探测拖慢启动 | 后台任务 + `JoinHandle` 存 engine；`start()` 路径零等待；探测中 `stop()` 即 abort |
| 全探测失败（如断网） | `ProbeEntry` 为 None → 排序沉底但仍在场 → **行为与现状完全一致**（退化安全） |
| 上游证书链差异 | 探测用系统根证书（与 `connect_test` 一致）；证书验证失败的候选记 None 沉底，不会误杀——因为竞速同样会失败 |

## 6. 验收清单

**单元测试（Windows 可跑）**
- [ ] `sort_by_probe`：RTT 升序 / 未探测沉底 / 空 cache 原序不变 / TTL 过期视为未探测
- [ ] `probe_cache`：TTL 过期清理 / 容量上限 / 并发读写无 panic

**集成测试（`crates/watt-core/tests/diag_probe.rs`，`--ignored`）**
- [ ] 对 github.com 全候选探测：输出「IP → TCP/TLS/RTT」排序表
- [ ] 排序后首位候选经 `race_tls` 胜出（首即最快）
- [ ] 探测全部失败时竞速行为与不开启探测一致

**真机验收（Windows + Mac）**
- [ ] 一键加速后：探测在引擎就绪后 8s 预算内完成，启动按钮无卡顿
- [ ] 加速页显示「已择优 N/M，最快 Xms」
- [ ] 断网场景启动：探测快速失败（≤8s），引擎正常启动，请求行为同改造前
- [ ] 对比改造前后**首个请求延迟**（重点域名：github.com、translate.google.com、figma.com）

## 7. 对需求原文的回应

| 用户诉求 | 落地方式 |
|---|---|
| 「一个 IP 一个地去尝试」 | 澄清：现状已是并发竞速；痛点在首请求盲赛 + 无量化排序，由启动预探测解决 |
| 「ping 一下」 | 升级为同层 TCP+TLS 握手 RTT（ICMP 有特权、禁 ping、判据不一致三宗罪，见 §3） |
| 「根据连接时常排序」 | `sort_by_probe`：RTT 升序 + 健康度优先 + 未探测沉底 |
| 「择优尝试代理」 | 排序传入 `race_tls`，最快候选优先 spawn；P2 可选 top-K 只放最优者参赛 |
