# 社区 GitHub Hosts 源：备选 IP 池的额外候选

> 记录日期：2026-11-13
> 数据源：`https://hosts.gitcdn.top/hosts.json`（社区维护，默认源）
> 落点：`crates/watt-core/src/community_hosts.rs` / `src-tauri/src/commands/community_hosts.rs` / `ui/src/views/IpPoolPage.vue`

---

## 1. 它是什么

社区维护的 GitHub hosts 清单，格式为二维数组，**IP 在前、域名在后**：

```json
[["140.82.112.25","alive.github.com"],["20.6.7.17","github.com"],["185.199.111.133","raw.githubusercontent.com"]]
```

内容随社区更新（GitHub 各子域的入口 IP 会变），因此**不能编译期内置**，必须运行期拉取。
这正好补上 [`crates/watt-core/src/fallback.rs`](../crates/watt-core/src/fallback.rs) 的短板：
那里的静态池是手写常量，只在发版时更新。

## 2. 数据流

```
拉取 hosts.json ──► 解析 [[ip,host]] ──► 过滤保留地址/非法域名
                                              │
                                              ▼
                            本地探测（TCP + TLS 握手，按 SNI 校验证书）
                                              │
                                     通过的 IP 按 RTT 排序
                                              │
                                              ▼
                        ip_pool::add_dynamic_ips（并集，每域名最多 4 个，池上限 8）
                                              │
                                              ▼
                          outbound::resolve_candidates 竞速候选之一
```

## 3. 三条硬约束

### 3.1 绝不写 hosts 文件

社区源是第三方数据。写进 hosts 等于把域名解析权交给它，且 hosts 条目优先于一切
DNS——一旦源里出现恶意条目，用户所有 GitHub 流量都会被导向指定 IP，且**没有二次校验**。

本项目只把它当 IP 候选，不碰 hosts。最坏情况是一个无效候选被竞速丢弃。

### 3.2 必须本地探测

`ip_pool::probe_ip` 走完整 TLS 握手并按 SNI 校验证书。因此即使源被投毒
（`github.com → 攻击者 IP`），证书校验必然失败而被丢弃。

**这是本模块唯一的信任边界，不能为省时间跳过。** 实测数据：37 条中 21 条通过。

### 3.3 只补不删

合并走 `ip_pool::add_dynamic_ips`（并集），不是 `set_entry`（替换）。
后者是「DNS 刷新结果」的语义，两者混用会互相清空对方的结果。

## 4. 调度

不用常驻 sleep 到点，而是**每 30 分钟醒一次判断是否到期**：

| 项 | 值 | 说明 |
|---|---|---|
| 检查周期 | 30 分钟 | 用户把间隔改成 1 小时也能及时生效 |
| 默认间隔 | 24 小时 | 社区源一天更新数次，更频繁只增加探测开销 |
| `interval_hours = 0` | 仅手动 | 关闭定期拉取但保留「立即拉取」按钮 |
| 失败退避 | 1 小时 | 不可达网络下不该每 30 分钟刷一次日志 |
| 启动延迟 | 20 秒 | 避开 CA 生成 / 迁移 / 池加载的启动高峰 |

## 5. 配置

`{AppData}/Settings/CommunityHosts.json`（独立文件，与 `IpPool.json` / `UpdateSettings.json` 同级）：

```json
{
  "enabled": true,
  "url": "https://hosts.gitcdn.top/hosts.json",
  "intervalHours": 24,
  "lastFetchMs": 1794541878283,
  "lastError": null
}
```

`lastFetchMs` / `lastError` 由后端维护，**前端保存时不会回传**——前端手里可能是几分钟前的
快照，覆盖会把后台刚写入的结果冲掉。

判定「是否到期」用 `lastFetchMs` 而非文件 mtime：备份还原会篡改 mtime 导致误判。

## 6. 失败语义

拉取 / 解析 / 探测失败**不影响任何既有功能**：池里原有候选照常工作。
失败原因写进 `lastError`，IP 池页用 `a-alert` 展示，不弹窗、不阻断启动。

上游 URL 可改为任一兼容格式的地址（自建镜像），但强制 HTTPS——明文源可被中间人
替换内容，虽然后续探测会过滤掉不可达 IP，但没必要给它这个机会。仅本机回环允许 http
（便于本地测试）。

## 7. 前端入口

IP 池页（备选 IP 池）底部新增「社区 GitHub Hosts 源」卡片：开关、源地址、间隔、
保存、立即拉取、上次更新时刻、失败原因。

拉取成功后同时刷新 `pool.load()`——社区源可能引入池里原本没有的域名（如
`alive.github.com`），需要立即出现在域名列表里。

## 8. 验证

```bash
# 单元测试：解析容错（顺序颠倒 / 对象格式 / 脏数据 / URL 冒充域名）
cargo test -p watt-core community_hosts

# 命令层：URL 校验与到期判断
cargo test -p watt-toolkit-app community_hosts

# 真实链路（需网络）：拉取 → 探测 → 入池
cargo test -p watt-core --test diag_community_hosts -- --ignored --nocapture
```

2026-11-13 实测：37 条解析 → 37 条可用 → 21 条通过 TLS 探测 → 21 个域名入池，
`github.com` 得到 `20.6.7.17`（不同于静态池的 `140.82.112.3`，说明源确实在更新）。
