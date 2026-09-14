//! 云端加速项目：API 客户端 + DTO → 领域模型转换 + 本地缓存。
//!
//! 对齐原 .NET `ProxyService.InitializeAccelerateAsync()`：
//! `IMicroServiceClient.Instance.Accelerate.All()` → 分组列表 → 本地缓存 → 勾选状态恢复。
//!
//! 云端返回 **索引键 JSON**（MessagePack 契约式序列化）：
//! ```json
//! {"🦓":[{"0":"Steam 服务","1":[{...}],"2":"<GUID>","3":true,"4":1}],"🦄":200,"🐴":null}
//! ```
//! - 包装层：`🦓`=Content、`🦄`=Code、`🐴`=Message（服务端属性名混淆）
//! - 分组：`0`=Name、`1`=Items、`2`=Id、`3`=Show、`4`=Order
//! - 项目：`0`=Name、`1`=Port、`2`=MatchDomainNames、`3`=ForwardDomainNames（转发目标域名）、
//!   `4`=IPAddress、`5`=FakeServerName（SNI 覆盖）、`ProxyType`、`7`=ListenDomainNames、
//!   `8`=Checked、`9`=Id、`10`=Order、`11`=FakeUserAgent、`12`=Items（子规则，结构递归）
//!
//! 字段语义经 `ReverseProxyHttpClientHandler.GetIPEndPointsAsync()` 交叉确认：
//! `IPAddress` 直连 IP → `ForwardDestination` 解析该镜像域名取 IP（Host/SNI 仍为原始域名）。

pub mod builtin;
pub mod cache;
pub mod client;
pub mod dto;
pub mod model;

pub use cache::{load_cached, save_cached, CACHE_FILE_NAME};
pub use client::{AccelerateClient, CloudError, DEFAULT_API_BASE};
pub use model::{AccelerateProject, AccelerateProjectGroup};
