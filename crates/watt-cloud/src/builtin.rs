//! 内置加速分组：云端目录之外的本地补充。
//!
//! # 背景
//!
//! 原版 Watt Toolkit 的「Google 翻译」分组来自云端微服务；本项目云端目录
//! （`api.steampp.net/api/Accelerate/All`）当前不含该分组。为对齐原版功能，
//! 在目录加载后本地注入内置分组。
//!
//! # Google 翻译加速原理（对齐原版）
//!
//! Google 翻译服务在国内的可达路径是其部署于国内的边缘节点
//! （`203.208.0.0/16` Google China 段，与 `google.cn` 同源），这些节点对
//! `translate.googleapis.com` 等域名提供完整 TLS 服务（证书有效）。
//! 因此规则为「域名 → 覆盖 IP」，出站候选链中还叠加 `fallback.rs` 的
//! Google 翻译备用 IP 池竞速兜底。
//!
//! # Figma 加速原理（2026-10 实测选型）
//!
//! Figma 各域分处不同 AWS 基础设施，但均可由「域名 → 覆盖 IP」直达：
//! - `www.figma.com` / `static.figma.com` / `cdn.figma.com` 位于 CloudFront
//!   （`99.86.x` / `18.65.x` 任播段），任意边缘 IP 均可凭 SNI + Host 出具有
//!   效证书并路由到对应分发；
//! - `api.figma.com` 位于 AWS Global Accelerator（`13.35.190.x` 任播段，
//!   实测亦可经 CloudFront 边缘 IP 访问）；
//! - `s3-alpha-sig.figma.com`（预览图）位于 AWS S3（`65.8.76.35`，
//!   实测同样可经 CloudFront 边缘 IP 访问）。
//!
//! 因此每个加速项各自携带覆盖 IP，出站候选链再叠加 `fallback.rs` 的 Figma 备用 IP 池竞速兜底（个别 CloudFront 任播 IP 不可达时自动跳过）。
//!
//! **注意**：不得向监听域名写入裸 `figma.com`——`help.figma.com` 等营销/帮助
//! 子域不在 CloudFront 上，经边缘 IP 访问会因证书 SNI 不匹配而 TLS 失败。
//!
//! 分组/项目 Id 为固定 GUID：保证勾选状态持久化键跨版本稳定；
//! 注入时按 Id 去重，云端将来若提供同名分组则优先采用云端数据。

use super::model::{AccelerateCatalog, AccelerateProject, AccelerateProjectGroup};
use watt_config::{DomainRule, DomainRuleFields};

/// 内置「Google 翻译」分组 Id（固定 GUID，持久化键）
pub const GOOGLE_TRANSLATE_GROUP_ID: &str = "e5a1c7b0-4f2d-4c6a-9b3e-8d7f6a5c4b3a";

/// Google 翻译服务的国内边缘节点首选 IP（Google China 段）。
/// 2026-09 实测：`120.253.253.34/.98/.226` 对三个 translate 域名均提供
/// 全证书验证通过的 TLS 服务；其余候选进 `watt-core::fallback` 备用池竞速兜底。
const GOOGLE_TRANSLATE_EDGE_IP: &str = "120.253.253.34";

/// 内置「Google 翻译」分组（translate.google.com / translate.googleapis.com /
/// translate.gstatic.com 三个加速项，对齐原版域名清单）
pub fn google_translate_group() -> AccelerateProjectGroup {
    let item = |id: &str, name: &str, domain: &str, order: i32| AccelerateProject {
        id: id.to_string(),
        name: name.to_string(),
        order,
        port: 443,
        default_checked: false,
        server_side: false,
        rule: DomainRule {
            match_domain_names: vec![domain.to_string()],
            listening_domain_names: vec![domain.to_string()],
            order,
            fields: DomainRuleFields {
                ip_address: Some(GOOGLE_TRANSLATE_EDGE_IP.parse().expect("合法 IP")),
                ..Default::default()
            },
        },
        items: Vec::new(),
    };

    AccelerateProjectGroup {
        id: GOOGLE_TRANSLATE_GROUP_ID.to_string(),
        name: "Google 翻译".to_string(),
        order: 9,
        show: true,
        items: vec![
            item(
                "b2c3d4e5-6f7a-4b8c-9d0e-1f2a3b4c5d6e",
                "Google 翻译",
                "translate.google.com",
                1,
            ),
            item(
                "c3d4e5f6-7a8b-4c9d-0e1f-2a3b4c5d6e7f",
                "Google 翻译 API",
                "translate.googleapis.com",
                2,
            ),
            item(
                "d4e5f6a7-8b9c-4d0e-1f2a-3b4c5d6e7f8a",
                "Google 翻译静态资源",
                "translate.gstatic.com",
                3,
            ),
        ],
    }
}

/// 内置「Figma」分组 Id（固定 GUID，持久化键）
pub const FIGMA_GROUP_ID: &str = "d155261c-1e3c-4318-b2c9-e8bd060eada7";

/// Figma 各加速项的覆盖 IP（2026-10 实测：TLS 全证书验证通过 + HTTP 可达）。
/// 覆盖 IP 仅作为出站候选链首选项，失效时由 DNS 与 `fallback.rs` 备用池接力。
const FIGMA_WEB_IP: &str = "99.86.18.30"; // CloudFront（www.figma.com）
const FIGMA_API_IP: &str = "13.35.190.56"; // AWS Global Accelerator（api.figma.com）
const FIGMA_THUMBNAIL_IP: &str = "65.8.76.35"; // AWS S3（s3-alpha-sig.figma.com）
const FIGMA_STATIC_IP: &str = "18.65.14.118"; // CloudFront（static.figma.com）
const FIGMA_CDN_IP: &str = "18.65.14.71"; // CloudFront（cdn.figma.com）

/// 内置「Figma」分组（主站 / API / 预览图 / 静态资源 / CDN 五个加速项）。
/// 不包含裸 `figma.com` 与 help/status 等营销子域（非 CloudFront 后端，
/// 经覆盖 IP 访问证书不匹配），原因见模块文档。
pub fn figma_group() -> AccelerateProjectGroup {
    let item = |id: &str, name: &str, domain: &str, ip: &str, order: i32| AccelerateProject {
        id: id.to_string(),
        name: name.to_string(),
        order,
        port: 443,
        default_checked: false,
        server_side: false,
        rule: DomainRule {
            match_domain_names: vec![domain.to_string()],
            listening_domain_names: vec![domain.to_string()],
            order,
            fields: DomainRuleFields {
                ip_address: Some(ip.parse().expect("合法 IP")),
                ..Default::default()
            },
        },
        items: Vec::new(),
    };

    AccelerateProjectGroup {
        id: FIGMA_GROUP_ID.to_string(),
        name: "Figma".to_string(),
        order: 17,
        show: true,
        items: vec![
            item(
                "2bde16db-255f-45a9-a6d6-1bbb1a9028b5",
                "Figma 主站",
                "www.figma.com",
                FIGMA_WEB_IP,
                1,
            ),
            item(
                "a58cf439-2e66-44a9-9285-19d2322feb6f",
                "Figma API",
                "api.figma.com",
                FIGMA_API_IP,
                2,
            ),
            item(
                "729fb99f-5a05-4bc7-8f4c-48cc97237e54",
                "Figma 预览图",
                "s3-alpha-sig.figma.com",
                FIGMA_THUMBNAIL_IP,
                3,
            ),
            item(
                "efabd9a4-b129-469b-81af-39f316144c30",
                "Figma 静态资源",
                "static.figma.com",
                FIGMA_STATIC_IP,
                4,
            ),
            item(
                "eaa643da-d8d9-4585-bb34-b91345ddc7fa",
                "Figma CDN",
                "cdn.figma.com",
                FIGMA_CDN_IP,
                5,
            ),
        ],
    }
}

impl AccelerateCatalog {
    /// 注入内置分组（按分组 Id 逐个去重：已存在则不重复注入，云端数据优先）。
    pub fn with_builtins(mut self) -> Self {
        for group in [google_translate_group(), figma_group()] {
            if !self.groups.iter().any(|g| g.id == group.id) {
                self.groups.push(group);
            }
        }
        // 注入的分组 order 与云端混排，统一按 order 排序保持展示顺序稳定
        self.groups.sort_by_key(|g| g.order);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{AccelerateProjectGroupDto, ApiRsp};

    fn catalog_with_cloud() -> AccelerateCatalog {
        let json = include_str!("../tests/fixtures/accelerate_all.json");
        let rsp: ApiRsp<Vec<AccelerateProjectGroupDto>> = serde_json::from_str(json).unwrap();
        let groups = rsp
            .content
            .unwrap()
            .iter()
            .filter_map(AccelerateProjectGroup::from_dto)
            .collect();
        AccelerateCatalog::new(groups)
    }

    #[test]
    fn test_builtin_group_injected() {
        let c = catalog_with_cloud().with_builtins();
        let g = c
            .groups
            .iter()
            .find(|g| g.id == GOOGLE_TRANSLATE_GROUP_ID)
            .expect("应注入 Google 翻译分组");
        assert_eq!(g.name, "Google 翻译");
        assert_eq!(g.items.len(), 3);
        for item in &g.items {
            assert_eq!(
                item.rule.fields.ip_address.map(|i| i.to_string()),
                Some(GOOGLE_TRANSLATE_EDGE_IP.to_string())
            );
            // 勾选持久化键非空（对齐云端 GUID 语义）
            assert!(!item.id.is_empty());
        }
        // API 域名在匹配列表中
        assert!(g.items[1]
            .rule
            .match_domain_names
            .contains(&"translate.googleapis.com".to_string()));
    }

    #[test]
    fn test_builtin_injection_is_idempotent() {
        let once = catalog_with_cloud().with_builtins();
        let twice = once.clone().with_builtins();
        assert_eq!(once.groups.len(), twice.groups.len());
        assert_eq!(
            twice
                .groups
                .iter()
                .filter(|g| g.id == GOOGLE_TRANSLATE_GROUP_ID)
                .count(),
            1
        );
    }

    #[test]
    fn test_builtin_group_flattens_to_rules() {
        let c = catalog_with_cloud().with_builtins();
        let g = c
            .groups
            .iter()
            .find(|g| g.id == GOOGLE_TRANSLATE_GROUP_ID)
            .unwrap();
        let ids: Vec<String> = g.items.iter().map(|i| i.id.clone()).collect();
        let rules = c.to_domain_rules(Some(&ids));
        assert_eq!(rules.len(), 3);
        assert!(rules
            .iter()
            .any(|r| r.match_domain_names.contains(&"translate.gstatic.com".to_string())));
    }

    #[test]
    fn test_groups_sorted_by_order_after_injection() {
        let c = catalog_with_cloud().with_builtins();
        let orders: Vec<i32> = c.groups.iter().map(|g| g.order).collect();
        let mut sorted = orders.clone();
        sorted.sort();
        assert_eq!(orders, sorted);
    }

    #[test]
    fn test_figma_group_injected() {
        let c = catalog_with_cloud().with_builtins();
        let g = c
            .groups
            .iter()
            .find(|g| g.id == FIGMA_GROUP_ID)
            .expect("应注入 Figma 分组");
        assert_eq!(g.name, "Figma");
        assert_eq!(g.items.len(), 5);
        // 默认不勾选（用户主动启用，对齐 Google 翻译内置分组语义）
        for item in &g.items {
            assert!(!item.default_checked);
            assert!(!item.server_side);
            assert_eq!(item.port, 443);
        }
        // 用户点名的两个核心域必须在列
        let domains: Vec<&str> = g
            .items
            .iter()
            .flat_map(|i| i.rule.match_domain_names.iter().map(String::as_str))
            .collect();
        assert!(domains.contains(&"www.figma.com"));
        assert!(domains.contains(&"api.figma.com"));
        // 覆盖 IP 各就各位（CloudFront / Global Accelerator / S3）
        let ip_of = |domain: &str| {
            g.items
                .iter()
                .find(|i| i.rule.match_domain_names.contains(&domain.to_string()))
                .and_then(|i| i.rule.fields.ip_address.map(|ip| ip.to_string()))
        };
        assert_eq!(ip_of("www.figma.com").as_deref(), Some("99.86.18.30"));
        assert_eq!(ip_of("api.figma.com").as_deref(), Some("13.35.190.56"));
        assert_eq!(
            ip_of("s3-alpha-sig.figma.com").as_deref(),
            Some("65.8.76.35")
        );
        // 不得写入裸 figma.com（help/friends 等非 CF 子域会因证书不匹配 TLS 失败）
        assert!(!domains.contains(&"figma.com"));
    }

    #[test]
    fn test_figma_injection_is_idempotent() {
        let once = catalog_with_cloud().with_builtins();
        let twice = once.clone().with_builtins();
        assert_eq!(once.groups.len(), twice.groups.len());
        assert_eq!(
            twice
                .groups
                .iter()
                .filter(|g| g.id == FIGMA_GROUP_ID)
                .count(),
            1,
        );
        // Google 翻译分组不受影响
        assert_eq!(
            twice
                .groups
                .iter()
                .filter(|g| g.id == GOOGLE_TRANSLATE_GROUP_ID)
                .count(),
            1,
        );
    }

    #[test]
    fn test_figma_group_flattens_to_rules() {
        let c = catalog_with_cloud().with_builtins();
        let g = c
            .groups
            .iter()
            .find(|g| g.id == FIGMA_GROUP_ID)
            .unwrap();
        let ids: Vec<String> = g.items.iter().map(|i| i.id.clone()).collect();
        let rules = c.to_domain_rules(Some(&ids));
        assert_eq!(rules.len(), 5);
        // 未勾选任何 Figma 项 → 无 Figma 规则
        assert!(c
            .to_domain_rules(Some(&[]))
            .iter()
            .all(|r| !r.match_domain_names.iter().any(|d| d.ends_with("figma.com"))));
    }
}
