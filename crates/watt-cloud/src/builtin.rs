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

impl AccelerateCatalog {
    /// 注入内置分组（按分组 Id 去重：已存在则不重复注入，云端数据优先）。
    pub fn with_builtins(mut self) -> Self {
        if !self
            .groups
            .iter()
            .any(|g| g.id == GOOGLE_TRANSLATE_GROUP_ID)
        {
            self.groups.push(google_translate_group());
            // 注入的分组 order 与云端混排，统一按 order 排序保持展示顺序稳定
            self.groups.sort_by_key(|g| g.order);
        }
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
}
