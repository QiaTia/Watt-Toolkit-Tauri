//! 领域模型：云端 DTO → 加速项目树（UI 三态勾选）→ 引擎 `DomainRule`。
//!
//! 勾选状态：云端 `Checked` 提供默认值，用户勾选以 Id 集合持久化于
//! `ProxySettings.enabled_accelerate_ids`（对齐旧版 `SupportProxyServicesStatus`）。
//! 本地无勾选记录时回退云端默认值（旧版语义：未显式关闭即启用）。

use crate::dto::{split_semicolon, AccelerateProjectDto, AccelerateProjectGroupDto, ProxyType};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use watt_config::domain_rule::url_patterns_to_regex;
use watt_config::{DomainRule, DomainRuleFields, SubRule};

/// 加速项目分组（UI 列表顶层）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccelerateProjectGroup {
    /// 分组 Id（GUID）
    pub id: String,
    /// 分组名
    pub name: String,
    /// 排序
    pub order: i32,
    /// 是否在列表中默认展开/展示（云端控制）
    pub show: bool,
    /// 项目列表
    pub items: Vec<AccelerateProject>,
}

/// 加速项目（可递归包含按 URL 匹配的子项目）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccelerateProject {
    /// 项目 Id（GUID，勾选状态持久化键）
    pub id: String,
    /// 显示名
    pub name: String,
    /// 排序
    pub order: i32,
    /// 监听端口（云端固定 443）
    pub port: u16,
    /// 云端默认勾选
    pub default_checked: bool,
    /// 服务端加速（ProxyType == 4，需 ServerSideProxyToken）
    pub server_side: bool,
    /// 自身规则（不含子规则）
    pub rule: DomainRule,
    /// 子项目（按 URL 模式匹配，命中后覆盖父规则字段）
    pub items: Vec<AccelerateProject>,
}

/// 加速项目目录（分组集合）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccelerateCatalog {
    pub groups: Vec<AccelerateProjectGroup>,
}

impl AccelerateCatalog {
    pub fn new(groups: Vec<AccelerateProjectGroup>) -> Self {
        Self { groups }
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// 项目总数（含子项目）
    pub fn project_count(&self) -> usize {
        self.groups
            .iter()
            .flat_map(|g| g.items.iter())
            .map(count_projects)
            .sum()
    }

    /// 云端默认启用 Id 集合（`Checked == true` 的项目及其祖先链）
    pub fn default_enabled_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        for group in &self.groups {
            for item in &group.items {
                collect_checked(item, &mut ids);
            }
        }
        ids
    }

    /// 展平为引擎规则：按启用 Id 集合过滤父项目与子项目。
    /// `enabled` 为 `None` 时使用云端默认值（首次运行语义）。
    pub fn to_domain_rules(&self, enabled: Option<&[String]>) -> Vec<DomainRule> {
        let set: Option<HashSet<&str>> =
            enabled.map(|ids| ids.iter().map(String::as_str).collect());
        let mut rules = Vec::new();
        for group in &self.groups {
            for item in &group.items {
                if let Some(rule) = build_rule(item, set.as_ref()) {
                    rules.push(rule);
                }
            }
        }
        rules
    }
}

/// 递归统计项目数
fn count_projects(project: &AccelerateProject) -> usize {
    1 + project.items.iter().map(count_projects).sum::<usize>()
}

/// 收集云端默认勾选的项目 Id（子项随父项一起提供默认值）
fn collect_checked(project: &AccelerateProject, out: &mut Vec<String>) {
    if project.default_checked {
        out.push(project.id.clone());
    }
    for child in &project.items {
        collect_checked(child, out);
    }
}

/// 构建引擎规则：父项目未启用 → 整棵子树立丢弃；子项目未启用 → 从 Items 中剔除。
/// `enabled` 为 `None` 时按云端 `Checked` 默认值过滤（首次运行语义）。
fn build_rule(project: &AccelerateProject, enabled: Option<&HashSet<&str>>) -> Option<DomainRule> {
    if !is_enabled(&project.id, project.default_checked, enabled) {
        return None;
    }
    let mut rule = project.rule.clone();
    rule.fields.items = project
        .items
        .iter()
        .filter_map(|child| build_sub_rule(child, enabled))
        .collect();
    Some(rule)
}

/// 子项目 → SubRule（匹配串为 URL 模式正则）
fn build_sub_rule(project: &AccelerateProject, enabled: Option<&HashSet<&str>>) -> Option<SubRule> {
    if !is_enabled(&project.id, project.default_checked, enabled) {
        return None;
    }
    let mut fields = project.rule.fields.clone();
    fields.items = project
        .items
        .iter()
        .filter_map(|child| build_sub_rule(child, enabled))
        .collect();
    Some(SubRule {
        regex: url_patterns_to_regex(&project.rule.match_domain_names.join(";")),
        rule: fields,
    })
}

/// 生效判断：显式集合优先；`None` 回退云端默认勾选
fn is_enabled(id: &str, default_checked: bool, enabled: Option<&HashSet<&str>>) -> bool {
    match enabled {
        Some(set) => set.contains(id),
        None => default_checked,
    }
}

impl AccelerateProjectGroup {
    /// DTO → 领域模型（分组内无可解析项目时返回 None）
    pub fn from_dto(dto: &AccelerateProjectGroupDto) -> Option<Self> {
        let name = dto.name.clone().filter(|s| !s.trim().is_empty())?;
        let items: Vec<AccelerateProject> = dto
            .items
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(AccelerateProject::from_dto)
            .collect();
        Some(Self {
            id: dto.id.clone().unwrap_or_default(),
            name,
            order: dto.order.unwrap_or_default(),
            show: dto.show.unwrap_or(true),
            items,
        })
    }
}

impl AccelerateProject {
    /// DTO → 领域模型（无匹配域名时返回 None：云端存在脏数据）
    pub fn from_dto(dto: &AccelerateProjectDto) -> Option<Self> {
        let match_domain_names = split_semicolon(dto.match_domain_names.as_deref());
        if match_domain_names.is_empty() {
            return None;
        }
        let listening_domain_names = split_semicolon(dto.listen_domain_names.as_deref());
        let proxy_type = ProxyType::from_value(dto.proxy_type.unwrap_or_default());

        let fields = DomainRuleFields {
            ip_address: crate::dto::non_empty(dto.ip_address.clone()).and_then(|s| s.parse().ok()),
            forward_destination: crate::dto::non_empty(dto.forward_destination.clone()),
            fake_server_name: crate::dto::non_empty(dto.fake_server_name.clone()),
            user_agent: crate::dto::non_empty(dto.fake_user_agent.clone()),
            is_server_side_proxy: proxy_type.is_server_side(),
            ..Default::default()
        };

        Some(Self {
            id: dto.id.clone().unwrap_or_default(),
            name: dto.name.clone().unwrap_or_default(),
            order: dto.order.unwrap_or_default(),
            port: dto.port.unwrap_or(443),
            default_checked: dto.checked.unwrap_or(false),
            server_side: proxy_type.is_server_side(),
            rule: DomainRule {
                match_domain_names,
                listening_domain_names: if listening_domain_names.is_empty() {
                    split_semicolon(dto.match_domain_names.as_deref())
                } else {
                    listening_domain_names
                },
                order: dto.order.unwrap_or_default(),
                fields,
            },
            items: dto
                .items
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter_map(AccelerateProject::from_dto)
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::ApiRsp;

    fn catalog() -> AccelerateCatalog {
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
    fn test_catalog_from_fixture() {
        let c = catalog();
        assert!(!c.is_empty());
        // 10 分组 + 58 项目（含子项目）由 fixture 决定，此处只校验解析有效
        assert!(c.project_count() > 50);
        let steam = &c.groups[0];
        assert_eq!(steam.name, "Steam 服务");
        assert!(steam.show);
        let img = &steam.items[0];
        assert_eq!(img.name, "Steam 图片");
        assert_eq!(
            img.rule.fields.forward_destination.as_deref(),
            Some("steamimage.rmbgame.net")
        );
        assert_eq!(img.rule.listening_domain_names.len(), 6);
        // Steam 社区 SNI 覆盖 + UA 模板
        let community = &steam.items[3];
        assert_eq!(
            community.rule.fields.fake_server_name.as_deref(),
            Some("steamstore-a.akamaihd.net")
        );
        assert!(community
            .rule
            .fields
            .user_agent
            .as_deref()
            .unwrap()
            .contains("${origin}"));
        // 子项目
        assert!(!community.items.is_empty());
        assert!(community.items[0]
            .rule
            .match_domain_names
            .iter()
            .any(|m| m.contains("https://")));
    }

    #[test]
    fn test_ip_address_project() {
        let c = catalog();
        let all: Vec<_> = c
            .groups
            .iter()
            .flat_map(|g| g.items.iter())
            .flat_map(|p| std::iter::once(p).chain(p.items.iter()))
            .collect();
        let gravatar = all
            .iter()
            .find(|p| p.name == "Gravatar 头像")
            .expect("fixture 含 Gravatar 头像");
        assert!(gravatar.rule.fields.ip_address.is_some());
        assert!(gravatar.rule.fields.forward_destination.is_none());
    }

    #[test]
    fn test_default_enabled_ids_are_checked_ones() {
        let c = catalog();
        let ids = c.default_enabled_ids();
        assert!(!ids.is_empty());
        let steam = &c.groups[0];
        // Steam 图片云端 Checked=true
        assert!(ids.contains(&steam.items[0].id));
    }

    #[test]
    fn test_to_domain_rules_filters_disabled() {
        let c = catalog();
        let steam = &c.groups[0];
        let community = &steam.items[3];

        // 启用 Steam 社区（前端传入完整生效集合，含其启用子项）
        let mut enabled = vec![community.id.clone()];
        enabled.extend(community.items.iter().map(|s| s.id.clone()));
        let rules = c.to_domain_rules(Some(&enabled));
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].match_domain_names,
            community.rule.match_domain_names
        );
        assert!(!rules[0].fields.items.is_empty());
        for sub in &rules[0].fields.items {
            assert!(sub.regex.contains("steamcommunity"));
        }

        // 仅启用父项、子项均未在生效集合 → 子规则剔除
        let rules = c.to_domain_rules(Some(std::slice::from_ref(&community.id)));
        assert_eq!(rules.len(), 1);
        assert!(rules[0].fields.items.is_empty());

        // 空启用集合 → 无规则
        assert!(c.to_domain_rules(Some(&[])).is_empty());

        // None → 云端默认值（顶层勾选项目数；子项随父规则进入 Items）
        let defaults = c.to_domain_rules(None);
        assert_eq!(
            defaults.len(),
            c.groups
                .iter()
                .flat_map(|g| g.items.iter())
                .filter(|p| p.default_checked)
                .count()
        );
    }

    #[test]
    fn test_disabled_parent_drops_whole_subtree() {
        let c = catalog();
        let steam = &c.groups[0];
        let community = &steam.items[3];
        let sub_id = community.items[0].id.clone();
        // 只启用子项、父项未启用 → 子项不生效（父规则不存在）
        assert!(c.to_domain_rules(Some(&[sub_id])).is_empty());
    }

    #[test]
    fn test_roundtrip_serde() {
        let c = catalog();
        let json = serde_json::to_string(&c).unwrap();
        let back: AccelerateCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(back.project_count(), c.project_count());
        assert_eq!(back.groups[0].items[0].name, c.groups[0].items[0].name);
    }
}
