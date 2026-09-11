//! 脚本元数据（对齐 ScriptIPCDTO）：注入匹配与排除规则。

use serde::{Deserialize, Serialize};

/// 已启用脚本配置（传递给代理引擎）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScriptConfig {
    /// 本地 ID（注入路径 /WattToolkit_Inject/{lid}.js）
    #[serde(default)]
    pub local_id: String,
    /// 脚本缓存文件路径
    #[serde(default)]
    pub cache_path: String,
    /// 匹配域名（支持通配）
    #[serde(default)]
    pub match_domain_names: Vec<String>,
    /// 排除域名
    #[serde(default)]
    pub exclude_domain_names: Vec<String>,
    /// 执行顺序
    #[serde(default)]
    pub order: i32,
}

/// 判断 URL 是否命中脚本注入（对齐 TryGetScriptConfig）
pub fn script_matches_url(script: &ScriptConfig, url: &str) -> bool {
    // 提取 host
    let host = extract_host(url);
    let Some(host) = host else {
        return false;
    };
    // 排除优先
    if script
        .exclude_domain_names
        .iter()
        .any(|d| domain_match(d, &host))
    {
        return false;
    }
    script
        .match_domain_names
        .iter()
        .any(|d| domain_match(d, &host))
}

fn extract_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn domain_match(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if let Some(first_dot) = host.find('.') {
            return &host[first_dot + 1..] == suffix;
        }
    }
    false
}

/// 脚本集：按 URL 匹配全部命中脚本（按 order 排序）
pub struct ScriptSet {
    pub scripts: Vec<ScriptConfig>,
}

impl ScriptSet {
    pub fn new(scripts: Vec<ScriptConfig>) -> Self {
        Self { scripts }
    }

    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    /// 匹配 URL 的全部脚本（order 升序）
    pub fn match_url(&self, url: &str) -> Vec<&ScriptConfig> {
        let mut matched: Vec<&ScriptConfig> = self
            .scripts
            .iter()
            .filter(|s| script_matches_url(s, url))
            .collect();
        matched.sort_by_key(|s| s.order);
        matched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(matchs: &[&str], excludes: &[&str]) -> ScriptConfig {
        ScriptConfig {
            local_id: "test".into(),
            cache_path: "C:/cache/test.js".into(),
            match_domain_names: matchs.iter().map(|s| s.to_string()).collect(),
            exclude_domain_names: excludes.iter().map(|s| s.to_string()).collect(),
            order: 0,
        }
    }

    #[test]
    fn test_match() {
        let s = script(&["*.steamcommunity.com"], &["api.steamcommunity.com"]);
        assert!(script_matches_url(&s, "https://steamcommunity.com/path") == false); // 通配不匹配裸域
        assert!(script_matches_url(
            &s,
            "https://www.steamcommunity.com/path"
        ));
        assert!(!script_matches_url(
            &s,
            "https://api.steamcommunity.com/path"
        )); // 排除
        assert!(!script_matches_url(&s, "https://example.com/"));
    }

    #[test]
    fn test_exact_match() {
        let s = script(&["steamcommunity.com"], &[]);
        assert!(script_matches_url(
            &s,
            "https://steamcommunity.com/path?x=1"
        ));
        assert!(!script_matches_url(&s, "https://sub.steamcommunity.com/"));
    }

    #[test]
    fn test_order() {
        let set = ScriptSet::new(vec![
            ScriptConfig {
                order: 2,
                local_id: "b".into(),
                match_domain_names: vec!["any.com".into()],
                ..Default::default()
            },
            ScriptConfig {
                order: 1,
                local_id: "a".into(),
                match_domain_names: vec!["*.any.com".into(), "any.com".into()],
                ..Default::default()
            },
        ]);
        let matched = set.match_url("https://any.com/");
        assert_eq!(matched.len(), 2);
        assert_eq!(matched[0].local_id, "a");
        assert_eq!(matched[1].local_id, "b");
    }
}
