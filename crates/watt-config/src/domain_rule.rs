//! 域名规则：对齐原 .NET IDomainConfig / DomainConfig。

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// 静态响应规则（原 Response 属性）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticResponse {
    /// HTTP 状态码
    pub status_code: u16,
    /// 响应体（文本）
    pub body: String,
    /// 响应头
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

/// 子规则（原 Items，按正则匹配 URL 递归细化规则）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubRule {
    /// 正则表达式（匹配完整 URL）
    pub regex: String,
    #[serde(flatten)]
    pub rule: DomainRuleFields,
}

/// 域名规则完整字段（SubRule 与顶层规则共用）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DomainRuleFields {
    /// 代理目标 IP（优先于 DNS 解析）
    #[serde(default, alias = "IPAddress", alias = "IpAddress")]
    pub ip_address: Option<IpAddr>,
    /// 目标模板，支持 @domain / @uri 占位
    #[serde(default)]
    pub destination: Option<String>,
    /// 仅转发目标（同 destination 语义别名，兼容旧数据）
    #[serde(default)]
    pub forward_destination: Option<String>,
    /// 静态响应
    #[serde(default)]
    pub response: Option<StaticResponse>,
    /// 子规则
    #[serde(default)]
    pub items: Vec<SubRule>,
    /// UserAgent 替换，${origin} 为原始 UA
    #[serde(default)]
    pub user_agent: Option<String>,
    /// 出站超时（毫秒）
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// TLS SNI 启用（默认 true）
    #[serde(default = "default_true")]
    pub tls_sni: bool,
    /// TLS SNI 覆盖（对齐 C# FakeServerName / GetTlsSniPattern）
    /// 支持 `@domain`、`{origin}`、`${domain}`、`${random}` 占位；空表示不覆盖。
    #[serde(default, alias = "FakeServerName")]
    pub fake_server_name: Option<String>,
    /// TLS 忽略名称不匹配
    #[serde(default)]
    pub tls_ignore_name_mismatch: bool,
    /// 服务端代理（追加 X-Watt-Origin-Dest-* / X-Watt-Token 头）
    #[serde(default, alias = "IsServerSideProxy")]
    pub is_server_side_proxy: bool,
}

fn default_true() -> bool {
    true
}

/// 对齐 C# DomainConfig：TlsSni 默认 true（defaultDomainConfig = new DomainConfig { TlsSni = true }）
impl Default for DomainRuleFields {
    fn default() -> Self {
        Self {
            ip_address: None,
            destination: None,
            forward_destination: None,
            response: None,
            items: Vec::new(),
            user_agent: None,
            timeout_ms: None,
            tls_sni: true,
            fake_server_name: None,
            tls_ignore_name_mismatch: false,
            is_server_side_proxy: false,
        }
    }
}

/// 域名规则（原 DomainConfig）
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DomainRule {
    /// 匹配域名（支持通配，如 *.steamcommunity.com）
    #[serde(default, alias = "MatchDomainNames")]
    pub match_domain_names: Vec<String>,
    /// 监听域名（hosts 写入用，"ip domain" 反序格式兼容）
    #[serde(default, alias = "ListeningDomainNames")]
    pub listening_domain_names: Vec<String>,
    /// 排序
    #[serde(default)]
    pub order: i32,
    #[serde(flatten)]
    pub fields: DomainRuleFields,
}

/// 域名规则集（匹配 + 递归子规则），线程安全共享
#[derive(Debug, Clone, Default)]
pub struct DomainRules {
    rules: Vec<DomainRule>,
}

impl DomainRules {
    pub fn new(rules: Vec<DomainRule>) -> Self {
        Self { rules }
    }

    pub fn all(&self) -> &[DomainRule] {
        &self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 所有监听域名（hosts 模式写入）
    pub fn listening_domain_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .rules
            .iter()
            .flat_map(|r| r.listening_domain_names.iter().cloned())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// 匹配域名（不带 scheme 的 host），返回命中的规则。
    /// 多条规则同时命中时取**最长匹配模式**（最具体者），平局取 order 大者。
    pub fn find(&self, host: &str) -> Option<&DomainRule> {
        let host = host.split(':').next().unwrap_or(host);
        self.rules
            .iter()
            .filter_map(|r| {
                r.match_domain_names
                    .iter()
                    .filter(|m| domain_match(m, host))
                    .map(|m| (r, m.len()))
                    .max_by_key(|(_, len)| *len)
            })
            .max_by_key(|(r, len)| (*len, r.order))
            .map(|(r, _)| r)
    }

    /// 按完整 URL 匹配（云端规则存在带路径的匹配项，如 `maxcdn.bootstrapcdn.com/bootstrap`）。
    /// 模式含 `/` 时按 URL 前缀/通配匹配整条 URL，否则退化为 host 域名匹配。
    /// 多条规则同时命中时取最长匹配模式（最具体者），平局取 order 大者。
    pub fn find_by_url(&self, url: &str, host: &str) -> Option<&DomainRule> {
        let host = host.split(':').next().unwrap_or(host);
        self.rules
            .iter()
            .filter_map(|r| {
                r.match_domain_names
                    .iter()
                    .filter(|m| pattern_matches(m, host, url))
                    .map(|m| (r, m.len()))
                    .max_by_key(|(_, len)| *len)
            })
            .max_by_key(|(r, len)| (*len, r.order))
            .map(|(r, _)| r)
    }
}

/// 单条匹配模式判定：URL 模式（含 `/`）匹配整条 URL，否则按域名匹配 host
pub fn pattern_matches(pattern: &str, host: &str, url: &str) -> bool {
    if pattern.contains('/') {
        url_pattern_matches(pattern, url)
    } else {
        domain_match(pattern, host)
    }
}

/// URL 模式匹配：`;` 分隔多模式，任意模式命中即匹配；`*` 通配段、`?` 通配单字符。
/// 对齐 C# DomainPattern：正则未锚定，匹配完整 URL 的任意位置。
pub fn url_pattern_matches(pattern: &str, url: &str) -> bool {
    match regex::RegexBuilder::new(&url_patterns_to_regex(pattern))
        .case_insensitive(true)
        .build()
    {
        Ok(re) => re.is_match(url),
        Err(e) => {
            tracing::warn!("URL 模式无效（{pattern}）：{e}");
            false
        }
    }
}

/// `;` 分隔的通配模式 → 正则串（对齐 C# DomainPattern：转义后 `*`→`.*`、`?`→`.`）
pub fn url_patterns_to_regex(patterns: &str) -> String {
    let parts: Vec<String> = patterns
        .split(';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            let escaped = regex::escape(s).replace(r"\*", ".*").replace(r"\?", ".");
            format!("(?:{escaped})")
        })
        .collect();
    if parts.is_empty() {
        // 空模式不匹配任何 URL
        return "^$".to_string();
    }
    parts.join("|")
}

/// 域名匹配：支持通配符（*.example.com 匹配子域名），大小写不敏感
pub fn domain_match(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if pattern == host {
        return true;
    }
    // 裸父域名隐式匹配全部子域名：原版 C# DomainPattern 为未锚定正则子串语义，
    // `githubusercontent.com` 可命中 `raw.githubusercontent.com` 的 URL；
    // host 层等价语义为子域后缀匹配（精确且不跨域误吞）
    if host.ends_with(&format!(".{pattern}")) {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if let Some(first_dot) = host.find('.') {
            return &host[first_dot + 1..] == suffix;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_match() {
        assert!(domain_match("steamcommunity.com", "steamcommunity.com"));
        assert!(domain_match(
            "*.steamcommunity.com",
            "api.steamcommunity.com"
        ));
        assert!(!domain_match("*.steamcommunity.com", "steamcommunity.com"));
        // 裸父域名匹配子域名（原版为未锚定子串语义）
        assert!(domain_match("steamcommunity.com", "api.steamcommunity.com"));
        assert!(domain_match(
            "githubusercontent.com",
            "raw.githubusercontent.com"
        ));
        assert!(domain_match("SteamCommunity.com", "steamcommunity.com"));
    }

    /// GitHub 云端实景回归：裸父域规则（githubusercontent.com, order 70）
    /// 与精确子域规则（api.github.com, order 68）并存时的判定
    #[test]
    fn test_github_catalog_matching() {
        let rules = DomainRules::new(vec![
            DomainRule {
                match_domain_names: vec!["githubusercontent.com".into()],
                listening_domain_names: vec![],
                order: 70,
                fields: DomainRuleFields {
                    ip_address: Some("23.235.37.133".parse().unwrap()),
                    ..Default::default()
                },
            },
            DomainRule {
                match_domain_names: vec!["github.com".into(), "gist.github.com".into()],
                listening_domain_names: vec![],
                order: 72,
                fields: DomainRuleFields {
                    ip_address: Some("20.207.73.82".parse().unwrap()),
                    ..Default::default()
                },
            },
            DomainRule {
                match_domain_names: vec!["api.github.com".into()],
                listening_domain_names: vec![],
                order: 68,
                fields: DomainRuleFields {
                    forward_destination: Some("githubapi.rmbgame.net".into()),
                    ..Default::default()
                },
            },
        ]);
        // raw 命中 UserContent 裸父域规则
        let raw = rules
            .find_by_url(
                "https://raw.githubusercontent.com/a/b/README.md",
                "raw.githubusercontent.com",
            )
            .expect("raw should match UserContent");
        assert_eq!(raw.order, 70);
        // api.github.com 必须命中更具体的 Api 规则，而非被 Web 的 github.com 裸域吞掉
        let api = rules
            .find_by_url("https://api.github.com/", "api.github.com")
            .expect("api should match");
        assert_eq!(api.order, 68);
        assert!(api.fields.forward_destination.is_some());
        // gist 精确命中 Web 规则
        let gist = rules
            .find_by_url("https://gist.github.com/", "gist.github.com")
            .expect("gist should match");
        assert_eq!(gist.order, 72);
    }

    #[test]
    fn test_find_rule() {
        let rules = DomainRules::new(vec![DomainRule {
            match_domain_names: vec!["*.example.com".into()],
            listening_domain_names: vec!["example.com api.example.com".into()],
            order: 0,
            fields: DomainRuleFields {
                destination: Some("https://mirror.test".into()),
                ..Default::default()
            },
        }]);
        let found = rules.find("api.example.com").expect("should match");
        assert_eq!(
            found.fields.destination.as_deref(),
            Some("https://mirror.test")
        );
        assert!(rules.find("other.com").is_none());
    }

    #[test]
    fn test_find_by_url_with_path_pattern() {
        let rules = DomainRules::new(vec![DomainRule {
            match_domain_names: vec!["maxcdn.bootstrapcdn.com/bootstrap".into()],
            listening_domain_names: vec!["maxcdn.bootstrapcdn.com".into()],
            order: 0,
            fields: DomainRuleFields {
                forward_destination: Some("cdn.bootcdn.net".into()),
                ..Default::default()
            },
        }]);
        let url = "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css";
        assert!(rules.find_by_url(url, "maxcdn.bootstrapcdn.com").is_some());
        assert!(rules
            .find_by_url(
                "https://maxcdn.bootstrapcdn.com/other",
                "maxcdn.bootstrapcdn.com"
            )
            .is_none());
    }

    #[test]
    fn test_url_patterns_to_regex() {
        // 多模式 + 通配：任一段命中即匹配
        let re = url_patterns_to_regex(
            "https://steamcommunity.com/comment;https://steamcommunity.com/*/discussions",
        );
        assert!(regex::Regex::new(&re)
            .unwrap()
            .is_match("https://steamcommunity.com/comment/1"));
        assert!(regex::Regex::new(&re)
            .unwrap()
            .is_match("https://steamcommunity.com/app/1/discussions/"));
        assert!(!regex::Regex::new(&re)
            .unwrap()
            .is_match("https://steamcommunity.com/"));
        // 空模式不匹配任何 URL
        assert!(!regex::Regex::new(&url_patterns_to_regex(""))
            .unwrap()
            .is_match("https://a.com/"));
    }
}
