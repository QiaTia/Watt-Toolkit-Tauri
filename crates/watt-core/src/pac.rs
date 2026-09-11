//! PAC 脚本生成（对齐 C# HttpProxyPacMiddleware.CreateProxyPac）。
//!
//! 生成 `FindProxyForURL`：匹配加速域名（规则 + 脚本 + 本地域名）走本地代理，
//! 其余 `DIRECT` 直连。域名模式直接作为 shExpMatch 参数（支持 `*` 通配）。

use watt_config::DomainRules;
use watt_script::ScriptConfig;

/// 生成 PAC 脚本
///
/// `proxy_authority`：代理地址（如 `127.0.0.1:26501`）
pub fn generate_pac(
    proxy_authority: &str,
    rules: &DomainRules,
    scripts: &[ScriptConfig],
) -> String {
    let mut patterns: Vec<String> = Vec::new();

    // 规则匹配域名（对齐 GetDomainPatterns）
    for rule in rules.all() {
        for name in &rule.match_domain_names {
            push_pattern(&mut patterns, name);
        }
    }

    // 脚本匹配域名（System/PAC 模式下脚本注入域名也需走代理）
    for script in scripts {
        for name in &script.match_domain_names {
            push_pattern(&mut patterns, name);
        }
    }

    // 本地域名（启用脚本时）
    if !scripts.is_empty() {
        push_pattern(&mut patterns, watt_config::constants::LOCAL_DOMAIN);
    }

    let mut pac = String::with_capacity(256 + patterns.len() * 64);
    pac.push_str("function FindProxyForURL(url, host){\n");
    pac.push_str(&format!("    var pac = 'PROXY {proxy_authority}';\n"));
    for pattern in &patterns {
        pac.push_str(&format!(
            "    if (shExpMatch(host, '{pattern}')) return pac;\n"
        ));
    }
    pac.push_str("    return 'DIRECT';\n");
    pac.push_str("}\n");
    pac
}

/// 收集去重（大小写不敏感），转义单引号
fn push_pattern(patterns: &mut Vec<String>, name: &str) {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() {
        return;
    }
    if !patterns.iter().any(|p| p.eq_ignore_ascii_case(&name)) {
        patterns.push(name.replace('\'', "\\'"));
    }
}

/// PAC 响应 Content-Type（对齐原实现）
pub const PAC_CONTENT_TYPE: &str = "application/x-ns-proxy-autoconfig";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pac_rules_and_scripts() {
        let rules = DomainRules::new(vec![watt_config::DomainRule {
            match_domain_names: vec!["steamcommunity.com".into(), "*.steamcommunity.com".into()],
            ..Default::default()
        }]);
        let scripts = vec![ScriptConfig {
            local_id: "s1".into(),
            cache_path: "/tmp/s1.js".into(),
            match_domain_names: vec!["example.com".into()],
            exclude_domain_names: vec![],
            order: 0,
        }];

        let pac = generate_pac("127.0.0.1:26501", &rules, &scripts);

        assert!(pac.contains("function FindProxyForURL(url, host){"));
        assert!(pac.contains("var pac = 'PROXY 127.0.0.1:26501';"));
        assert!(pac.contains("shExpMatch(host, 'steamcommunity.com')"));
        assert!(pac.contains("shExpMatch(host, '*.steamcommunity.com')"));
        assert!(pac.contains("shExpMatch(host, 'example.com')"));
        assert!(pac.contains("shExpMatch(host, 'local.steampp.net')"));
        assert!(pac.contains("return 'DIRECT';\n}"));
        // 去重：相同域名只出现一次（精确条目计数，排除 *. 通配条目）
        assert_eq!(pac.matches(", 'steamcommunity.com')").count(), 1);
    }

    #[test]
    fn test_generate_pac_empty() {
        let pac = generate_pac("127.0.0.1:26501", &DomainRules::default(), &[]);
        assert!(pac.contains("return 'DIRECT';"));
        assert!(!pac.contains("shExpMatch"));
    }
}
