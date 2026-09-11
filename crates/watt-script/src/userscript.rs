//! UserScript 头部解析：`// ==UserScript==` 块内 `// @tag value` 元数据提取。
//! 对齐 ScriptManager.ReadScriptAsync（DescRegex = `(?<=@Tag)[\s\S]*?(?=\n)`，忽略大小写）。
//!
//! 字段语义（与 C# 一致）：
//! - 单值字段取首次出现（Regex.Match）；多值字段收集全部出现（Regex.Matches）
//! - @match 为空时回退 @include 作为匹配域名（见 ReadScriptAsync 尾部）

use crate::model::ScriptConfig;

/// UserScript 头部元数据
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserScriptMeta {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub homepage_url: String,
    pub download_url: String,
    pub update_url: String,
    /// @match 全部值
    pub match_domains: Vec<String>,
    /// @include 全部值
    pub include_domains: Vec<String>,
    /// @exclude 全部值
    pub exclude_domains: Vec<String>,
    /// @require 全部值
    pub require_urls: Vec<String>,
    /// @grant 全部值
    pub grants: Vec<String>,
}

impl UserScriptMeta {
    /// 匹配域名：@match 优先，空则回退 @include（对齐 ReadScriptAsync）
    pub fn effective_match_domains(&self) -> &[String] {
        if self.match_domains.is_empty() {
            &self.include_domains
        } else {
            &self.match_domains
        }
    }

    /// 转为引擎侧脚本配置
    pub fn to_script_config(&self, local_id: &str, cache_path: &str, order: i32) -> ScriptConfig {
        ScriptConfig {
            local_id: local_id.to_string(),
            cache_path: cache_path.to_string(),
            match_domain_names: self.effective_match_domains().to_vec(),
            exclude_domain_names: self.exclude_domains.clone(),
            order,
        }
    }
}

/// 解析脚本内容中的 UserScript 头部；无头部块返回 None
pub fn parse_userscript(content: &str) -> Option<UserScriptMeta> {
    let start = content.find("==UserScript==")?;
    let end = content[start..].find("==/UserScript==")? + start;
    let block = &content[start..end];

    let mut meta = UserScriptMeta::default();
    for line in block.lines() {
        let line = line.trim();
        // 形如 `// @tag value`（允许 //@tag 紧凑写法）
        let Some(rest) = line.strip_prefix("//") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('@') else {
            continue;
        };
        let (tag, value) = split_tag(rest);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match tag.as_str() {
            "name" => set_once(&mut meta.name, value),
            "version" => set_once(&mut meta.version, value),
            "description" => set_once(&mut meta.description, value),
            "author" => set_once(&mut meta.author, value),
            "homepageurl" => set_once(&mut meta.homepage_url, value),
            "downloadurl" => set_once(&mut meta.download_url, value),
            "updateurl" => set_once(&mut meta.update_url, value),
            "match" => meta.match_domains.push(value.to_string()),
            "include" => meta.include_domains.push(value.to_string()),
            "exclude" => meta.exclude_domains.push(value.to_string()),
            "require" => meta.require_urls.push(value.to_string()),
            "grant" => meta.grants.push(value.to_string()),
            _ => {}
        }
    }
    Some(meta)
}

/// `tag  value` → (小写 tag, 值)；tag 为首个空白前的部分
fn split_tag(rest: &str) -> (String, &str) {
    match rest.find(char::is_whitespace) {
        Some(i) => (rest[..i].to_ascii_lowercase(), &rest[i..]),
        None => (rest.to_ascii_lowercase(), ""),
    }
}

/// 单值字段仅首次出现生效（对齐 Regex.Match 取第一个匹配）
fn set_once(slot: &mut String, value: &str) {
    if slot.is_empty() {
        *slot = value.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"// ==UserScript==
// @name         Steam 下载加速
// @namespace    watt
// @version      1.2.3
// @description  加速 Steam 商店
// @author       someone
// @homepageURL  https://steampp.net
// @downloadURL  https://api.steampp.net/1.js
// @updateURL    https://api.steampp.net/1.js
// @match        *.steamcommunity.com
// @match        steamstatic.com
// @include      include.example.com
// @exclude      api.steamcommunity.com
// @require      https://cdn.example.com/lib.js
// @grant        GM_xmlhttpRequest
// ==/UserScript==
(function(){})();
"#;

    #[test]
    fn test_parse_full_header() {
        let meta = parse_userscript(SAMPLE).unwrap();
        assert_eq!(meta.name, "Steam 下载加速");
        assert_eq!(meta.version, "1.2.3");
        assert_eq!(meta.description, "加速 Steam 商店");
        assert_eq!(meta.author, "someone");
        assert_eq!(meta.homepage_url, "https://steampp.net");
        assert_eq!(meta.download_url, "https://api.steampp.net/1.js");
        assert_eq!(meta.update_url, "https://api.steampp.net/1.js");
        assert_eq!(
            meta.match_domains,
            vec!["*.steamcommunity.com", "steamstatic.com"]
        );
        assert_eq!(meta.include_domains, vec!["include.example.com"]);
        assert_eq!(meta.exclude_domains, vec!["api.steamcommunity.com"]);
        assert_eq!(meta.require_urls, vec!["https://cdn.example.com/lib.js"]);
        assert_eq!(meta.grants, vec!["GM_xmlhttpRequest"]);
    }

    #[test]
    fn test_match_fallback_to_include() {
        let content =
            "// ==UserScript==\n// @include a.com\n// @exclude b.com\n// ==/UserScript==\n";
        let meta = parse_userscript(content).unwrap();
        assert_eq!(meta.effective_match_domains(), ["a.com"]);
    }

    #[test]
    fn test_no_header() {
        assert!(parse_userscript("var x = 1;").is_none());
    }

    /// tag 大小写不敏感 + 首次出现优先 + name 不误吞 namespace
    #[test]
    fn test_tag_matching_rules() {
        let content = "// ==UserScript==\n// @NAME First\n// @Name Second\n// @namespace ns\n// ==/UserScript==\n";
        let meta = parse_userscript(content).unwrap();
        assert_eq!(meta.name, "First");
        assert_eq!(meta.version, "");
    }

    #[test]
    fn test_to_script_config() {
        let meta = parse_userscript(SAMPLE).unwrap();
        let config = meta.to_script_config("abc123", "C:/cache/abc123.js", 7);
        assert_eq!(config.local_id, "abc123");
        assert_eq!(config.cache_path, "C:/cache/abc123.js");
        assert_eq!(config.order, 7);
        assert_eq!(
            config.match_domain_names,
            vec!["*.steamcommunity.com", "steamstatic.com"]
        );
        assert_eq!(config.exclude_domain_names, vec!["api.steamcommunity.com"]);
    }
}
