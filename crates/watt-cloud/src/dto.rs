//! 云端 DTO：索引键 JSON 反序列化（属性名为数字索引 / 混淆 emoji）。
//!
//! 服务端字段顺序与 `AccelerateProjectDTO` 的 MessagePack 契约一致；
//! 全部字段 `Option` 以容忍字段缺失或类型变化（云端改版不阻断启动）。

use serde::Deserialize;

/// API 响应包装层（原 `IApiRsp`；属性名为 emoji 混淆）
#[derive(Debug, Clone, Deserialize)]
pub struct ApiRsp<T> {
    /// 🦓 Content：业务数据
    #[serde(rename = "\u{1F993}")]
    pub content: Option<T>,
    /// 🦄 Code：状态码（200 为成功）
    #[serde(rename = "\u{1F984}")]
    pub code: Option<i64>,
    /// 🐴 Message：错误信息
    #[serde(rename = "\u{1F434}")]
    pub message: Option<String>,
}

impl<T> ApiRsp<T> {
    /// 是否成功（对齐 `IApiRsp.IsSuccess`：Code == 200 且 Content 非空）
    pub fn is_success(&self) -> bool {
        self.code == Some(200) && self.content.is_some()
    }
}

/// 加速项目分组
#[derive(Debug, Clone, Deserialize)]
pub struct AccelerateProjectGroupDto {
    /// 0 = Name
    #[serde(rename = "0")]
    pub name: Option<String>,
    /// 1 = Items
    #[serde(rename = "1")]
    pub items: Option<Vec<AccelerateProjectDto>>,
    /// 2 = Id（GUID）
    #[serde(rename = "2")]
    pub id: Option<String>,
    /// 3 = Show（分组是否在列表中展示）
    #[serde(rename = "3")]
    pub show: Option<bool>,
    /// 4 = Order
    #[serde(rename = "4")]
    pub order: Option<i32>,
}

/// ProxyType 枚举（服务端数值）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyType {
    /// 0 = 常规反向代理
    Default = 0,
    /// 1 = 镜像替换（默认不勾选）
    Mirror = 1,
    /// 4 = 服务端代理（需 ServerSideProxyToken）
    ServerAccelerate = 4,
}

impl ProxyType {
    pub fn from_value(v: i32) -> Self {
        match v {
            1 => ProxyType::Mirror,
            4 => ProxyType::ServerAccelerate,
            _ => ProxyType::Default,
        }
    }

    /// 是否为服务端加速（对齐 C# `ProxyType.ServerAccelerate`）
    pub fn is_server_side(self) -> bool {
        matches!(self, ProxyType::ServerAccelerate)
    }
}

/// 加速项目（子规则 Items 结构递归）
#[derive(Debug, Clone, Deserialize)]
pub struct AccelerateProjectDto {
    /// 0 = Name
    #[serde(rename = "0")]
    pub name: Option<String>,
    /// 1 = Port
    #[serde(rename = "1")]
    pub port: Option<u16>,
    /// 2 = MatchDomainNames（`;` 分隔，可为域名或带路径的 URL 模式）
    #[serde(rename = "2")]
    pub match_domain_names: Option<String>,
    /// 3 = ForwardDomainNames（转发目标域名，DNS 解析取 IP 后连该 IP）
    #[serde(rename = "3")]
    pub forward_destination: Option<String>,
    /// 4 = IPAddress（直连 IP 覆盖）
    #[serde(rename = "4")]
    pub ip_address: Option<String>,
    /// 5 = FakeServerName（SNI 覆盖，支持 `@domain` / `{origin}` / `${random}`）
    #[serde(rename = "5")]
    pub fake_server_name: Option<String>,
    /// ProxyType（唯一按名序列化的字段）
    #[serde(rename = "ProxyType")]
    pub proxy_type: Option<i32>,
    /// 7 = ListenDomainNames（`;` 分隔，hosts 写入用）
    #[serde(rename = "7")]
    pub listen_domain_names: Option<String>,
    /// 8 = Checked（云端默认勾选）
    #[serde(rename = "8")]
    pub checked: Option<bool>,
    /// 9 = Id（GUID）
    #[serde(rename = "9")]
    pub id: Option<String>,
    /// 10 = Order
    #[serde(rename = "10")]
    pub order: Option<i32>,
    /// 11 = FakeUserAgent（`${origin}` 占位替换为原始 UA）
    #[serde(rename = "11")]
    pub fake_user_agent: Option<String>,
    /// 12 = Items（子规则，结构同父级）
    #[serde(rename = "12")]
    pub items: Option<Vec<AccelerateProjectDto>>,
}

/// `;` 分隔字符串 → 非空片段列表
pub fn split_semicolon(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// 空字符串视为 None
pub fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实 API 响应片段（结构裁剪自 https://api.steampp.net/api/Accelerate/All）
    const SAMPLE: &str = r#"{
        "🦓": [
            {
                "0": "Steam 服务",
                "1": [
                    {
                        "0": "Steam 图片",
                        "1": 443,
                        "2": "steamcdn-a.akamaihd.net;community.akamai.steamstatic.com",
                        "3": "steamimage.rmbgame.net",
                        "4": "",
                        "5": "",
                        "ProxyType": 0,
                        "7": "steamcdn-a.akamaihd.net;community.akamai.steamstatic.com",
                        "8": true,
                        "9": "bbd6dafa-c295-eb11-abaa-a0d3c1f2a15d",
                        "10": 32,
                        "11": null,
                        "12": null
                    },
                    {
                        "0": "Steam 社区",
                        "1": 443,
                        "2": "steamcommunity.com;www.steamcommunity.com",
                        "3": "steamcommunity.rmbgame.net",
                        "4": "",
                        "5": "steamstore-a.akamaihd.net",
                        "ProxyType": 0,
                        "7": "steamcommunity.com;www.steamcommunity.com",
                        "8": true,
                        "9": "abd6dafa-c295-eb11-abaa-a0d3c1f2a15d",
                        "10": 37,
                        "11": "Chrome/150.0.6478.183; ${origin}",
                        "12": [
                            {
                                "0": "Steam 社区(解锁访问限制)",
                                "1": 443,
                                "2": "https://steamcommunity.com/*/discussions/",
                                "3": "steamuserimages-a.akamaihd.net.edgesuite.net",
                                "4": "",
                                "5": "officecdn-microsoft-com.akamaized.net",
                                "ProxyType": 0,
                                "7": "steamcommunity.com",
                                "8": true,
                                "9": "379bf61c-398c-444e-968a-1dccc3202e55",
                                "10": 35,
                                "11": "${origin} Googlebot/2.1 (+http://www.google.com/bot.html)",
                                "12": null
                            }
                        ]
                    }
                ],
                "2": "fcd2423e-f36b-1410-886e-00e23e1d515d",
                "3": true,
                "4": 1
            }
        ],
        "🦄": 200,
        "🐴": null
    }"#;

    #[test]
    fn test_parse_real_response() {
        let rsp: ApiRsp<Vec<AccelerateProjectGroupDto>> = serde_json::from_str(SAMPLE).unwrap();
        assert!(rsp.is_success());
        let groups = rsp.content.unwrap();
        assert_eq!(groups.len(), 1);

        let g = &groups[0];
        assert_eq!(g.name.as_deref(), Some("Steam 服务"));
        assert_eq!(g.show, Some(true));
        assert_eq!(g.order, Some(1));

        let items = g.items.as_ref().unwrap();
        assert_eq!(items.len(), 2);
        let img = &items[0];
        assert_eq!(img.port, Some(443));
        assert_eq!(split_semicolon(img.match_domain_names.as_deref()).len(), 2);
        assert_eq!(
            img.forward_destination.as_deref(),
            Some("steamimage.rmbgame.net")
        );
        assert_eq!(non_empty(img.ip_address.clone()), None);
        assert_eq!(non_empty(img.fake_server_name.clone()), None);
        assert_eq!(img.checked, Some(true));

        let community = &items[1];
        assert_eq!(
            community.fake_server_name.as_deref(),
            Some("steamstore-a.akamaihd.net")
        );
        assert!(community
            .fake_user_agent
            .as_deref()
            .unwrap()
            .contains("${origin}"));
        let sub = community.items.as_ref().unwrap();
        assert_eq!(sub.len(), 1);
        assert_eq!(sub[0].name.as_deref(), Some("Steam 社区(解锁访问限制)"));
        assert!(sub[0]
            .match_domain_names
            .as_deref()
            .unwrap()
            .contains("/*/"));
    }

    #[test]
    fn test_code_not_200_is_failure() {
        let json = r#"{"🦓":null,"🦄":500,"🐴":"服务器错误"}"#;
        let rsp: ApiRsp<Vec<AccelerateProjectGroupDto>> = serde_json::from_str(json).unwrap();
        assert!(!rsp.is_success());
        assert_eq!(rsp.message.as_deref(), Some("服务器错误"));
    }

    /// 字段类型变化（如 Port 变字符串）时整体解析失败但不 panic，由调用方降级到缓存
    #[test]
    fn test_tolerant_to_missing_fields() {
        let json = r#"{"🦓":[{"0":"X"}],"🦄":200,"🐴":null}"#;
        let rsp: ApiRsp<Vec<AccelerateProjectGroupDto>> = serde_json::from_str(json).unwrap();
        let g = &rsp.content.unwrap()[0];
        assert_eq!(g.name.as_deref(), Some("X"));
        assert!(g.items.is_none());
    }

    #[test]
    fn test_proxy_type_mapping() {
        assert!(ProxyType::from_value(4).is_server_side());
        assert!(!ProxyType::from_value(0).is_server_side());
        assert!(matches!(ProxyType::from_value(1), ProxyType::Mirror));
    }
}
