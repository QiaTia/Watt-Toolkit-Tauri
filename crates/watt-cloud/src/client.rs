//! 云端 API 客户端：`GET {base}/api/Accelerate/All`。
//!
//! 对齐旧版 `IMicroServiceClient.Instance.Accelerate.All()`：
//! 索引键 JSON → DTO → 领域模型目录。

use crate::dto::{AccelerateProjectGroupDto, ApiRsp};
use crate::model::{AccelerateCatalog, AccelerateProjectGroup};

/// 生产环境 API 基址
pub const DEFAULT_API_BASE: &str = "https://api.steampp.net";

#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    #[error("HTTP 请求失败: {0}")]
    Http(#[from] reqwest::Error),
    #[error("云端返回错误 Code={code} Message={message}")]
    Api { code: i64, message: String },
    #[error("响应解析失败: {0}")]
    Parse(#[from] serde_json::Error),
}

/// 加速项目云端客户端
pub struct AccelerateClient {
    http: reqwest::Client,
    api_base: String,
}

impl AccelerateClient {
    pub fn new() -> Self {
        Self::with_base(DEFAULT_API_BASE)
    }

    pub fn with_base(api_base: &str) -> Self {
        // rustls-no-provider 不会自动安装 crypto provider，需手动安装（进程级全局、幂等）
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .user_agent(concat!("WattToolkit/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .expect("reqwest client 构建失败");
        Self {
            http,
            api_base: api_base.trim_end_matches('/').to_string(),
        }
    }

    /// 拉取加速项目目录（云端 → 领域模型）
    pub async fn fetch_catalog(&self) -> Result<AccelerateCatalog, CloudError> {
        let groups = self.fetch_groups().await?;
        Ok(AccelerateCatalog::new(
            groups
                .iter()
                .filter_map(AccelerateProjectGroup::from_dto)
                .collect(),
        ))
    }

    /// 拉取原始分组 DTO 列表
    pub async fn fetch_groups(&self) -> Result<Vec<AccelerateProjectGroupDto>, CloudError> {
        let url = format!("{}/api/Accelerate/All", self.api_base);
        let rsp: ApiRsp<Vec<AccelerateProjectGroupDto>> =
            self.http.get(&url).send().await?.json().await?;
        if rsp.is_success() {
            Ok(rsp.content.unwrap_or_default())
        } else {
            Err(CloudError::Api {
                code: rsp.code.unwrap_or_default(),
                message: rsp.message.unwrap_or_else(|| "未知错误".to_string()),
            })
        }
    }
}

impl Default for AccelerateClient {
    fn default() -> Self {
        Self::new()
    }
}
