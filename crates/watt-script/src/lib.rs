//! 脚本域：脚本元数据模型（注入匹配）+ 服务端钩子引擎（Phase 4b: rquickjs）+
//! UserScript 头解析与已安装脚本存储（Phase 6.4: 旧缓存迁移）。

pub mod hooks;
pub mod model;
pub mod store;
pub mod userscript;

pub use model::ScriptConfig;
pub use store::{copy_scripts, load_installed, save_installed, scan_legacy_dir, InstalledScript};
pub use userscript::parse_userscript;
