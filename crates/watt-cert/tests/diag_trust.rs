//! 真实信任存储诊断（读取本机证书目录与系统 Root 存储）。
//!
//! 默认忽略：结果依赖运行机器的实际安装状态，不适合作为 CI 断言。
//! 手动运行：`cargo test -p watt-cert --test diag_trust -- --ignored --nocapture`

use watt_cert::ca::CaCertificate;

#[test]
#[ignore = "读取真实系统信任存储，需人工判读"]
fn diag_real_trust_store() {
    let dir = watt_cert::cert_dir();
    let path = CaCertificate::cert_path(&dir);
    println!("证书路径: {}", path.display());
    println!("目录存在: {}", dir.exists());

    let d = watt_cert::diagnose(&path);
    println!("{d:#?}");

    // 结构性断言：诊断必须给出至少一条结论，且 advise 与 installed 不矛盾
    assert!(!d.advice.is_empty(), "诊断不能返回空建议");
    if d.installed {
        assert!(
            d.advice.iter().any(|s| s.contains("已安装")),
            "installed=true 时建议里必须体现已安装: {:?}",
            d.advice
        );
    }
    if let Some(n) = d.same_cn_certs {
        println!("同 CN 证书数量: {n}");
    }
    if let Some(e) = d.elevated {
        println!("已提权: {e}");
    }
}
