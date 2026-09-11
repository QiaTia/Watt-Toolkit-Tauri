//! HTML 脚本注入（对齐 HttpReverseProxyMiddleware.HandleScriptInject）。
//!
//! 流程：解压（gzip/deflate/br）→ 编码探测（BOM/charset）→ 定位插入点 →
//! 插入 `<script src="/WattToolkit_Inject/{lid}.js">` → 重压缩。

use std::io::Read;

/// 内容编码类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCompression {
    Gzip,
    Deflate,
    Brotli,
    None,
}

impl ContentCompression {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => ContentCompression::Gzip,
            "deflate" => ContentCompression::Deflate,
            "br" => ContentCompression::Brotli,
            _ => ContentCompression::None,
        }
    }
}

/// 解压响应体（对齐 GetStreamByContentCompression Decompress）
pub fn decompress(data: &[u8], compression: ContentCompression) -> Result<Vec<u8>, String> {
    match compression {
        ContentCompression::None => Ok(data.to_vec()),
        ContentCompression::Gzip => {
            let mut decoder = flate2::read::MultiGzDecoder::new(data);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| format!("gzip 解压失败: {e}"))?;
            Ok(out)
        }
        ContentCompression::Deflate => {
            let mut decoder = flate2::read::DeflateDecoder::new(data);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| format!("deflate 解压失败: {e}"))?;
            Ok(out)
        }
        ContentCompression::Brotli => {
            let mut decoder = brotli::Decompressor::new(data, 4096);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| format!("br 解压失败: {e}"))?;
            Ok(out)
        }
    }
}

/// 重压缩响应体（对齐 GetStreamByContentCompression Compress）
pub fn compress(data: &[u8], compression: ContentCompression) -> Result<Vec<u8>, String> {
    match compression {
        ContentCompression::None => Ok(data.to_vec()),
        ContentCompression::Gzip => {
            use std::io::Write;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder
                .write_all(data)
                .map_err(|e| format!("gzip 压缩失败: {e}"))?;
            encoder.finish().map_err(|e| format!("gzip 压缩失败: {e}"))
        }
        ContentCompression::Deflate => {
            use std::io::Write;
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder
                .write_all(data)
                .map_err(|e| format!("deflate 压缩失败: {e}"))?;
            encoder
                .finish()
                .map_err(|e| format!("deflate 压缩失败: {e}"))
        }
        ContentCompression::Brotli => {
            let mut out = Vec::new();
            let mut params = brotli::enc::BrotliEncoderParams::default();
            params.quality = 5;
            brotli::BrotliCompress(&mut &data[..], &mut out, &params)
                .map_err(|e| format!("br 压缩失败: {e:?}"))?;
            Ok(out)
        }
    }
}

/// 检测字符编码（对齐 TryDetectEncoding：BOM 探测）
fn detect_encoding_bom(data: &[u8]) -> Option<&'static str> {
    if data.len() >= 2 {
        let first2 = ((data[0] as u16) << 8) | data[1] as u16;
        match first2 {
            0xEFBB => {
                if data.len() >= 3 && data[2] == 0xBF {
                    return Some("utf-8");
                }
            }
            0xFFFE => return Some("utf-16le"), // UTF32/Unicode 同前缀，取 UTF16
            0xFEFF => return Some("utf-16be"),
            _ => {}
        }
    }
    None
}

/// 从 Content-Type charset 解析编码
fn charset_from_content_type(content_type: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    for part in lower.split(';').skip(1) {
        let part = part.trim();
        if let Some(cs) = part.strip_prefix("charset=") {
            return Some(cs.trim_matches('"').trim_matches('\'').to_string());
        }
    }
    None
}

/// 判断是否为 GitHub 域（对齐 IsGithubHost）
pub fn is_github_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("github.com") || host.to_ascii_lowercase().ends_with(".github.com")
}

/// 定位注入位置（对齐 FindScriptInjectInsertPosition）：
/// 倒序扫描 `</BODY>` 或 `</HEAD>`（大小写不敏感），返回 `</` 起始位置
pub fn find_inject_position(buffer: &[u8]) -> Option<usize> {
    // 匹配末尾 ">"，再匹配开头 "</"，中间标签名恰好 4 字符且为 BODY/HEAD
    let len = buffer.len();
    if len == 0 {
        return None;
    }
    let mut i = len - 1;
    // index_name_end: 最近一个 '>' 的位置（含）
    let mut index_name_end: Option<usize> = None;
    let mut match_start_idx = 0usize; // 已匹配 "</" 的字节数

    loop {
        let item = buffer[i];
        match index_name_end {
            None => {
                if item == b'>' {
                    index_name_end = Some(i);
                }
            }
            Some(name_end) => {
                // 匹配 "</"：先匹配 '/'（match_start_idx=0），再匹配 '<'（=1）
                let expected = if match_start_idx == 0 { b'/' } else { b'<' };
                if item == expected {
                    match_start_idx += 1;
                    if match_start_idx >= 2 {
                        let index_name_start = i + 2;
                        if name_end > index_name_start {
                            let bytes = &buffer[index_name_start..name_end];
                            if bytes.len() == 4 {
                                let name = std::str::from_utf8(bytes)
                                    .map(|s| {
                                        s.eq_ignore_ascii_case("BODY")
                                            || s.eq_ignore_ascii_case("HEAD")
                                    })
                                    .unwrap_or(false);
                                if name {
                                    return Some(i);
                                }
                            }
                        }
                        // 重置继续向前找
                        match_start_idx = 0;
                        index_name_end = None;
                    }
                } else if item == b'>' {
                    // 更新最近的 '>' 位置，继续匹配 "</"
                    index_name_end = Some(i);
                    match_start_idx = 0;
                } else if item != b'<' && match_start_idx > 0 {
                    match_start_idx = 0;
                }
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    None
}

/// 定位注入位置（GitHub 分支：最后一个带 src 的 <script> 标签前）
pub fn find_inject_position_github(buffer: &[u8]) -> Option<usize> {
    let mark: &[u8] = b"<script";
    let mut last_script_with_src_start: Option<usize> = None;
    if buffer.len() >= mark.len() {
        let mut i = 0;
        while i + mark.len() <= buffer.len() {
            if !equals_ascii_ignore_case(&buffer[i..i + mark.len()], mark) {
                i += 1;
                continue;
            }
            let after_mark = i + mark.len();
            // 下一字符必须是空白或 '>'（属性名边界）
            if after_mark < buffer.len() && is_html_attribute_name_char(buffer[after_mark]) {
                i += 1;
                continue;
            }
            // 找到标签结束 '>'
            let rest = &buffer[after_mark..];
            let tag_end_offset = rest.iter().position(|&b| b == b'>').unwrap_or(rest.len());
            if tag_end_offset >= rest.len() {
                break;
            }
            let tag_end_index = after_mark + tag_end_offset;
            let script_tag = &buffer[i..tag_end_index + 1];
            if script_tag_has_src_attribute(script_tag) {
                last_script_with_src_start = Some(i);
            }
            i = tag_end_index + 1;
        }
    }
    if let Some(pos) = last_script_with_src_start {
        return Some(pos);
    }
    find_inject_position(buffer)
}

fn script_tag_has_src_attribute(tag: &[u8]) -> bool {
    let src: &[u8] = b"src";
    if tag.len() < src.len() {
        return false;
    }
    for i in 0..=tag.len() - src.len() {
        if !equals_ascii_ignore_case(&tag[i..i + src.len()], src) {
            continue;
        }
        if i > 0 && is_html_attribute_name_char(tag[i - 1]) {
            continue;
        }
        let mut j = i + src.len();
        while j < tag.len() && is_ascii_whitespace(tag[j]) {
            j += 1;
        }
        if j < tag.len() && tag[j] == b'=' {
            return true;
        }
    }
    false
}

fn equals_ascii_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(a, b)| to_upper_ascii(*a) == to_upper_ascii(*b))
}

fn to_upper_ascii(v: u8) -> u8 {
    if v.is_ascii_lowercase() {
        v - 32
    } else {
        v
    }
}

fn is_ascii_whitespace(v: u8) -> bool {
    matches!(v, b' ' | b'\t' | b'\r' | b'\n' | 0x0C)
}

fn is_html_attribute_name_char(v: u8) -> bool {
    v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_' | b':' | b'.')
}

/// 注入结果
pub struct InjectResult {
    pub body: Vec<u8>,
    /// 使用的 Content-Encoding（None = 移除头）
    pub compression: ContentCompression,
}

/// 注入脚本标签（对齐 WriteAsync：`<script type="text/javascript" src="/WattToolkit_Inject/{lid}.js"></script>`）
///
/// `content_type` 用于编码选择；`scripts` 为脚本 local_id 列表。
pub fn inject_scripts(
    body: &[u8],
    content_encoding: &str,
    content_type: &str,
    scripts: &[String],
    host: &str,
) -> Result<InjectResult, String> {
    let compression = ContentCompression::parse(content_encoding);
    let decompressed = decompress(body, compression)?;

    // 编码探测：charset 优先，其次 BOM，兜底 UTF-8（注入内容为纯 ASCII，无需转码）
    let _charset = charset_from_content_type(content_type)
        .or_else(|| detect_encoding_bom(&decompressed).map(|s| s.to_string()))
        .unwrap_or_else(|| "utf-8".to_string());

    let is_github = is_github_host(host);
    let position = if is_github {
        find_inject_position_github(&decompressed)
    } else {
        find_inject_position(&decompressed)
    };

    let Some(position) = position else {
        return Err("未找到注入位置".into());
    };

    // 构建注入内容（ASCII 域 + local_id 均为 ASCII，无需编码转换）
    let mut injected = Vec::with_capacity(decompressed.len() + 256);
    injected.extend_from_slice(&decompressed[..position]);
    for lid in scripts {
        injected.extend_from_slice(
            format!(
                "<script type=\"text/javascript\" src=\"/WattToolkit_Inject/{lid}.js\"></script>"
            )
            .as_bytes(),
        );
    }
    injected.extend_from_slice(&decompressed[position..]);

    // 重压缩（原实现：无压缩则移除 Content-Encoding 头）
    let result_body = compress(&injected, compression)?;
    Ok(InjectResult {
        body: result_body,
        compression,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_inject_position_body() {
        let html = b"<html><head></head><body>hello</body></html>";
        // </body> 的 '<' 位置
        let pos = find_inject_position(html).unwrap();
        assert_eq!(&html[pos..pos + 7], b"</body>");
    }

    #[test]
    fn test_find_inject_position_head() {
        // 无 </body> 时回退到 </head>（对齐 C# 倒序扫描：BODY 优先于 HEAD）
        let html = b"<html><head>abc</head></html>";
        let pos = find_inject_position(html).unwrap();
        assert_eq!(&html[pos..pos + 7], b"</head>");
    }

    #[test]
    fn test_find_inject_position_case_insensitive() {
        let html = b"<html><Body>x</Body></html>";
        let pos = find_inject_position(html).unwrap();
        assert_eq!(&html[pos..pos + 7], b"</Body>");
    }

    #[test]
    fn test_find_inject_position_none() {
        assert!(find_inject_position(b"plain text").is_none());
        assert!(find_inject_position(b"<div></div>").is_none());
    }

    #[test]
    fn test_find_inject_position_github() {
        let html = b"<html><head><script src=\"a.js\"></script></head><body></body></html>";
        let pos = find_inject_position_github(html).unwrap();
        assert_eq!(&html[pos..pos + 7], b"<script");
    }

    #[test]
    fn test_inject_plain() {
        let html = b"<html><body>hi</body></html>";
        let result = inject_scripts(
            html,
            "",
            "text/html; charset=utf-8",
            &["123".to_string()],
            "steamcommunity.com",
        )
        .unwrap();
        assert!(result.compression == ContentCompression::None);
        let text = String::from_utf8(result.body).unwrap();
        assert!(text.contains(
            "<script type=\"text/javascript\" src=\"/WattToolkit_Inject/123.js\"></script>"
        ));
        assert!(text.contains("hi"));
    }

    #[test]
    fn test_inject_gzip() {
        let html = b"<html><body>compressed</body></html>";
        let gz = compress(html, ContentCompression::Gzip).unwrap();
        let result =
            inject_scripts(&gz, "gzip", "text/html", &["42".to_string()], "example.com").unwrap();
        assert_eq!(result.compression, ContentCompression::Gzip);
        let plain = decompress(&result.body, ContentCompression::Gzip).unwrap();
        let text = String::from_utf8(plain).unwrap();
        assert!(text.contains("/WattToolkit_Inject/42.js"));
    }

    #[test]
    fn test_compression_parse() {
        assert_eq!(ContentCompression::parse("gzip"), ContentCompression::Gzip);
        assert_eq!(ContentCompression::parse("GZIP"), ContentCompression::Gzip);
        assert_eq!(ContentCompression::parse("br"), ContentCompression::Brotli);
        assert_eq!(
            ContentCompression::parse("deflate"),
            ContentCompression::Deflate
        );
        assert_eq!(ContentCompression::parse(""), ContentCompression::None);
    }

    #[test]
    fn test_is_github_host() {
        assert!(is_github_host("github.com"));
        assert!(is_github_host("GITHUB.COM"));
        assert!(is_github_host("gist.github.com"));
        assert!(!is_github_host("gitlab.com"));
    }
}
