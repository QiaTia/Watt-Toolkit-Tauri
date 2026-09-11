//! 标记块算法核心（对齐 HostsFileServiceImpl.HandleHosts 逐行语义）。

use crate::{BACKUP_MARK_END, BACKUP_MARK_START, MARK_END, MARK_START};
use std::collections::HashSet;

/// 有序 Map（保持插入顺序，upsert 保位更新——对齐 C# Dictionary 语义）
struct OrderedMap<V> {
    entries: Vec<(String, V)>,
}

impl<V> OrderedMap<V> {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn upsert(&mut self, key: &str, value: V) {
        if let Some(e) = self.entries.iter_mut().find(|(k, _)| k == key) {
            e.1 = value;
        } else {
            self.entries.push((key.to_string(), value));
        }
    }

    fn contains_key(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    fn get(&self, key: &str) -> Option<&V> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn remove(&mut self, key: &str) {
        self.entries.retain(|(k, _)| k != key);
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn iter(&self) -> impl Iterator<Item = &(String, V)> {
        self.entries.iter()
    }
}

/// 行分类结果（对齐 HandleLineResult）
#[derive(Debug, PartialEq)]
enum LineResult {
    /// 格式不正确，不处理直接写入
    WriteAsIs,
    /// 格式正确，开始处理
    Handle,
    /// 格式不正确，不处理也不写入（标记行/备份行/V1 行）
    Skip,
    /// 重复项（仍进入处理，但对齐原语义）
    Duplicate,
}

/// 标记识别（对齐 GetMarkValue）
fn mark_value(split: &[&str]) -> Option<&'static str> {
    if split.len() == 3 {
        let joined = split.join(" ");
        if joined.eq_ignore_ascii_case(MARK_START) {
            return Some(MARK_START);
        }
        if joined.eq_ignore_ascii_case(MARK_END) {
            return Some(MARK_END);
        }
    } else if split.len() == 4 {
        let joined = split.join(" ");
        if joined.eq_ignore_ascii_case(BACKUP_MARK_START) {
            return Some(BACKUP_MARK_START);
        }
        if joined.eq_ignore_ascii_case(BACKUP_MARK_END) {
            return Some(BACKUP_MARK_END);
        }
    }
    None
}

/// V1 格式：`ip domain #Steam++`
fn is_v1_format(split: &[&str]) -> bool {
    split.len() == 3 && split[2] == "#Steam++"
}

/// 核心算法：处理 hosts 内容，返回新内容。
///
/// - `is_update_or_remove=true` + hosts：更新/新增记录（标记块内 IP 替换为 hosts 值）
/// - `is_update_or_remove=false` + Some(hosts)：删除指定域名记录
/// - `is_update_or_remove=false` + None：按标记移除全部（还原备份）
pub fn handle_hosts(
    content: &str,
    is_update_or_remove: bool,
    hosts: Option<&[(String, String)]>,
    newline: &str,
) -> Result<String, crate::HostsError> {
    let hosts_map: Option<OrderedMap<String>> = hosts.map(|h| {
        let mut m = OrderedMap::new();
        for (domain, ip) in h {
            m.upsert(domain, ip.clone());
        }
        m
    });
    let has_hosts = hosts_map.is_some();

    let mut output = String::new();
    let mut seen_marks: HashSet<&'static str> = HashSet::new();
    // 标记块内数据（domain → ip）
    let mut insert_mark_datas: OrderedMap<String> = OrderedMap::new();
    // 标记块外命中的已有行（domain → (输出行号, 原始行)）
    let mut backup_insert_mark_datas: OrderedMap<(usize, String)> = OrderedMap::new();
    // 备份块数据（domain → (原行号, 原始行)）
    let mut backup_datas: OrderedMap<(usize, String)> = OrderedMap::new();
    // 域名唯一性检查
    let mut domains: HashSet<String> = HashSet::new();
    // 最近一次写入输出的行（用于 MarkStart 前的空行移除）
    let mut last_line_value: Option<String> = None;

    // line_num 对齐原实现：自增于行首，跳过时回退——即输出行计数
    let mut line_num: usize = 0;

    for raw_line in content.split_inclusive('\n') {
        let line_value = raw_line.trim_end_matches(['\r', '\n']);
        line_num += 1;

        let split: Vec<&str> = line_value.split_whitespace().collect();

        // —— 备份块内 ——
        if seen_marks.contains(BACKUP_MARK_START) && !seen_marks.contains(BACKUP_MARK_END) {
            // #{line_num} {line_value}
            if split.len() >= 2 && split[0].starts_with('#') {
                if let Ok(bak_line_num) = split[0].trim_start_matches('#').parse::<usize>() {
                    let rest: Vec<&str> = split[1..].to_vec();
                    if rest.len() >= 2 {
                        let domain = rest[1].to_string();
                        let line = rest.join(" ");
                        if !backup_datas.contains_key(&domain) {
                            backup_datas.entries.push((domain, (bak_line_num, line)));
                        }
                    }
                }
            }
            // 备份块行一律不写入（对齐 return null）
            line_num -= 1;
            continue;
        }

        // —— 标记行识别 ——
        if let Some(mark) = mark_value(&split) {
            if mark == MARK_END && !seen_marks.contains(MARK_START) {
                line_num -= 1;
                continue;
            }
            if mark == BACKUP_MARK_END && !seen_marks.contains(BACKUP_MARK_START) {
                line_num -= 1;
                continue;
            }
            if (mark == MARK_START || mark == BACKUP_MARK_START) && last_line_value.is_some() {
                // 标记前若是空白行，移除（原实现：Remove last_line_value + newline）
                if last_line_value
                    .as_deref()
                    .is_some_and(|s| s.chars().all(char::is_whitespace))
                {
                    let remove_len =
                        last_line_value.as_deref().map(str::len).unwrap_or(0) + newline.len();
                    let new_len = output.len().saturating_sub(remove_len);
                    output.truncate(new_len);
                }
            }
            if !seen_marks.insert(mark) {
                return Err(crate::HostsError::MarkDuplicate(mark.to_string()));
            }
            line_num -= 1;
            continue;
        }

        // —— 普通行基础校验 ——
        let result = if split.len() < 2 {
            LineResult::WriteAsIs
        } else if split[0].starts_with('#') {
            LineResult::WriteAsIs
        } else if split.len() > 2 && !split[2].starts_with('#') {
            LineResult::WriteAsIs
        } else if is_v1_format(&split) {
            LineResult::Skip
        } else if domains.contains(split[1]) {
            LineResult::Duplicate
        } else {
            domains.insert(split[1].to_string());
            LineResult::Handle
        };

        if result == LineResult::Skip {
            line_num -= 1;
            continue;
        }
        if result == LineResult::WriteAsIs {
            output.push_str(line_value);
            output.push_str(newline);
            last_line_value = Some(line_value.to_string());
            continue;
        }

        // —— 有效行处理（Handle / Duplicate 均进入） ——
        let ip = split[0];
        let domain = split[1];
        let match_domain = has_hosts && hosts_map.as_ref().unwrap().contains_key(domain);

        if seen_marks.contains(MARK_START) && !seen_marks.contains(MARK_END) {
            // 标记区域内
            let ip_value = if match_domain {
                if is_update_or_remove {
                    hosts_map.as_ref().unwrap().get(domain).cloned()
                } else {
                    // 删除：跳过不写入
                    line_num -= 1;
                    continue;
                }
            } else {
                Some(ip.to_string())
            };
            if let Some(ip_value) = ip_value {
                insert_mark_datas.upsert(domain, ip_value);
            }
            line_num -= 1;
            continue;
        } else if match_domain {
            // 标记区域外命中
            if is_update_or_remove {
                insert_mark_datas.upsert(domain, ip.to_string());
            }
            backup_insert_mark_datas.upsert(domain, (line_num, line_value.to_string()));
            line_num -= 1;
            continue;
        }

        // 未命中：原样写入
        output.push_str(line_value);
        output.push_str(newline);
        last_line_value = Some(line_value.to_string());
    }

    // —— 合并新数据 ——
    if is_update_or_remove {
        if let Some(hm) = &hosts_map {
            for (domain, ip) in hm.iter() {
                insert_mark_datas.upsert(domain, ip.clone());
            }
        }
    }

    let is_restore = !has_hosts && !is_update_or_remove;

    // 在输出中按行号插入（对齐 Restore + GetLineIndex）
    // 返回 true 表示找到位置插入，false 表示追加到末尾
    fn insert_line_at(output: &mut String, line_idx_zero_based: usize, line: &str, newline: &str) {
        // 计算第 N 行起始字符位置
        let mut current_line = 0usize;
        let mut pos = None;
        let bytes: Vec<(usize, char)> = output.char_indices().collect();
        for &(i, c) in &bytes {
            if current_line == line_idx_zero_based {
                pos = Some(i);
                break;
            }
            if c == '\n' {
                current_line += 1;
            }
        }
        // 行号等于行数（插入到末尾位置）
        if pos.is_none() && current_line == line_idx_zero_based {
            pos = Some(output.len());
        }
        match pos {
            Some(p) => output.insert_str(p, &format!("{line}{newline}")),
            None => {
                output.push_str(line);
                output.push_str(newline);
            }
        }
    }

    if is_restore {
        // 还原全部备份数据
        let items: Vec<(String, (usize, String))> = backup_datas.entries.clone();
        for (domain, (line_idx, line)) in items {
            insert_line_at(&mut output, line_idx.saturating_sub(1), &line, newline);
            backup_datas.remove(&domain);
        }
    } else {
        // 恢复未被接管的备份数据
        let any_insert = !insert_mark_datas.is_empty();
        let to_restore: Vec<(String, (usize, String))> = backup_datas
            .iter()
            .filter(|(k, _)| !any_insert || !insert_mark_datas.contains_key(k))
            .cloned()
            .collect();
        for (domain, (line_idx, line)) in to_restore {
            insert_line_at(&mut output, line_idx.saturating_sub(1), &line, newline);
            backup_datas.remove(&domain);
        }

        // 写入标记块
        if any_insert {
            output.push_str(newline);
            output.push_str(MARK_START);
            output.push_str(newline);
            for (domain, ip) in insert_mark_datas.iter() {
                output.push_str(&format!("{ip} {domain}"));
                output.push_str(newline);
            }
            output.push_str(MARK_END);
            output.push_str(newline);
        }

        // 计算备份块内容
        let any_backup_insert = !backup_insert_mark_datas.is_empty();
        let mut insert_or_remove: Vec<(String, (usize, String))> = if any_insert {
            backup_datas
                .iter()
                .filter(|(k, _)| insert_mark_datas.contains_key(k))
                .cloned()
                .collect()
        } else {
            backup_datas.entries.clone()
        };
        if any_backup_insert {
            insert_or_remove.retain(|(k, _)| !backup_insert_mark_datas.contains_key(k));
        }

        if any_backup_insert || !insert_or_remove.is_empty() {
            output.push_str(newline);
            output.push_str(BACKUP_MARK_START);
            output.push_str(newline);
            if any_backup_insert {
                for (_, (line_idx, line)) in backup_insert_mark_datas.iter() {
                    output.push_str(&format!("#{line_idx} {line}"));
                    output.push_str(newline);
                }
            }
            for (_, (_, line)) in &insert_or_remove {
                output.push_str(line);
                output.push_str(newline);
            }
            output.push_str(BACKUP_MARK_END);
            output.push_str(newline);
        }
    }

    Ok(output)
}

/// 读取全部有效记录（域名→IP，重复以后行为准——对齐 ReadHostsAllLines）
pub fn read_hosts_all_lines(content: &str) -> Vec<(String, String)> {
    let mut result: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let split: Vec<&str> = line.split_whitespace().collect();
        if split.len() < 2 {
            continue;
        }
        if split[0].starts_with('#') {
            continue;
        }
        if split.len() > 2 && !split[2].starts_with('#') {
            continue;
        }
        if is_v1_format(&split) {
            continue;
        }
        let domain = split[1].to_string();
        let ip = split[0].to_string();
        if let Some(entry) = result.iter_mut().find(|(d, _)| *d == domain) {
            entry.1 = ip;
        } else {
            result.push((domain, ip));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str, update: bool, hosts: Option<&[(String, String)]>) -> String {
        handle_hosts(content, update, hosts, "\r\n").unwrap()
    }

    #[test]
    fn test_update_creates_mark_block() {
        let content = "127.0.0.1 localhost\r\n";
        let out = run(
            content,
            true,
            Some(&[("steamcommunity.com".into(), "127.0.0.1".into())]),
        );
        assert!(out.contains("127.0.0.1 localhost"));
        assert!(out.contains("# Steam++ Start"));
        assert!(out.contains("127.0.0.1 steamcommunity.com"));
        assert!(out.contains("# Steam++ End"));
        assert!(!out.contains("# Steam++ Backup Start"));
    }

    #[test]
    fn test_existing_line_moves_to_backup() {
        let content = "1.1.1.1 old.com\r\n\r\n";
        let out = run(
            content,
            true,
            Some(&[("old.com".into(), "127.0.0.1".into())]),
        );
        // 原行从正文移除，进备份块 #1 格式
        assert!(!out.contains("1.1.1.1 old.com\r\n127"));
        assert!(out.contains("# Steam++ Backup Start"));
        assert!(out.contains("#1 1.1.1.1 old.com"));
        assert!(out.contains("127.0.0.1 old.com"));
    }

    #[test]
    fn test_remove_by_tag_restores_backup() {
        let content = "1.1.1.1 old.com\r\n\r\n# Steam++ Start\r\n127.0.0.1 old.com\r\n# Steam++ End\r\n\r\n# Steam++ Backup Start\r\n#1 1.1.1.1 old.com\r\n# Steam++ Backup End\r\n";
        let out = run(content, false, None);
        assert!(!out.contains("# Steam++ Start"));
        assert!(!out.contains("# Steam++ Backup Start"));
        assert!(out.contains("1.1.1.1 old.com"));
    }

    #[test]
    fn test_update_replaces_ip_in_mark_block() {
        let content = "# Steam++ Start\r\n127.0.0.1 old.com\r\n# Steam++ End\r\n";
        let out = run(
            content,
            true,
            Some(&[("old.com".into(), "192.168.1.1".into())]),
        );
        assert!(out.contains("192.168.1.1 old.com"));
        assert!(!out.contains("127.0.0.1 old.com"));
    }

    #[test]
    fn test_v1_format_removed() {
        let content = "127.0.0.1 v1.com #Steam++\r\n";
        let out = run(
            content,
            true,
            Some(&[("new.com".into(), "127.0.0.1".into())]),
        );
        assert!(!out.contains("#Steam++"));
        assert!(!out.contains("v1.com"));
    }

    #[test]
    fn test_duplicate_mark_error() {
        let content = "# Steam++ Start\r\n# Steam++ Start\r\n";
        let result = handle_hosts(content, false, None, "\r\n");
        assert!(matches!(result, Err(crate::HostsError::MarkDuplicate(_))));
    }

    #[test]
    fn test_remove_specific_domain() {
        let content =
            "# Steam++ Start\r\n127.0.0.1 keep.com\r\n127.0.0.1 drop.com\r\n# Steam++ End\r\n";
        let out = run(content, false, Some(&[("drop.com".into(), String::new())]));
        assert!(out.contains("127.0.0.1 keep.com"));
        assert!(!out.contains("drop.com"));
    }

    #[test]
    fn test_read_all_lines() {
        let content = "127.0.0.1 a.com\r\n# comment\r\n1.1.1.1 b.com # tag\r\n2.2.2.2 a.com\r\nbad line\r\n127.0.0.1 c.com #Steam++\r\n";
        let result = read_hosts_all_lines(content);
        // a.com 重复取后值
        assert!(result.contains(&("a.com".into(), "2.2.2.2".into())));
        assert!(result.contains(&("b.com".into(), "1.1.1.1".into())));
        // 两列即视为有效行（对齐 C#，不校验 IP 格式）
        assert!(result.contains(&("line".into(), "bad".into())));
        // V1 行不读
        assert!(!result.iter().any(|(d, _)| d == "c.com"));
        assert_eq!(result.len(), 3);
    }
}
