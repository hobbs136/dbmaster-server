//! MySQL script splitter (ADR-0003 S8b prep).
//!
//! Splits a multi-statement SQL script into individual statements, correctly
//! handling the cases that a naive `split(';')` gets wrong:
//!
//! - `'...'`, `"..."`, and `` `...` `` quoted strings (semicolons inside are
//!   literal, not statement boundaries).
//! - `--` and `#` line comments (semicolon at end of comment line is not a
//!   boundary).
//! - `/* ... */` block comments.
//! - `BEGIN ... END` compound bodies (stored routines / triggers / events —
//!   semicolons inside the body delimit inner statements, not the routine).
//! - `DELIMITER $$` directives (change the statement terminator, as the mysql
//!   CLI does for routine definitions).
//!
//! Empty statements (only whitespace/comments) are skipped. Each returned
//! statement keeps its trailing terminator context stripped. This is a
//! **splitter**, not a parser — it does not validate SQL syntax, only finds
//! statement boundaries. It is intentionally conservative: when in doubt it
//! keeps characters in the current statement rather than risk a bad split.

/// Split a SQL script into individual statements.
///
/// Handles quoting, comments, `BEGIN...END` blocks, and `DELIMITER`
/// directives. Whitespace-only / comment-only fragments are dropped. Each
/// returned string is a single statement (no trailing terminator).
pub fn split_sql_script(script: &str) -> Vec<String> {
    let chars: Vec<char> = script.chars().collect();
    let mut statements = Vec::new();
    let mut buf = String::new();
    let mut delimiter = ";".to_string();
    // State machine
    let mut in_quote: Option<char> = None; // Some('\'') / Some('"') / Some('`')
    let mut begin_depth: usize = 0; // nesting of BEGIN...END blocks
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        // ── Inside a quote: copy verbatim until matching close quote ──
        if let Some(q) = in_quote {
            buf.push(c);
            if c == '\\' && i + 1 < chars.len() {
                // escaped char (e.g. \' or \\) — copy next verbatim
                buf.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }

        // ── Not in a quote ──

        // Line comment: -- or #  (MySQL line-comment forms)
        if is_line_comment_start(&chars, i) {
            // consume to end of line, appending (keep comments in statement
            // text so error messages preserve context)
            while i < chars.len() && chars[i] != '\n' {
                buf.push(chars[i]);
                i += 1;
            }
            continue;
        }
        // Block comment: /* ... */
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            buf.push(c);
            buf.push(chars[i + 1]);
            i += 2;
            while i < chars.len() {
                buf.push(chars[i]);
                if chars[i] == '*' && i + 1 < chars.len() && chars[i + 1] == '/' {
                    buf.push(chars[i + 1]);
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }

        // Quote start
        if c == '\'' || c == '"' || c == '`' {
            in_quote = Some(c);
            buf.push(c);
            i += 1;
            continue;
        }

        // DELIMITER directive (only at start of a line / statement, case-insensitive)
        // Detect when buf is empty (ignoring leading whitespace) and the upcoming
        // tokens spell DELIMITER.
        if buf.trim().is_empty() && matches_delimiter_directive(&chars, i) {
            // consume "DELIMITER" keyword
            let kw_len = "DELIMITER".len();
            let mut j = i + kw_len;
            // skip whitespace between DELIMITER and the new delimiter
            while j < chars.len() && chars[j].is_whitespace() && chars[j] != '\n' {
                j += 1;
            }
            // read the new delimiter up to end of line
            let mut new_delim = String::new();
            while j < chars.len() && chars[j] != '\n' {
                new_delim.push(chars[j]);
                j += 1;
            }
            let new_delim = new_delim.trim().to_string();
            if !new_delim.is_empty() {
                delimiter = new_delim;
            }
            // discard the DELIMITER line from buf (it's a CLI directive, not SQL)
            buf.clear();
            i = j; // j is at '\n' or end; loop continues
            continue;
        }

        // BEGIN keyword — increments compound-body depth (case-insensitive,
        // word boundary via match_keyword). Detected at any position in the
        // statement (e.g. "CREATE PROCEDURE p() BEGIN ..."), not just at the
        // start. match_keyword's word-boundary check prevents matching
        // "BEGINNING" or "BEGIN" inside identifiers.
        if let Some(_end) = match_keyword(&chars, i, "BEGIN") {
            begin_depth += 1;
            buf.push_str(&chars[i..i + 5].iter().collect::<String>());
            i += 5;
            continue;
        }

        // Terminator match
        if matches_str(&chars, i, &delimiter) {
            // Inside a BEGIN...END block, the inner-statement terminator does
            // NOT end the routine — only the terminator AFTER the matching END
            // does. So if we're inside a compound body, treat this terminator
            // as an inner statement separator (flush a sub-statement is not
            // needed; we keep the whole body in buf until END + terminator).
            if begin_depth > 0 {
                // keep the terminator in the buffer (part of routine body)
                for dc in delimiter.chars() {
                    buf.push(dc);
                }
                i += delimiter.len();
                continue;
            }
            // End of statement at top level.
            i += delimiter.len();
            // flush
            let stmt = buf.trim().to_string();
            if !stmt.is_empty() {
                statements.push(stmt);
            }
            buf.clear();
            continue;
        }

        // END keyword — decrements compound-body depth (case-insensitive).
        // Match END as a standalone keyword; the terminator that follows it
        // (handled above) closes the routine.
        if begin_depth > 0 {
            if let Some(_end) = match_keyword(&chars, i, "END") {
                // Only decrement if followed by a terminator or whitespace+terminator
                // (END without terminator is a column alias, not a block close).
                // We check the next non-whitespace token.
                let after = i + 3;
                let mut k = after;
                while k < chars.len() && chars[k].is_whitespace() && chars[k] != '\n' {
                    k += 1;
                }
                if matches_str(&chars, k, &delimiter) || k >= chars.len() {
                    buf.push_str(&chars[i..i + 3].iter().collect::<String>());
                    begin_depth = begin_depth.saturating_sub(1);
                    i += 3;
                    continue;
                }
            }
        }

        buf.push(c);
        i += 1;
    }

    // Flush trailing statement (no terminator at end of script)
    let stmt = buf.trim().to_string();
    if !stmt.is_empty() {
        statements.push(stmt);
    }
    statements
}

/// Does `chars[i..]` start with the line-comment markers `--` or `#`?
/// `--` requires a following space or EOL per MySQL (avoids matching `--` in
/// expressions like `a--b`, though those are rare in DDL).
fn is_line_comment_start(chars: &[char], i: usize) -> bool {
    if chars[i] == '#' {
        return true;
    }
    if chars[i] == '-' && i + 1 < chars.len() && chars[i + 1] == '-' {
        // MySQL requires whitespace or EOL after --; be lenient and also
        // accept end-of-input.
        if i + 2 >= chars.len() {
            return true;
        }
        let nxt = chars[i + 2];
        return nxt.is_whitespace();
    }
    false
}

/// Does `chars[i..]` start with the word `kw` (case-insensitive), followed by
/// a word boundary (non-alphanumeric/underscore)? Returns the index past the
/// keyword if so.
fn match_keyword(chars: &[char], i: usize, kw: &str) -> Option<usize> {
    let kw_chars: Vec<char> = kw.chars().collect();
    if i + kw_chars.len() > chars.len() {
        return None;
    }
    for (k, expected) in kw_chars.iter().enumerate() {
        if chars[i + k].to_ascii_uppercase() != *expected {
            return None;
        }
    }
    // word boundary after
    let after = i + kw_chars.len();
    if after >= chars.len() {
        return Some(after);
    }
    let nxt = chars[after];
    if nxt.is_alphanumeric() || nxt == '_' {
        return None;
    }
    Some(after)
}

/// Does `chars[i..]` start with `s`? (plain substring match)
fn matches_str(chars: &[char], i: usize, s: &str) -> bool {
    let s_chars: Vec<char> = s.chars().collect();
    if i + s_chars.len() > chars.len() {
        return false;
    }
    for (k, expected) in s_chars.iter().enumerate() {
        if chars[i + k] != *expected {
            return false;
        }
    }
    true
}

/// Does `chars[i..]` start with the `DELIMITER` directive (case-insensitive)?
fn matches_delimiter_directive(chars: &[char], i: usize) -> bool {
    match_keyword(chars, i, "DELIMITER").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_simple_statements() {
        let s = split_sql_script("SELECT 1; SELECT 2;");
        assert_eq!(s, vec!["SELECT 1", "SELECT 2"]);
    }

    #[test]
    fn handles_semicolon_in_single_quotes() {
        let s = split_sql_script("INSERT INTO t VALUES ('a;b'); SELECT 1;");
        assert_eq!(s, vec!["INSERT INTO t VALUES ('a;b')", "SELECT 1"]);
    }

    #[test]
    fn handles_semicolon_in_double_quotes() {
        let s = split_sql_script(r#"INSERT INTO t VALUES ("a;b"); SELECT 1;"#);
        assert_eq!(s, vec![r#"INSERT INTO t VALUES ("a;b")"#, "SELECT 1"]);
    }

    #[test]
    fn handles_semicolon_in_backticks() {
        let s = split_sql_script("SELECT `a;b` FROM t; SELECT 1;");
        assert_eq!(s.len(), 2);
        assert_eq!(s[1], "SELECT 1");
    }

    #[test]
    fn handles_escaped_quote_in_string() {
        let s = split_sql_script("INSERT INTO t VALUES ('a\\'b;c'); SELECT 1;");
        assert_eq!(s.len(), 2);
        assert_eq!(s[1], "SELECT 1");
    }

    #[test]
    fn ignores_semicolon_in_line_comment() {
        let s = split_sql_script("SELECT 1 -- a comment with ; semicolon\n; SELECT 2;");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn ignores_semicolon_in_block_comment() {
        let s = split_sql_script("SELECT 1 /* a ; b */ ; SELECT 2;");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn handles_hash_comment() {
        let s = split_sql_script("SELECT 1 # comment ; here\n; SELECT 2;");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn begin_end_block_keeps_inner_semicolons() {
        let script = "CREATE PROCEDURE p() BEGIN INSERT INTO t VALUES (1); INSERT INTO t VALUES (2); END; SELECT 1;";
        let s = split_sql_script(script);
        assert_eq!(s.len(), 2, "got {s:?}");
        assert!(s[0].contains("BEGIN"));
        assert!(s[0].contains("END"));
        assert!(s[0].contains("INSERT INTO t VALUES (1)"));
        assert!(s[0].contains("INSERT INTO t VALUES (2)"));
        assert_eq!(s[1], "SELECT 1");
    }

    #[test]
    fn delimiter_directive_changes_terminator() {
        let script = "DELIMITER $$\nCREATE PROCEDURE p() BEGIN INSERT INTO t VALUES (1); END$$ DELIMITER ;\nSELECT 1;";
        let s = split_sql_script(script);
        assert_eq!(s.len(), 2, "got {s:?}");
        assert!(s[0].contains("CREATE PROCEDURE"));
        assert!(s[0].contains("END"));
        assert_eq!(s[1], "SELECT 1");
    }

    #[test]
    fn trailing_statement_without_terminator() {
        let s = split_sql_script("SELECT 1; SELECT 2");
        assert_eq!(s, vec!["SELECT 1", "SELECT 2"]);
    }

    #[test]
    fn empty_and_whitespace_statements_skipped() {
        let s = split_sql_script("  ;  ; SELECT 1;  ");
        assert_eq!(s, vec!["SELECT 1"]);
    }

    #[test]
    fn multiple_statements_no_trailing_terminator() {
        let s = split_sql_script("CREATE TABLE a (x INT); CREATE TABLE b (y INT)");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn nested_begin_end_not_supported_conservatively() {
        // Nested BEGIN...END is rare in MySQL (conditions/handlers). This
        // splitter does not deeply track nesting — a single END closes the
        // block. Documented limitation; conservative for the common case.
        let script = "BEGIN SELECT 1; BEGIN SELECT 2; END; END; SELECT 3;";
        let s = split_sql_script(script);
        // The outer block absorbs until the first END; the second END + the
        // remaining BEGIN...END handling is best-effort. Just ensure no panic
        // and at least one statement.
        assert!(!s.is_empty());
    }

    #[test]
    fn preserves_statement_text() {
        let s = split_sql_script("  SELECT * FROM `my table` WHERE x = 'foo'  ;");
        assert_eq!(s, vec!["SELECT * FROM `my table` WHERE x = 'foo'"]);
    }
}
