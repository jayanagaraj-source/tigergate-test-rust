//! Injection fixtures: CWE-78, CWE-89, CWE-79, CWE-117, CWE-1333, CWE-943.

use regex::Regex;
use rusqlite::Connection;
use std::process::{Command, Output};

/// SAST: CWE-89 SQL injection (format! into a prepared statement text).
pub fn find_user_email(conn: &Connection, username: &str) -> rusqlite::Result<Vec<String>> {
    let sql = format!("SELECT email FROM users WHERE username = '{}'", username);
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect()
}

/// SAST: CWE-89 SQL injection (string concatenation into execute_batch).
pub fn delete_user(conn: &Connection, id: &str) -> rusqlite::Result<()> {
    conn.execute_batch(&("DELETE FROM users WHERE id = ".to_owned() + id))
}

/// SAST: CWE-89 SQL injection (ORDER BY clause built from input).
pub fn list_users_sorted(conn: &Connection, sort_column: &str) -> rusqlite::Result<usize> {
    let query = "SELECT id, username FROM users ORDER BY ".to_string() + sort_column;
    conn.execute(&query, [])
}

/// SAST: CWE-78 OS command injection via `sh -c`.
pub fn ping_host(host: &str) -> std::io::Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 1 {}", host))
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// SAST: CWE-78 command injection — attacker chooses the program to execute.
pub fn run_user_command(program: &str, args: &[String]) -> std::io::Result<Output> {
    Command::new(program).args(args).output()
}

/// SAST: CWE-78 command injection via `bash -c` with a user-supplied archive name.
pub fn backup_directory(dir: &str) -> std::io::Result<Output> {
    let cmd = "tar czf /tmp/backup.tgz ".to_owned() + dir;
    Command::new("bash").args(["-c", &cmd]).output()
}

/// SAST: CWE-79 reflected XSS — unescaped input rendered into HTML.
pub fn render_greeting(name: &str) -> String {
    format!("<html><body><h1>Hello, {}!</h1></body></html>", name)
}

/// SAST: CWE-79 stored XSS — comment body inserted into markup without encoding.
pub fn render_comment(author: &str, body: &str) -> String {
    let mut html = String::from("<div class=\"comment\">");
    html.push_str(&format!("<b>{}</b><p>{}</p>", author, body));
    html.push_str("</div>");
    html
}

/// SAST: CWE-117 log injection — CR/LF in input forges log lines.
pub fn log_search(term: &str) {
    println!("INFO search performed term={}", term);
}

/// SAST: CWE-1333 / CWE-625 regex built from untrusted input (ReDoS, RUSTSEC-2022-0013 reachable).
pub fn user_regex_match(pattern: &str, haystack: &str) -> bool {
    Regex::new(pattern).map(|re| re.is_match(haystack)).unwrap_or(false)
}

/// SAST: CWE-943 NoSQL/LDAP-style filter injection.
pub fn build_ldap_filter(username: &str) -> String {
    format!("(&(objectClass=person)(uid={}))", username)
}
