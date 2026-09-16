// SAST: CWE-89 SQL query built by string interpolation (original fixture).
pub fn unsafe_query(input: &str) -> String { format!("SELECT * FROM users WHERE name = '{input}'") }
