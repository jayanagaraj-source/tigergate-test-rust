pub fn unsafe_query(input: &str) -> String { format!("SELECT * FROM users WHERE name = '{input}'") }
