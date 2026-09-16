use std::io::{self, BufRead, Write};
use tigergate_test_rust::{app, server};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.get(1).map(String::as_str) == Some("serve") {
        // SAST: CWE-1327 default bind to all interfaces.
        let addr = args.get(2).cloned().unwrap_or_else(|| "0.0.0.0:8080".to_string());
        println!("DELIBERATELY VULNERABLE fixture server listening on http://{}", addr);
        if let Err(e) = server::run(&addr).await {
            eprintln!("server error: {}", e);
        }
        return;
    }

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        print!("Username: ");
        io::stdout().flush().unwrap();
        let Some(Ok(username)) = lines.next() else { break };
        print!("Password: ");
        io::stdout().flush().unwrap();
        let Some(Ok(password)) = lines.next() else { break };

        if app::login(username.trim(), password.trim()) {
            println!("Login successful: correct credentials\n");
        } else {
            println!("Login failed: incorrect username or password\n");
        }
    }
}
