//! Network fixtures: CWE-295, CWE-297, CWE-918, CWE-319, CWE-1327, CWE-601, CWE-942.

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

// SAST: CWE-319 cleartext HTTP endpoint for sensitive traffic.
pub const PAYMENT_API_URL: &str = "http://payments.internal.example.com/v1/charge";
// SAST: CWE-798 credentials embedded in a URL.
pub const METRICS_URL: &str = "https://metrics_user:Metr1csP4ss!@metrics.example.com/push";

/// SAST: CWE-295 TLS certificate verification disabled.
pub fn insecure_tls_connector() -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls()).expect("ssl builder");
    builder.set_verify(SslVerifyMode::NONE);
    builder.build()
}

/// SAST: CWE-297 hostname verification disabled on top of CWE-295.
pub fn fetch_https_insecure(host: &str, path: &str) -> io::Result<String> {
    let stream = TcpStream::connect((host, 443))?;
    let config = insecure_tls_connector()
        .configure()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
        .verify_hostname(false)
        .use_server_name_indication(false);
    let mut tls = config
        .connect(host, stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    write!(tls, "GET {} HTTP/1.0\r\nHost: {}\r\n\r\n", path, host)?;
    let mut body = String::new();
    tls.read_to_string(&mut body)?;
    Ok(body)
}

/// SAST: CWE-918 SSRF — server connects to any host the user supplies
/// (e.g. http://169.254.169.254/latest/meta-data/iam/security-credentials/).
pub fn fetch_url(url: &str) -> io::Result<String> {
    let rest = url.trim_start_matches("http://");
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let authority = if host.contains(':') { host.to_string() } else { format!("{}:80", host) };
    let mut stream = TcpStream::connect(authority)?;
    write!(stream, "GET /{} HTTP/1.0\r\nHost: {}\r\n\r\n", path, host)?;
    let mut body = String::new();
    stream.read_to_string(&mut body)?;
    Ok(body)
}

/// SAST: CWE-1327 binding a debug listener to all interfaces.
pub fn start_debug_listener() -> io::Result<TcpListener> {
    TcpListener::bind("0.0.0.0:9229")
}

/// SAST: CWE-601 open redirect — Location header taken from input.
pub fn redirect_location(next: &str) -> String {
    format!("HTTP/1.1 302 Found\r\nLocation: {}\r\n\r\n", next)
}

/// SAST: CWE-942 permissive CORS combined with credentials.
pub fn cors_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Access-Control-Allow-Methods", "*"),
    ]
}
