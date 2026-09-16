//! tigergate-test-rust: a DELIBERATELY VULNERABLE crate for validating SCA, SAST,
//! secret, IaC and SBOM scanners. Every insecure pattern is intentional and is
//! tagged with a `// SAST:` / `// SECRET:` comment naming the expected finding.
//! Nothing here is safe to deploy or copy into real code.

pub mod app;
pub mod sast;
pub mod secrets;
pub mod server;
pub mod vulnerable;
