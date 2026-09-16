# Deliberately insecure test fixtures

This repository is for validating **SCA, SAST, secret, IaC and SBOM** scanners (e.g. TigerGate).
It deliberately contains outdated dependencies, unsafe code patterns, fake hard-coded
credentials and insecure infrastructure settings. **Do not deploy or reuse these patterns.**

All credentials are randomly generated fakes (or throwaway keys generated only for this repo)
and are not connected to any real account.

Use this file as the answer key: run the scanner, then check each section below.
The "Baseline" columns are what the reference open-source tools reported locally
(Trivy 0.68.1, Syft 1.51.1, Semgrep OSS `p/rust p/secrets p/github-actions p/dockerfile`).
A good commercial scanner should find at least the baseline, and ideally the gaps too.

---

## 1. SCA — vulnerable dependencies (`Cargo.toml` / `Cargo.lock`)

| Crate | Version | Advisory / CVE | Reachable from |
|---|---|---|---|
| time | 0.1.43 | RUSTSEC-2020-0071 / CVE-2020-26235 | `sast::misc::legacy_timestamp` |
| chrono | 0.4.19 | RUSTSEC-2020-0159 (no CVE) | `sast::misc::local_timestamp` |
| smallvec | 0.6.13 | RUSTSEC-2021-0003 / CVE-2021-25900 (CRITICAL) | `sast::memory::merge_tags` |
| regex | 1.5.4 | RUSTSEC-2022-0013 / CVE-2022-24713 | `sast::injection::user_regex_match` |
| tokio | 1.8.0 | CVE-2021-45710, CVE-2021-38191, CVE-2023-22466 | `main.rs`, `server.rs` |
| hyper | 0.14.9 | CVE-2021-32714, CVE-2021-32715, GHSA-f67m-9j94-qv9j | `server.rs` |
| mio (transitive) | 0.7.14 | CVE-2024-27308 | via tokio |
| tar | 0.4.35 | RUSTSEC-2021-0080 / CVE-2021-38511 | `sast::filesystem::extract_archive` |
| base64 | 0.5.1 | RUSTSEC-2017-0004 / CVE-2017-1000430 (CRITICAL) | `sast::misc::decode_base64` |
| libsqlite3-sys (via rusqlite 0.25.4) | 0.22.2 | RUSTSEC-2022-0090 / CVE-2022-35737 | `sast::injection::*` |
| openssl | 0.10.45 | CVE-2023-53159, CVE-2025-24898, GHSA-xphf-cx8h-7q9g, … | `sast::crypto`, `sast::network` |

Other SCA targets: `terraform/versions.tf` pins `hashicorp/aws` 3.0.0; `docker-compose.yml`
uses `postgres:9.6` and `redis:5.0.0`; `Dockerfile` uses `debian:bullseye-20210902`
(OS package CVEs appear when the **built image** is scanned).

**Baseline (Trivy):** 33 vulnerabilities in 11 packages. Gap: chrono RUSTSEC-2020-0159 is not reported.

## 2. SAST — insecure code (`src/`)

Every sink is tagged in the source with `// SAST: CWE-xxx`. `src/server.rs` wires HTTP
query parameters (sources) into these sinks so taint-tracking engines have real data flows.

| File | Weaknesses |
|---|---|
| `src/app.rs` | CWE-798 hard-coded credentials, CWE-208 timing compare, CWE-532 password logged, CWE-328/759 unsalted MD5 |
| `src/vulnerable.rs` | CWE-89 SQL built with `format!` |
| `src/sast/injection.rs` | CWE-89 SQLi (×3, rusqlite), CWE-78 command injection (`sh -c`, `bash -c`, user-chosen program), CWE-79 XSS (×2), CWE-117 log injection, CWE-1333 regex from input, LDAP filter injection |
| `src/sast/crypto.rs` | CWE-328 MD5 & SHA-1 passwords, CWE-327 AES-ECB & 3DES, CWE-321 hard-coded keys, CWE-329 static IV, CWE-326 512-bit RSA, CWE-330/338 time-seeded RNG tokens, CWE-208 |
| `src/sast/filesystem.rs` | CWE-22 path traversal (×2) & zip-slip, CWE-73, CWE-377 predictable temp file, CWE-732 `0o777` perms, CWE-367 TOCTOU |
| `src/sast/memory.rs` | `unsafe`: CWE-125 `get_unchecked`, CWE-119 `from_raw_parts`, CWE-457 `set_len`, CWE-416 use-after-free, CWE-704 `transmute` lifetime, `from_utf8_unchecked`, CWE-843 `ptr::read` type confusion, unsound `unsafe impl Send/Sync`, `static mut`, `mem::forget` |
| `src/sast/network.rs` | CWE-295 `SslVerifyMode::NONE`, CWE-297 hostname verification off, CWE-918 SSRF, CWE-319 cleartext HTTP, credentials in URL, CWE-1327 bind `0.0.0.0`, CWE-601 open redirect, CWE-942 CORS `*` + credentials |
| `src/sast/misc.rs` | CWE-807 `env::args`/`current_exe`, CWE-377 `temp_dir`, CWE-190 wrapping overflow, CWE-197 truncation, CWE-789 unbounded alloc, CWE-248 panic on input, CWE-502/915 mass assignment, CWE-209 error leakage, CWE-676 raw FFI `getenv` |
| `src/server.rs` | Taint flows: `/ping`→command injection, `/user`→SQLi, `/greet`→XSS, `/file`→path traversal, `/fetch`→SSRF, `/redirect`→open redirect, `/debug/env`→env var disclosure |

**Baseline (Semgrep OSS):** 16 Rust findings — `unsafe-usage` ×9, `args` ×2, `current-exe`,
`temp-dir` ×2, `insecure-hashes`, credentials in URI. Gap: OSS Rust rules have no taint rules,
so SQLi / command injection / XSS / SSRF / path traversal / TLS-verify-off are **not** found.
These are the key cases for judging a scanner's Rust SAST.

## 3. Secrets

| Location | Planted secrets |
|---|---|
| `src/secrets.rs` | AWS key pair, GitHub PAT, GitLab PAT, Slack bot token + webhook, Stripe key, Google API key, SendGrid, Twilio SID + key, Mailgun, npm token, Azure storage connection string, Postgres/MongoDB/Redis URLs with passwords, JWT secret + signed JWT, SMTP password, embedded private key (`include_str!`) |
| `src/app.rs`, `src/sast/network.rs`, `src/sast/crypto.rs` | hard-coded admin password, URL credentials, AES/3DES keys |
| `.env` | AWS pair, DB URL, GitHub PAT, Slack webhook, Stripe, SendGrid, JWT secret, admin password |
| `.npmrc` | npm auth token |
| `config/application.yml` | DB/SMTP passwords, GitLab, Google, Twilio, Mailgun, Azure |
| `config/gcp-service-account.json` | GCP service account with private key |
| `config/docker-config.json` | Docker Hub base64 auth, registry password |
| `keys/id_rsa`, `keys/server.key` | RSA private keys (PKCS#1 and PKCS#8) |
| `kubernetes/secret.yaml`, `kubernetes/deployment.yaml` | base64 Secret data, GitHub PAT, Stripe, AWS secret in env |
| `Dockerfile`, `docker-compose.yml`, `.github/workflows/insecure-ci.yml` | AWS pair / GitHub PAT / DB passwords in ENV/ARG/env |
| `terraform/main.tf`, `compute.tf`, `database.tf`, `secrets.tf`; `cloudformation/insecure-stack.yaml` | provider static keys, user_data keys, RDS passwords, AWS example key |

**Baseline:** Trivy 32 findings in 12 files; Semgrep adds `.npmrc`, Mailgun, Twilio,
`src/secrets.rs` AWS key id, Slack webhook, TF RDS passwords. Neither baseline tool reported
the Google API key, Azure key, DB connection strings or `config/docker-config.json`.

## 4. IaC — misconfigurations

| File | Highlights |
|---|---|
| `terraform/insecure.tf` | public-read-write S3 + public policy, no encryption/versioning/logging, unencrypted EBS/SQS/SNS, KMS rotation off, DynamoDB no PITR |
| `terraform/network.tf` | SSH/RDP/all ports open to `0.0.0.0/0`, open egress, allow-all NACL, public subnet, internet-facing ALB with HTTP listener, no flow logs |
| `terraform/iam.tf` | `*:*` policy, AdministratorAccess on a user, role assumable by `*`, weak password policy |
| `terraform/compute.tf` | IMDSv1, unencrypted root volume, secrets in user_data, mutable ECR without scan, public EKS endpoint without logging |
| `terraform/database.tf` | public unencrypted RDS without backups/deletion protection, unencrypted Aurora/ElastiCache/Elasticsearch |
| `terraform/logging.tf` | single-region CloudTrail without validation/KMS, CloudFront allowing HTTP + TLSv1 |
| `cloudformation/insecure-stack.yaml` | public S3, open SG, public unencrypted RDS, unencrypted EBS, `*:*` policy, weak CloudTrail |
| `kubernetes/deployment.yaml` | privileged, root, hostNetwork/PID/IPC, hostPath `/`, docker.sock, SYS_ADMIN, no limits, `:latest` |
| `kubernetes/rbac.yaml` | wildcard ClusterRole, secrets read, pods/exec, `system:anonymous` bound to cluster-admin |
| `kubernetes/service.yaml`, `secret.yaml` | public LoadBalancer incl. SSH, HTTP-only Ingress, Secret committed to git |
| `Dockerfile` | `:latest`, root user, no HEALTHCHECK, ADD from URL, `curl \| sh`, secrets in ENV/ARG, apt upgrade, `chmod 777`, EXPOSE 22 |
| `docker-compose.yml` | privileged, host network/PID, cap_add ALL, seccomp off, docker.sock and `/` mounted, DB trust auth |
| `.github/workflows/insecure-ci.yml` | `permissions: write-all`, unpinned actions, script injection, `curl \| bash`, secrets in env |

**Baseline (Trivy):** 151 failed checks — Dockerfile 9, CloudFormation 25, K8s deployment 30,
K8s RBAC 5, Terraform 82 (compute 16, database 16, iam 7, insecure 18, logging 8, network 17).
Gaps: Trivy does not scan `docker-compose.yml` or GitHub workflows (Semgrep found
4 workflow issues); `kubernetes/service.yaml` produced no Trivy findings.

## 5. SBOM

Expected components from `Cargo.lock`: **97 cargo packages** (including every vulnerable pin
above, and both `smallvec` 0.6.13 and 1.16.1), plus GitHub Actions references
(`actions/checkout@v4`, `actions/checkout@master`, …). Check that the SBOM records exact
versions and purls (`pkg:cargo/time@0.1.43`), keeps both smallvec versions, and that
SBOM-based vulnerability matching agrees with section 1.

**Baseline (Syft CycloneDX):** 105 components — 97 cargo, 4 GitHub Actions, 3 files, 1 other.

---

## Running locally

```bash
cargo test                                  # 7 tests
cargo run                                   # interactive login (admin / password123)
cargo run -- serve 127.0.0.1:8080           # vulnerable HTTP server (keep it on localhost)

trivy fs --scanners vuln,secret,misconfig --skip-dirs target .
syft dir:. --exclude ./target -o cyclonedx-json
```
