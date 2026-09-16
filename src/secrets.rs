//! SECRET-SCANNING FIXTURES. Every value below is randomly generated and fake:
//! it is not tied to any real account. Formats mirror real providers so that
//! regex + entropy based detectors fire.

// Original fixture.
pub const API_KEY: &str = "test-fixture-not-a-real-secret";

// SECRET: AWS access key id + secret access key.
pub const AWS_ACCESS_KEY_ID: &str = "AKIAYD5G4M2JC5KLREOA";
pub const AWS_SECRET_ACCESS_KEY: &str = "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";

// SECRET: GitHub personal access token (classic).
pub const GITHUB_TOKEN: &str = "ghp_09F6lqEHR8LH05H66rfpqwRoQfptO8OqmfNv";

// SECRET: GitLab personal access token.
pub const GITLAB_TOKEN: &str = "glpat-A_O9wgiAiibeoQFAvElf";

// SECRET: Slack bot token and incoming webhook.
pub const SLACK_BOT_TOKEN: &str = "xoxb-611289491057-5530017281142-UKhnz7QkgWhOgjrCI4JTyZDs";
pub const SLACK_WEBHOOK_URL: &str =
    "https://hooks.slack.com/services/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";

// SECRET: Stripe secret key (test-mode format).
pub const STRIPE_SECRET_KEY: &str = "sk_test_IGQCf5mngSK4SK2gMGQ5Y1ja";

// SECRET: Google API key.
pub const GOOGLE_API_KEY: &str = "AIzaPeDVDQrJ8oOVIpAsoAoHdahmP3BfTh35CdN";

// SECRET: SendGrid API key.
pub const SENDGRID_API_KEY: &str =
    "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";

// SECRET: Twilio account SID + API key.
pub const TWILIO_ACCOUNT_SID: &str = "AC1dd646a59245a02f19f3e95f176e2e60";
pub const TWILIO_API_KEY: &str = "SK12bc15779a8a4a524d9b096eeb8dd6a9";

// SECRET: Mailgun API key.
pub const MAILGUN_API_KEY: &str = "key-05fcbd5ea828f80a330026d0d33e200b";

// SECRET: npm automation token.
pub const NPM_TOKEN: &str = "npm_eU8N2cehMEPhip0dfnFpDwfA8JuZqRfv8zG3";

// SECRET: Azure storage connection string with account key.
pub const AZURE_STORAGE_CONNECTION_STRING: &str = "DefaultEndpointsProtocol=https;AccountName=tigergatefixture;AccountKey=6B9GfSgdlfUyAnfF0jVbd3I27wuVRMy7BADKq0x3HNGDgnIvi4ubx+Ki1DaCJlt0XJJ3G1ZG4Y/KWzjU4vBcGA==;EndpointSuffix=core.windows.net";

// SECRET: database connection strings with embedded passwords.
pub const DATABASE_URL: &str = "postgres://app_admin:YD1BE4nRNpELLvMz9Arn@prod-db.tigergate.internal:5432/orders";
pub const MONGODB_URI: &str = "mongodb+srv://root:YD1BE4nRNpELLvMz9Arn@cluster0.tigergate.mongodb.net/admin";
pub const REDIS_URL: &str = "redis://:YD1BE4nRNpELLvMz9Arn@cache.tigergate.internal:6379/0";

// SECRET: JWT signing secret and a token signed with it (HS256).
pub const JWT_SIGNING_SECRET: &str = "m1b299FDaWEEXw4O17EQP8AqotqqWy1FuzTnTX78ObEE9ssL";
pub const ADMIN_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwibmFtZSI6InRpZ2VyZ2F0ZS1hZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc2NzIyNTYwMCwiZXhwIjoxODkzNDU2MDAwfQ.z6FEUfatSgoT9L4A2__6X5RereBXsKNlL5AOxgFlRPE";

// SECRET: generic hard-coded password assignment.
pub const SMTP_PASSWORD: &str = "Sup3rS3cretSmtpP@ssw0rd";

// SECRET: embedded RSA private key (throwaway, generated for this fixture).
pub const TLS_PRIVATE_KEY_PEM: &str = include_str!("../keys/server.key");
