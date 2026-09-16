# DELIBERATELY INSECURE Dockerfile — IaC / container scanner fixture. Do not use.

# IaC: unpinned "latest"-style tag on the builder.
FROM rust:latest AS builder
WORKDIR /src
COPY . .
RUN cargo build --release

# SCA/SBOM: outdated runtime base image snapshot with known OS package CVEs.
FROM debian:bullseye-20210902

# SECRET + IaC: credentials baked into image layers via ENV/ARG.
ARG GITHUB_TOKEN=ghp_09F6lqEHR8LH05H66rfpqwRoQfptO8OqmfNv
ENV AWS_ACCESS_KEY_ID=AKIAYD5G4M2JC5KLREOA \
    AWS_SECRET_ACCESS_KEY=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 \
    DATABASE_PASSWORD=YD1BE4nRNpELLvMz9Arn

# IaC: apt without --no-install-recommends, unpinned packages, no cache cleanup,
# and 'apt-get upgrade'. Installs sudo and an SSH server.
RUN apt-get update && apt-get upgrade -y && apt-get install -y curl wget sudo openssh-server libssl1.1 ca-certificates

# IaC: ADD from a remote URL and curl piped into a shell.
ADD http://example.com/install-agent.sh /tmp/install-agent.sh
RUN curl -sSL http://example.com/bootstrap.sh | sh || true

# IaC: world-writable application directory.
RUN mkdir -p /app && chmod -R 777 /app

WORKDIR /app
COPY --from=builder /src/target/release/tigergate-test-rust /app/tigergate-test-rust
COPY keys/ /app/keys/
COPY .env /app/.env

# IaC: SSH port exposed.
EXPOSE 22 8080

# IaC: no USER instruction → container runs as root; no HEALTHCHECK.
CMD ["/app/tigergate-test-rust", "serve", "0.0.0.0:8080"]
