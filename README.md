# ejson-to-env

A minimal, dependency-light bash tool for managing encrypted environment
variables using RSA public/private key pairs.

**Author:** JumpFast Technologies

---

## Why ejson-to-env?

Managing secrets in configuration files is a common challenge. You want to:

- Store encrypted secrets safely in version control
- Share configuration with your team without exposing sensitive values
- Decrypt secrets at deploy time or runtime

This tool was inspired by [Shopify's EJSON](https://github.com/Shopify/ejson),
which pioneered the concept of asymmetric encryption for config files. We
built `ejson-to-env` as a lightweight alternative that:

- Requires only `bash`, `jq`, and `openssl` (no Go/Ruby runtime)
- Outputs standard `.env` files (compatible with Docker, dotenv, etc.)
- Uses familiar RSA encryption under the hood
- Fits in a single portable shell script

---

## Installation

### Local / macOS / Linux

```bash
git clone https://github.com/jumpfast-tech/ejson-to-env.git
cd ejson-to-env
make install        # installs to /usr/local/bin/ejson-to-env
```

Custom prefix (e.g. `~/.local/bin`):

```bash
make install PREFIX=~/.local
```

Uninstall:

```bash
make uninstall
```

### One-liner (any Unix system)

Downloads the latest release asset directly — no git clone needed:

```bash
curl -fsSL https://github.com/jumpfast-tech/ejson-to-env/releases/latest/download/ejson-to-env \
  -o /usr/local/bin/ejson-to-env && chmod +x /usr/local/bin/ejson-to-env
```

### GitHub Actions

Use the action directly in any workflow — no install step required:

```yaml
- name: Decrypt secrets
  uses: jumpfast-tech/ejson-to-env@v1
  with:
    private-key: ${{ secrets.EJSON_PRIVATE_KEY }}
    # ejson-file: env.ejson   (default)
    # output-file: .env       (default)
```

The action reads `env.ejson` and writes `.env` in your workspace.

### AWS CodeBuild

Add this to your `buildspec.yml` install phase:

```yaml
phases:
  install:
    commands:
      - curl -fsSL https://github.com/jumpfast-tech/ejson-to-env/releases/latest/download/ejson-to-env
          -o /usr/local/bin/ejson-to-env
      - chmod +x /usr/local/bin/ejson-to-env
  pre_build:
    commands:
      - ejson-to-env decrypt
```

Store the private key in AWS Secrets Manager or Parameter Store and inject it
as an environment variable named `EJ_PRIVATE_KEY`.

### GCP Cloud Build

```yaml
steps:
  - name: alpine
    entrypoint: sh
    args:
      - -c
      - |
        apk add --no-cache curl jq openssl
        curl -fsSL https://github.com/jumpfast-tech/ejson-to-env/releases/latest/download/ejson-to-env \
          -o /usr/local/bin/ejson-to-env
        chmod +x /usr/local/bin/ejson-to-env
        ejson-to-env decrypt
    secretEnv:
      - EJ_PRIVATE_KEY

availableSecrets:
  secretManager:
    - versionName: projects/$PROJECT_ID/secrets/ejson-private-key/versions/latest
      env: EJ_PRIVATE_KEY
```

### Docker

A pre-built image is published to the GitHub Container Registry on every
release:

```bash
# Decrypt env.ejson -> .env in the current directory
docker run --rm \
  -e EJ_PRIVATE_KEY="$(cat private.pem)" \
  -v "$PWD:/work" -w /work \
  ghcr.io/jumpfast-tech/ejson-to-env decrypt
```

Or use it as a base/stage in your own Dockerfile:

```dockerfile
FROM ghcr.io/jumpfast-tech/ejson-to-env:latest AS secrets
COPY env.ejson /work/
RUN ejson-to-env decrypt --input /work/env.ejson --output /work/.env

FROM your-app-image
COPY --from=secrets /work/.env .
```

Available tags: `latest`, `1`, `1.0`, `1.0.0` (semver on each release).

---

## Quick Start

```bash
# 1. Generate a new keypair
ejson-to-env gen-keys

# 2. Save the private key securely (printed to terminal)
#    Store it in a password manager or secure vault

# 3. Add encrypted secrets
ejson-to-env encrypt --key DB_PASSWORD --value "super_secret_123"

# 4. Decrypt to .env when needed
export EJ_PRIVATE_KEY="$(cat private.pem)"
ejson-to-env decrypt
```

---

## Use Cases

### 1. Secure secrets in Git repositories

Store your `env.ejson` file in version control. The public key and encrypted
values are safe to commit. Only holders of the private key can decrypt.

```json
{
  "_public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "DB_PASSWORD": "EJ[1:encrypted_base64_data]",
  "API_KEY": "EJ[1:another_encrypted_value]",
  "DEBUG": "true"
}
```

Plain text values (like `DEBUG`) pass through unchanged.

### 2. CI/CD pipeline integration

In your deployment pipeline, inject the private key as a secret environment
variable:

```yaml
# GitHub Actions — using the published action (recommended)
- name: Decrypt secrets
  uses: jumpfast-tech/ejson-to-env@v1
  with:
    private-key: ${{ secrets.EJSON_PRIVATE_KEY }}
```

### 3. Docker and container deployments

Generate `.env` at container startup using the published image:

```dockerfile
FROM ghcr.io/jumpfast-tech/ejson-to-env:latest AS secrets
COPY env.ejson /work/
RUN ejson-to-env decrypt --input /work/env.ejson --output /work/.env

FROM your-app-image
COPY --from=secrets /work/.env .
CMD ["myapp"]
```

### 4. Multi-environment configuration

Maintain separate files for each environment:

```bash
# Development
ejson-to-env decrypt -i dev.ejson -o .env.dev

# Production
ejson-to-env decrypt -i prod.ejson -o .env.prod
```

### 5. Team secret sharing

1. Generate keys once per environment
2. Share the private key securely with authorized team members
3. Anyone can add new encrypted secrets using just the public key
4. Commit changes to `env.ejson` without exposing values

---

## Commands

### `gen-keys`

Generate a new RSA keypair. The public key is stored in your ejson file; the
private key is printed to the terminal for you to save securely.

```bash
ejson-to-env gen-keys [options]

Options:
  --output-ejson <file>   Output file (default: env.ejson)
  --bits <n>              Key size in bits (default: 2048)
```

### `encrypt`

Add or update an encrypted secret in your ejson file.

```bash
ejson-to-env encrypt [options]

Options:
  --input, -i <file>      Input ejson file (default: env.ejson)
  --key <name>            Environment variable name (required)
  --value <secret>        Secret value to encrypt
  --value-stdin           Read secret from stdin (recommended for scripts)
```

Reading from stdin avoids secrets in shell history:

```bash
echo "my_secret" | ejson-to-env encrypt --key API_KEY --value-stdin
```

### `decrypt`

Decrypt an ejson file to a standard `.env` file.

```bash
ejson-to-env decrypt [options]

Options:
  --input, -i <file>          Input ejson file (default: env.ejson)
  --output, -o <file>         Output .env file (default: .env)
  --private-key-file <file>   Read private key from file
  --save-private-key <file>   Save EJ_PRIVATE_KEY to file (chmod 600)
```

The private key can be provided via:
- `EJ_PRIVATE_KEY` environment variable (recommended)
- `--private-key-file` flag

---

## EJSON File Format

```json
{
  "_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "SECRET_KEY": "EJ[1:base64_encrypted_data]",
  "PLAIN_KEY": "unencrypted values are fine too"
}
```

- `_public_key`: Required. RSA public key in PEM format.
- `EJ[1:...]`: Encrypted values (RSA + base64 encoded).
- Plain strings: Passed through as-is to the output `.env` file.

---

## Requirements

- `bash` (4.0+)
- `jq` (JSON processor)
- `openssl` (for RSA operations)

All three are available on most Unix systems and in CI environments.

---

## Security Notes

- **Never commit private keys.** Store them in a secrets manager, vault, or
  secure environment variable.
- **Rotate keys periodically.** Generate new keypairs and re-encrypt secrets
  as part of your security hygiene.
- **RSA key size:** Default is 2048 bits. Use `--bits 3072` or higher for
  stronger encryption if needed.

---

## Running Tests

A comprehensive test suite is included:

```bash
./test-ejson-to-env.sh
```

---

## Acknowledgments

This project was inspired by the excellent work on
[Shopify/ejson](https://github.com/Shopify/ejson). Their approach to
asymmetric encryption for configuration files shaped our design philosophy.
We're grateful to the Shopify team for pioneering this pattern.

---

## License

BSD 3-Clause License with Attribution. See [LICENSE](LICENSE) for details.

Copyright (c) 2026 JumpFast Technologies
