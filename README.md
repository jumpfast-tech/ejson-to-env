# env-to-ejson

A minimal, dependency-light bash tool for managing encrypted environment
variables using RSA public/private key pairs.

**Author:** JumpFast Technologies

---

## Why env-to-ejson?

Managing secrets in configuration files is a common challenge. You want to:

- Store encrypted secrets safely in version control
- Share configuration with your team without exposing sensitive values
- Decrypt secrets at deploy time or runtime

This tool was inspired by [Shopify's EJSON](https://github.com/Shopify/ejson),
which pioneered the concept of asymmetric encryption for config files. We
built `env-to-ejson` as a lightweight alternative that:

- Requires only `bash`, `jq`, and `openssl` (no Go/Ruby runtime)
- Outputs standard `.env` files (compatible with Docker, dotenv, etc.)
- Uses familiar RSA encryption under the hood
- Fits in a single portable shell script

---

## Quick Start

```bash
# 1. Generate a new keypair
./env-to-ejson.sh gen-keys

# 2. Save the private key securely (printed to terminal)
#    Store it in a password manager or secure vault

# 3. Add encrypted secrets
./env-to-ejson.sh encrypt --key DB_PASSWORD --value "super_secret_123"

# 4. Decrypt to .env when needed
export EJ_PRIVATE_KEY="$(cat private.pem)"
./env-to-ejson.sh decrypt
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
# GitHub Actions example
- name: Decrypt secrets
  env:
    EJ_PRIVATE_KEY: ${{ secrets.EJSON_PRIVATE_KEY }}
  run: ./env-to-ejson.sh decrypt
```

### 3. Docker and container deployments

Generate `.env` at container startup:

```dockerfile
COPY env.ejson /app/
COPY env-to-ejson.sh /app/

CMD ["sh", "-c", "./env-to-ejson.sh decrypt && exec myapp"]
```

### 4. Multi-environment configuration

Maintain separate files for each environment:

```bash
# Development
./env-to-ejson.sh decrypt -i dev.ejson -o .env.dev

# Production
./env-to-ejson.sh decrypt -i prod.ejson -o .env.prod
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
./env-to-ejson.sh gen-keys [options]

Options:
  --output-ejson <file>   Output file (default: env.ejson)
  --bits <n>              Key size in bits (default: 2048)
```

### `encrypt`

Add or update an encrypted secret in your ejson file.

```bash
./env-to-ejson.sh encrypt [options]

Options:
  --input, -i <file>      Input ejson file (default: env.ejson)
  --key <name>            Environment variable name (required)
  --value <secret>        Secret value to encrypt
  --value-stdin           Read secret from stdin (recommended for scripts)
```

Reading from stdin avoids secrets in shell history:

```bash
echo "my_secret" | ./env-to-ejson.sh encrypt --key API_KEY --value-stdin
```

### `decrypt`

Decrypt an ejson file to a standard `.env` file.

```bash
./env-to-ejson.sh decrypt [options]

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
./test-env-to-ejson.sh
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
