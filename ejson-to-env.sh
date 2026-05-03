#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Minimal EJSON (public/private key) -> .env generator
#
# Commands:
#   1) gen-keys   : generate RSA keypair, write _public_key into env.ejson,
#                   print private key to terminal
#   2) decrypt    : decrypt env.ejson -> .env (default if no command given)
#
# EJSON file format (flat JSON only):
#   {
#     "_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
#     "DB_PASSWORD": "EJ[1:BASE64_RSA_ENCRYPTED_BYTES]",
#     "PLAIN_KEY": "plain text ok"
#   }
#
# Private key input:
#   - EJ_PRIVATE_KEY env var (recommended)
#   - or --private-key-file /path/to/private.pem
#
# Requirements:
#   - bash
#   - jq
#   - openssl
# -----------------------------------------------------------------------------

DEFAULT_INPUT="env.ejson"
DEFAULT_OUTPUT=".env"

INPUT="$DEFAULT_INPUT"
OUTPUT="$DEFAULT_OUTPUT"

PRIVATE_KEY_FILE=""
SAVE_PRIVATE_KEY_FILE=""

# For gen-keys
EJSON_OUT="$DEFAULT_INPUT"
KEY_BITS="2048" # You can change to 3072 if you want stronger (slower) keys

usage() {
  cat <<EOF
Usage:
  $0 [command] [options]

Commands:
  gen-keys            Generate RSA key pair.
                      - Writes _public_key into env.ejson (default)
                      - Prints private key to terminal

  encrypt             Add/replace one encrypted key inside env.ejson, or use
                      --all to encrypt every plain-text value at once
  decrypt             Decrypt env.ejson -> .env (default command)

Options (encrypt):
  --input, -i <file>          Input EJSON file (default: env.ejson)
  --all                       Encrypt every plain-text value in the file at once
  --key <name>                Key to encrypt (single-key mode)
  --value <secret>            Value to encrypt
  --value-stdin               Read value from stdin

Options (decrypt):
  --input, -i <file>          Input EJSON file (default: env.ejson)
  --output, -o <file>         Output .env file (default: .env)
  --private-key-file <file>   Private key PEM file
  --save-private-key <file>   Save EJ_PRIVATE_KEY env var into this file (chmod 600 style)

Options (gen-keys):
  --output-ejson <file>       Where to store the generated _public_key (default: env.ejson)
  --bits <n>                  Key size (default: 2048)

Examples:
  # Generate keys (prints private key; stores public key inside env.ejson)
  ./ejson-to-env.sh gen-keys

  # Decrypt env.ejson -> .env
  EJ_PRIVATE_KEY="\$(cat private.pem)" ./ejson-to-env.sh decrypt

  # Same (default command is decrypt)
  EJ_PRIVATE_KEY="\$(cat private.pem)" ./ejson-to-env.sh

  # Encrypt every plain-text value in the file at once
  ./ejson-to-env.sh encrypt --all

  # Custom input/output
  EJ_PRIVATE_KEY="\$(cat private.pem)" ./ejson-to-env.sh decrypt --input prod.ejson --output .env.prod
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "❌ Missing dependency: $1" >&2; exit 1; }
}

# -------------------------------
# Helper: check wrapper
# -------------------------------
is_ejson_wrapped() {
  [[ "${1:-}" =~ ^EJ\[1:.*\]$ ]]
}

# -------------------------------
# Helper: quote .env values safely
# -------------------------------
quote_env_value() {
  local v="$1"
  v="${v//\\/\\\\}"       # escape backslashes
  v="${v//\"/\\\"}"       # escape quotes
  v="${v//$'\n'/\\n}"     # newlines -> \n (single line)
  printf '"%s"' "$v"
}

# -------------------------------
# Decrypt EJ[1:...] using RSA private key
# -------------------------------
decrypt_ejson_value() {
  local wrapped="$1"

  # Strip EJ[1:...]
  local b64="${wrapped#EJ[1:}"
  b64="${b64%]}"

  # base64 decode -> RSA decrypt
  # NOTE: This expects the ciphertext was created using RSA public-key encryption.
  local decrypted
  decrypted="$(
    printf '%s' "$b64" \
      | openssl base64 -d -A 2>/dev/null \
      | openssl pkeyutl -decrypt -inkey <(printf '%s' "$PRIVATE_KEY_PEM") 2>/dev/null
  )" || true

  [[ -n "$decrypted" ]] || return 1
  printf '%s' "$decrypted"
}

# -----------------------------------------------------------------------------
# COMMAND: gen-keys
# -----------------------------------------------------------------------------
cmd_gen_keys() {
  need_cmd openssl
  need_cmd jq

  local bits="$KEY_BITS"
  local out_ejson="$EJSON_OUT"

  # IMPORTANT:
  # Initialize temp vars to avoid "unbound variable" with set -u
  local tmp_priv=""
  local tmp_pub=""
  local tmp_json=""

  # Cleanup safely even if some files were never created
  cleanup_genkeys() {
    if [[ -n "${tmp_priv:-}" && -f "$tmp_priv" ]]; then rm -f "$tmp_priv"; fi
    if [[ -n "${tmp_pub:-}"  && -f "$tmp_pub"  ]]; then rm -f "$tmp_pub";  fi
    if [[ -n "${tmp_json:-}" && -f "$tmp_json" ]]; then rm -f "$tmp_json"; fi
  }
  trap cleanup_genkeys EXIT

  # Create temp files
  tmp_priv="$(mktemp)"
  tmp_pub="$(mktemp)"
  tmp_json="$(mktemp)"

  # 1) Generate private key
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"$bits" -out "$tmp_priv" >/dev/null 2>&1

  # 2) Derive public key
  openssl pkey -in "$tmp_priv" -pubout -out "$tmp_pub" >/dev/null 2>&1

  local priv_pem pub_pem
  priv_pem="$(cat "$tmp_priv")"
  pub_pem="$(cat "$tmp_pub")"

  # Ensure output file exists and is valid JSON object, or create a new one
  if [[ -f "$out_ejson" ]]; then
    if ! jq -e '.' "$out_ejson" >/dev/null 2>&1; then
      echo "❌ $out_ejson exists but is not valid JSON. Fix or delete it first." >&2
      exit 1
    fi
    if [[ "$(jq -r 'type' "$out_ejson")" != "object" ]]; then
      echo "❌ $out_ejson must contain a JSON object at top-level." >&2
      exit 1
    fi
  else
    echo "{}" > "$out_ejson"
  fi

  # Write/replace _public_key into the ejson file
  jq --arg pk "$pub_pem" '. + { "_public_key": $pk }' "$out_ejson" > "$tmp_json"
  mv "$tmp_json" "$out_ejson"

  echo "✅ Generated RSA keypair ($bits bits)"
  echo "✅ Saved _public_key into: $out_ejson"
  echo
  echo "==================== PRIVATE KEY (KEEP SECRET) ===================="
  cat "$tmp_priv"
  echo "==================================================================="
  echo
  echo "👉 Set it like:"
  echo "   export EJ_PRIVATE_KEY=\"\$(cat private.pem)\""
  echo
}

# -----------------------------------------------------------------------------
# COMMAND: encrypt
# -----------------------------------------------------------------------------
cmd_encrypt() {
  need_cmd jq
  need_cmd openssl

  local key="${ENCRYPT_KEY:-}"
  local value="${ENCRYPT_VALUE:-}"
  local use_stdin="${ENCRYPT_VALUE_STDIN:-false}"
  local encrypt_all="${ENCRYPT_ALL:-false}"

  if [[ ! -f "$INPUT" ]]; then
    echo "❌ Input file not found: $INPUT" >&2
    exit 1
  fi

  local pub_key
  pub_key="$(jq -r '._public_key // empty' "$INPUT")"
  if [[ -z "$pub_key" || "$pub_key" == "null" ]]; then
    echo "❌ Missing _public_key in $INPUT" >&2
    exit 1
  fi

  # ---------------------------
  # --all: encrypt every plain-text value in the file
  # ---------------------------
  if [[ "$encrypt_all" == "true" ]]; then
    local tmp_json=""
    cleanup_encrypt_all() {
      if [[ -n "${tmp_json:-}" && -f "$tmp_json" ]]; then rm -f "$tmp_json"; fi
    }
    trap cleanup_encrypt_all EXIT
    tmp_json="$(mktemp)"

    # Start from the current file; accumulate encrypted keys into it
    cp "$INPUT" "$tmp_json"

    local count=0
    local skipped=0

    while IFS= read -r entry; do
      local k v
      k="$(jq -r '.key' <<<"$entry")"
      v="$(jq -r '.value' <<<"$entry")"

      # Skip _public_key and already-encrypted values
      if [[ "$k" == "_public_key" ]] || is_ejson_wrapped "$v"; then
        skipped=$(( skipped + 1 ))
        continue
      fi

      local enc_b64
      enc_b64="$(
        printf '%s' "$v" \
          | openssl pkeyutl -encrypt -pubin -inkey <(printf '%s' "$pub_key") 2>/dev/null \
          | openssl base64 -A
      )"

      if [[ -z "$enc_b64" ]]; then
        echo "❌ Encryption failed for key '$k'" >&2
        exit 1
      fi

      local next
      next="$(mktemp)"
      jq --arg k "$k" --arg v "EJ[1:$enc_b64]" '.[$k] = $v' "$tmp_json" > "$next"
      mv "$next" "$tmp_json"
      count=$(( count + 1 ))
    done < <(jq -c 'to_entries[]' "$INPUT")

    mv "$tmp_json" "$INPUT"
    echo "✅ Encrypted $count key(s) in $INPUT (skipped $skipped already-encrypted)"
    return
  fi

  # ---------------------------
  # Single-key mode
  # ---------------------------
  if [[ -z "$key" ]]; then
    echo "❌ --key is required (or use --all to encrypt every plain-text value)" >&2
    exit 1
  fi

  if [[ "$use_stdin" == "true" ]]; then
    IFS= read -r value
  fi

  if [[ -z "$value" ]]; then
    echo "❌ Secret value is empty (use --value or --value-stdin)" >&2
    exit 1
  fi

  # Encrypt with public key (RSA) -> base64 -> wrap as EJ[1:...]
  enc_b64="$(
    printf '%s' "$value" \
      | openssl pkeyutl -encrypt -pubin -inkey <(printf '%s' "$pub_key") 2>/dev/null \
      | openssl base64 -A
  )"

  if [[ -z "$enc_b64" ]]; then
    echo "❌ Encryption failed" >&2
    exit 1
  fi

  # Write back to env.ejson atomically
  local tmp_json=""
  cleanup_encrypt() {
    if [[ -n "${tmp_json:-}" && -f "$tmp_json" ]]; then rm -f "$tmp_json"; fi
  }
  trap cleanup_encrypt EXIT
  tmp_json="$(mktemp)"

  jq --arg k "$key" --arg v "EJ[1:$enc_b64]" '. + {($k): $v}' "$INPUT" > "$tmp_json"
  mv "$tmp_json" "$INPUT"

  echo "✅ Added encrypted key '$key' into $INPUT"
}

# -----------------------------------------------------------------------------
# COMMAND: decrypt
# -----------------------------------------------------------------------------
cmd_decrypt() {
  need_cmd jq
  need_cmd openssl

  if [[ ! -f "$INPUT" ]]; then
    echo "❌ Input file not found: $INPUT" >&2
    exit 1
  fi

  # _public_key must exist in input file (your requirement)
  local public_key
  public_key="$(jq -r '._public_key // empty' "$INPUT")"
  if [[ -z "$public_key" || "$public_key" == "null" ]]; then
    echo "❌ Missing required key: _public_key in $INPUT" >&2
    exit 1
  fi

  # Load private key PEM
  PRIVATE_KEY_PEM=""
  if [[ -n "$PRIVATE_KEY_FILE" ]]; then
    [[ -f "$PRIVATE_KEY_FILE" ]] || { echo "❌ Private key file not found: $PRIVATE_KEY_FILE" >&2; exit 1; }
    PRIVATE_KEY_PEM="$(cat "$PRIVATE_KEY_FILE")"
  else
    PRIVATE_KEY_PEM="${EJ_PRIVATE_KEY:-}"
  fi

  if [[ -z "$PRIVATE_KEY_PEM" ]]; then
    echo "❌ Private key not provided." >&2
    echo "   Use EJ_PRIVATE_KEY env var OR --private-key-file." >&2
    exit 1
  fi

  # Optional: save EJ_PRIVATE_KEY into a file
  if [[ -n "$SAVE_PRIVATE_KEY_FILE" ]]; then
    if [[ -z "${EJ_PRIVATE_KEY:-}" ]]; then
      echo "❌ --save-private-key requires EJ_PRIVATE_KEY to be set" >&2
      exit 1
    fi
    mkdir -p "$(dirname "$SAVE_PRIVATE_KEY_FILE")"
    umask 077
    printf "%s\n" "$EJ_PRIVATE_KEY" > "$SAVE_PRIVATE_KEY_FILE"
    echo "✅ Saved private key to: $SAVE_PRIVATE_KEY_FILE"
  fi

  # Write output atomically
  local tmp_out=""
  cleanup_decrypt() {
    if [[ -n "${tmp_out:-}" && -f "$tmp_out" ]]; then rm -f "$tmp_out"; fi
  }
  trap cleanup_decrypt EXIT

  tmp_out="$(mktemp)"

  {
    echo "# Generated from: $INPUT"
    echo "# Do not edit directly. Edit $INPUT instead."
    echo

    jq -c 'to_entries[] | select(.key != "_public_key")' "$INPUT" \
      | while IFS= read -r entry; do
          key="$(jq -r '.key' <<<"$entry")"
          val_type="$(jq -r '.value | type' <<<"$entry")"

          if [[ "$val_type" != "string" ]]; then
            echo "❌ Non-string value for key '$key'. Only string values supported." >&2
            exit 1
          fi

          value="$(jq -r '.value' <<<"$entry")"

          if is_ejson_wrapped "$value"; then
            plain="$(decrypt_ejson_value "$value" || true)"
            if [[ -z "$plain" ]]; then
              echo "❌ Failed to decrypt key '$key' (wrong key or corrupted value)" >&2
              exit 1
            fi
            printf "%s=%s\n" "$key" "$(quote_env_value "$plain")"
          else
            printf "%s=%s\n" "$key" "$(quote_env_value "$value")"
          fi
        done
  } > "$tmp_out"

  mv "$tmp_out" "$OUTPUT"
  echo "✅ Wrote $OUTPUT from $INPUT"
}

# -----------------------------------------------------------------------------
# Entry: detect command + parse args (simple & strict)
# -----------------------------------------------------------------------------
COMMAND="decrypt" # default

if [[ $# -gt 0 ]]; then
  case "$1" in
    gen-keys|encrypt|decrypt)
      COMMAND="$1"
      shift
      ;;
  esac
fi

# Parse remaining args based on command
while [[ $# -gt 0 ]]; do
  case "$COMMAND" in
    encrypt)
      case "$1" in
        --input|-i) INPUT="${2:-}"; shift 2 ;;
        --all) ENCRYPT_ALL="true"; shift 1 ;;
        --key) ENCRYPT_KEY="${2:-}"; shift 2 ;;
        --value) ENCRYPT_VALUE="${2:-}"; shift 2 ;;
        --value-stdin) ENCRYPT_VALUE_STDIN="true"; shift 1 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "❌ Unknown option for encrypt: $1" >&2; usage >&2; exit 1 ;;
      esac
      ;;
    decrypt)
      case "$1" in
        --input|-i) INPUT="${2:-}"; shift 2 ;;
        --output|-o) OUTPUT="${2:-}"; shift 2 ;;
        --private-key-file) PRIVATE_KEY_FILE="${2:-}"; shift 2 ;;
        --save-private-key) SAVE_PRIVATE_KEY_FILE="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "❌ Unknown option for decrypt: $1" >&2; usage >&2; exit 1 ;;
      esac
      ;;
    gen-keys)
      case "$1" in
        --output-ejson) EJSON_OUT="${2:-}"; shift 2 ;;
        --bits) KEY_BITS="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "❌ Unknown option for gen-keys: $1" >&2; usage >&2; exit 1 ;;
      esac
      ;;
  esac
done

case "$COMMAND" in
  gen-keys) cmd_gen_keys ;;
  encrypt)  cmd_encrypt ;;
  decrypt)  cmd_decrypt ;;
  *) echo "❌ Unknown command: $COMMAND" >&2; usage >&2; exit 1 ;;
esac
