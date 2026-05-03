#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Minimal EJSON -> .env generator supporting two encryption modes:
#
#   RSA mode  (asymmetric, recommended for teams)
#     _public_key stored in the ejson file; private key kept secret.
#     Wrapped values: EJ[1:BASE64_RSA_OAEP_ENCRYPTED]
#
#   Passphrase mode  (symmetric, good for solo / simple deployments)
#     Shared passphrase via EP_PASSPHRASE env var or --passphrase-file.
#     Wrapped values: EP[1:BASE64_AES256CBC_PBKDF2_ENCRYPTED]
#     No gen-keys step needed.
#
# Commands:
#   gen-keys  : generate RSA keypair (RSA mode only)
#   encrypt   : add/replace encrypted key(s)
#   decrypt   : decrypt ejson -> .env (default)
#
# Requirements: bash, jq, openssl
# -----------------------------------------------------------------------------

DEFAULT_INPUT="env.ejson"
DEFAULT_OUTPUT=".env"

INPUT="$DEFAULT_INPUT"
OUTPUT="$DEFAULT_OUTPUT"

# RSA mode
PRIVATE_KEY_FILE=""
SAVE_PRIVATE_KEY_FILE=""
PRIVATE_KEY_PEM=""

# Passphrase mode
PASSPHRASE_FILE=""
PASSPHRASE=""

# gen-keys
EJSON_OUT="$DEFAULT_INPUT"
KEY_BITS="2048"

# encrypt
ENCRYPT_KEY=""
ENCRYPT_VALUE=""
ENCRYPT_VALUE_STDIN="false"
ENCRYPT_ALL="false"

usage() {
  cat <<EOF
Usage:
  $0 [command] [options]

Commands:
  gen-keys            Generate RSA key pair (RSA mode only).
                      Writes _public_key into env.ejson, prints private key.

  encrypt             Add/replace encrypted key(s) in an ejson file.
                      RSA mode   : requires _public_key in the file.
                      Passphrase : set EP_PASSPHRASE or --passphrase-file.

  decrypt             Decrypt env.ejson -> .env  (default command).
                      Auto-detects EJ[1:...] (RSA) and EP[1:...] (passphrase)
                      values; a file may contain both.

Options (encrypt):
  --input, -i <file>          Input ejson file (default: env.ejson)
  --all                       Encrypt every plain-text value at once
  --key <name>                Key to encrypt (single-key mode)
  --value <secret>            Value to encrypt
  --value-stdin               Read value from stdin (keeps secret out of history)
  --passphrase-file <file>    Read passphrase from file (passphrase mode)

Options (decrypt):
  --input, -i <file>          Input ejson file (default: env.ejson)
  --output, -o <file>         Output .env file (default: .env)
  --private-key-file <file>   RSA private key PEM file
  --save-private-key <file>   Save EJ_PRIVATE_KEY env var to file (chmod 600)
  --passphrase-file <file>    Read passphrase from file (passphrase mode)

Options (gen-keys):
  --output-ejson <file>       Where to write _public_key (default: env.ejson)
  --bits <n>                  RSA key size (default: 2048)

Environment variables:
  EJ_PRIVATE_KEY    RSA private key PEM (decrypt / RSA mode)
  EP_PASSPHRASE     Passphrase for AES-256-CBC encryption / decryption

Examples:
  # --- RSA mode ---
  ./ejson-to-env.sh gen-keys
  ./ejson-to-env.sh encrypt --key DB_PASSWORD --value "secret"
  EJ_PRIVATE_KEY="\$(cat private.pem)" ./ejson-to-env.sh decrypt

  # --- Passphrase mode ---
  EP_PASSPHRASE="my-passphrase" ./ejson-to-env.sh encrypt --key DB_PASSWORD --value "secret"
  EP_PASSPHRASE="my-passphrase" ./ejson-to-env.sh decrypt

  # --- Encrypt all plain-text values at once ---
  EP_PASSPHRASE="my-passphrase" ./ejson-to-env.sh encrypt --all

  # --- Custom input/output ---
  EJ_PRIVATE_KEY="\$(cat private.pem)" ./ejson-to-env.sh decrypt --input prod.ejson --output .env.prod
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "❌ Missing dependency: $1" >&2; exit 1; }
}

# -----------------------------------------------------------------------
# Wrapper detection helpers
# -----------------------------------------------------------------------
is_ejson_wrapped() {
  [[ "${1:-}" =~ ^EJ\[1:.*\]$ ]]
}

is_passphrase_wrapped() {
  [[ "${1:-}" =~ ^EP\[1:.*\]$ ]]
}

is_encrypted() {
  is_ejson_wrapped "$1" || is_passphrase_wrapped "$1"
}

# -----------------------------------------------------------------------
# .env value quoting
# -----------------------------------------------------------------------
quote_env_value() {
  local v="$1"
  v="${v//\\/\\\\}"
  v="${v//\"/\\\"}"
  v="${v//$'\n'/\\n}"
  printf '"%s"' "$v"
}

# -----------------------------------------------------------------------
# RSA-OAEP decrypt  (EJ[1:...])
# -----------------------------------------------------------------------
decrypt_ejson_value() {
  local wrapped="$1"
  local b64="${wrapped#EJ[1:}"
  b64="${b64%]}"

  local decrypted
  if ! decrypted="$(
    printf '%s' "$b64" \
      | openssl base64 -d -A 2>/dev/null \
      | openssl pkeyutl -decrypt \
          -inkey <(printf '%s' "$PRIVATE_KEY_PEM") \
          -pkeyopt rsa_padding_mode:oaep 2>/dev/null
  )"; then
    return 1
  fi

  [[ -n "$decrypted" ]] || return 1
  printf '%s' "$decrypted"
}

# -----------------------------------------------------------------------
# Passphrase encrypt  -> EP[1:BASE64]
#
# Scheme: AES-256-CBC, PBKDF2-SHA256 (310 000 iterations), random salt.
# A 4-byte magic prefix "EJPP" is prepended to the plaintext so that
# decryption with the wrong passphrase can be detected reliably.
# -----------------------------------------------------------------------
encrypt_passphrase_value() {
  local value="$1"
  local enc_b64
  enc_b64="$(
    printf '%s' "EJPP${value}" \
      | openssl enc -aes-256-cbc -pbkdf2 -iter 310000 \
          -pass file:<(printf '%s' "$PASSPHRASE") \
      | openssl base64 -A
  )"
  [[ -n "$enc_b64" ]] || return 1
  printf 'EP[1:%s]' "$enc_b64"
}

# -----------------------------------------------------------------------
# Passphrase decrypt  (EP[1:...])
# -----------------------------------------------------------------------
decrypt_passphrase_value() {
  local wrapped="$1"
  local b64="${wrapped#EP[1:}"
  b64="${b64%]}"

  local decrypted
  if ! decrypted="$(
    printf '%s' "$b64" \
      | openssl base64 -d -A \
      | openssl enc -d -aes-256-cbc -pbkdf2 -iter 310000 \
          -pass file:<(printf '%s' "$PASSPHRASE") 2>/dev/null
  )"; then
    return 1
  fi

  # Verify magic prefix — catches wrong passphrase producing garbage
  if [[ "${decrypted:0:4}" != "EJPP" ]]; then
    return 1
  fi

  printf '%s' "${decrypted:4}"
}

# -----------------------------------------------------------------------
# Load passphrase from file or env var into $PASSPHRASE
# -----------------------------------------------------------------------
load_passphrase() {
  if [[ -n "$PASSPHRASE_FILE" ]]; then
    [[ -f "$PASSPHRASE_FILE" ]] || { echo "❌ Passphrase file not found: $PASSPHRASE_FILE" >&2; exit 1; }
    PASSPHRASE="$(cat "$PASSPHRASE_FILE")"
  else
    PASSPHRASE="${EP_PASSPHRASE:-}"
  fi
}

# -----------------------------------------------------------------------
# COMMAND: gen-keys
# -----------------------------------------------------------------------
cmd_gen_keys() {
  need_cmd openssl
  need_cmd jq

  local bits="$KEY_BITS"
  local out_ejson="$EJSON_OUT"
  local tmp_priv="" tmp_pub="" tmp_json=""

  cleanup_genkeys() {
    if [[ -n "${tmp_priv:-}" && -f "$tmp_priv" ]]; then rm -f "$tmp_priv"; fi
    if [[ -n "${tmp_pub:-}"  && -f "$tmp_pub"  ]]; then rm -f "$tmp_pub";  fi
    if [[ -n "${tmp_json:-}" && -f "$tmp_json" ]]; then rm -f "$tmp_json"; fi
  }
  trap cleanup_genkeys EXIT

  tmp_priv="$(mktemp)"
  tmp_pub="$(mktemp)"
  tmp_json="$(mktemp)"

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"$bits" -out "$tmp_priv" >/dev/null 2>&1
  openssl pkey -in "$tmp_priv" -pubout -out "$tmp_pub" >/dev/null 2>&1

  local priv_pem pub_pem
  priv_pem="$(cat "$tmp_priv")"
  pub_pem="$(cat "$tmp_pub")"

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

# -----------------------------------------------------------------------
# COMMAND: encrypt
# -----------------------------------------------------------------------
cmd_encrypt() {
  need_cmd jq
  need_cmd openssl

  if [[ ! -f "$INPUT" ]]; then
    echo "❌ Input file not found: $INPUT" >&2
    exit 1
  fi

  # Determine encryption mode
  load_passphrase
  local passphrase_mode="false"
  if [[ -n "$PASSPHRASE" ]]; then
    passphrase_mode="true"
  fi

  # RSA mode: need _public_key in the file
  local pub_key=""
  if [[ "$passphrase_mode" == "false" ]]; then
    pub_key="$(jq -r '._public_key // empty' "$INPUT")"
    if [[ -z "$pub_key" || "$pub_key" == "null" ]]; then
      echo "❌ Missing _public_key in $INPUT" >&2
      echo "   Provide a passphrase (EP_PASSPHRASE / --passphrase-file) for passphrase mode," >&2
      echo "   or run 'gen-keys' to create an RSA keypair." >&2
      exit 1
    fi
  fi

  # Helper: encrypt one value to its wrapped form
  _encrypt_value() {
    local v="$1"
    if [[ "$passphrase_mode" == "true" ]]; then
      encrypt_passphrase_value "$v"
    else
      local b64
      b64="$(
        printf '%s' "$v" \
          | openssl pkeyutl -encrypt -pubin \
              -inkey <(printf '%s' "$pub_key") \
              -pkeyopt rsa_padding_mode:oaep 2>/dev/null \
          | openssl base64 -A
      )"
      [[ -n "$b64" ]] || return 1
      printf 'EJ[1:%s]' "$b64"
    fi
  }

  # --all mode: encrypt every plain-text value in the file
  if [[ "$ENCRYPT_ALL" == "true" ]]; then
    local tmp_json=""
    cleanup_encrypt_all() {
      if [[ -n "${tmp_json:-}" && -f "$tmp_json" ]]; then rm -f "$tmp_json"; fi
    }
    trap cleanup_encrypt_all EXIT
    tmp_json="$(mktemp)"
    cp "$INPUT" "$tmp_json"

    local count=0 skipped=0

    while IFS= read -r entry; do
      local k v
      k="$(jq -r '.key'   <<<"$entry")"
      v="$(jq -r '.value' <<<"$entry")"

      if [[ "$k" == "_public_key" ]] || is_encrypted "$v"; then
        skipped=$(( skipped + 1 ))
        continue
      fi

      local wrapped
      if ! wrapped="$(_encrypt_value "$v")"; then
        echo "❌ Encryption failed for key '$k'" >&2
        exit 1
      fi

      local next
      next="$(mktemp)"
      jq --arg k "$k" --arg v "$wrapped" '.[$k] = $v' "$tmp_json" > "$next"
      mv "$next" "$tmp_json"
      count=$(( count + 1 ))
    done < <(jq -c 'to_entries[]' "$INPUT")

    mv "$tmp_json" "$INPUT"
    echo "✅ Encrypted $count key(s) in $INPUT (skipped $skipped already-encrypted)"
    return
  fi

  # Single-key mode
  local key="${ENCRYPT_KEY:-}"
  local value="${ENCRYPT_VALUE:-}"

  if [[ -z "$key" ]]; then
    echo "❌ --key is required (or use --all to encrypt every plain-text value)" >&2
    exit 1
  fi

  if [[ "${ENCRYPT_VALUE_STDIN:-false}" == "true" ]]; then
    IFS= read -r value
  fi

  if [[ -z "$value" ]]; then
    echo "❌ Secret value is empty (use --value or --value-stdin)" >&2
    exit 1
  fi

  local wrapped
  if ! wrapped="$(_encrypt_value "$value")"; then
    echo "❌ Encryption failed" >&2
    exit 1
  fi

  local tmp_json=""
  cleanup_encrypt() {
    if [[ -n "${tmp_json:-}" && -f "$tmp_json" ]]; then rm -f "$tmp_json"; fi
  }
  trap cleanup_encrypt EXIT
  tmp_json="$(mktemp)"

  jq --arg k "$key" --arg v "$wrapped" '. + {($k): $v}' "$INPUT" > "$tmp_json"
  mv "$tmp_json" "$INPUT"

  echo "✅ Added encrypted key '$key' into $INPUT"
}

# -----------------------------------------------------------------------
# COMMAND: decrypt
# -----------------------------------------------------------------------
cmd_decrypt() {
  need_cmd jq
  need_cmd openssl

  if [[ ! -f "$INPUT" ]]; then
    echo "❌ Input file not found: $INPUT" >&2
    exit 1
  fi

  # Load RSA private key (if provided)
  if [[ -n "$PRIVATE_KEY_FILE" ]]; then
    [[ -f "$PRIVATE_KEY_FILE" ]] || { echo "❌ Private key file not found: $PRIVATE_KEY_FILE" >&2; exit 1; }
    PRIVATE_KEY_PEM="$(cat "$PRIVATE_KEY_FILE")"
  else
    PRIVATE_KEY_PEM="${EJ_PRIVATE_KEY:-}"
  fi

  # Load passphrase (if provided)
  load_passphrase

  # Optional: save EJ_PRIVATE_KEY to a file
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

    while IFS= read -r entry; do
      local key val_type value plain

      key="$(jq -r '.key' <<<"$entry")"
      val_type="$(jq -r '.value | type' <<<"$entry")"

      if [[ "$val_type" != "string" ]]; then
        echo "❌ Non-string value for key '$key'. Only string values supported." >&2
        exit 1
      fi

      value="$(jq -r '.value' <<<"$entry")"

      if is_ejson_wrapped "$value"; then
        if [[ -z "$PRIVATE_KEY_PEM" ]]; then
          echo "❌ Key '$key' is RSA-encrypted but no private key was provided." >&2
          echo "   Set EJ_PRIVATE_KEY or use --private-key-file." >&2
          exit 1
        fi
        if ! plain="$(decrypt_ejson_value "$value")"; then
          echo "❌ Failed to decrypt '$key' (wrong RSA key or corrupted value)" >&2
          exit 1
        fi

      elif is_passphrase_wrapped "$value"; then
        if [[ -z "$PASSPHRASE" ]]; then
          echo "❌ Key '$key' is passphrase-encrypted but no passphrase was provided." >&2
          echo "   Set EP_PASSPHRASE or use --passphrase-file." >&2
          exit 1
        fi
        if ! plain="$(decrypt_passphrase_value "$value")"; then
          echo "❌ Failed to decrypt '$key' (wrong passphrase or corrupted value)" >&2
          exit 1
        fi

      else
        plain="$value"
      fi

      printf "%s=%s\n" "$key" "$(quote_env_value "$plain")"

    done < <(jq -c 'to_entries[] | select(.key | startswith("_") | not)' "$INPUT")

  } > "$tmp_out"

  mv "$tmp_out" "$OUTPUT"
  echo "✅ Wrote $OUTPUT from $INPUT"
}

# -----------------------------------------------------------------------
# Entry: detect command + parse args
# -----------------------------------------------------------------------
COMMAND="decrypt"

if [[ $# -gt 0 ]]; then
  case "$1" in
    gen-keys|encrypt|decrypt)
      COMMAND="$1"
      shift
      ;;
  esac
fi

while [[ $# -gt 0 ]]; do
  case "$COMMAND" in
    encrypt)
      case "$1" in
        --input|-i)        INPUT="${2:-}";            shift 2 ;;
        --all)             ENCRYPT_ALL="true";        shift 1 ;;
        --key)             ENCRYPT_KEY="${2:-}";      shift 2 ;;
        --value)           ENCRYPT_VALUE="${2:-}";    shift 2 ;;
        --value-stdin)     ENCRYPT_VALUE_STDIN="true";shift 1 ;;
        --passphrase-file) PASSPHRASE_FILE="${2:-}";  shift 2 ;;
        --help|-h)         usage; exit 0 ;;
        *) echo "❌ Unknown option for encrypt: $1" >&2; usage >&2; exit 1 ;;
      esac
      ;;
    decrypt)
      case "$1" in
        --input|-i)        INPUT="${2:-}";              shift 2 ;;
        --output|-o)       OUTPUT="${2:-}";             shift 2 ;;
        --private-key-file)PRIVATE_KEY_FILE="${2:-}";   shift 2 ;;
        --save-private-key)SAVE_PRIVATE_KEY_FILE="${2:-}";shift 2 ;;
        --passphrase-file) PASSPHRASE_FILE="${2:-}";    shift 2 ;;
        --help|-h)         usage; exit 0 ;;
        *) echo "❌ Unknown option for decrypt: $1" >&2; usage >&2; exit 1 ;;
      esac
      ;;
    gen-keys)
      case "$1" in
        --output-ejson) EJSON_OUT="${2:-}"; shift 2 ;;
        --bits)         KEY_BITS="${2:-}";  shift 2 ;;
        --help|-h)      usage; exit 0 ;;
        *) echo "❌ Unknown option for gen-keys: $1" >&2; usage >&2; exit 1 ;;
      esac
      ;;
  esac
done

case "$COMMAND" in
  gen-keys) cmd_gen_keys ;;
  encrypt)  cmd_encrypt  ;;
  decrypt)  cmd_decrypt  ;;
  *) echo "❌ Unknown command: $COMMAND" >&2; usage >&2; exit 1 ;;
esac
