#!/usr/bin/env bash

# -----------------------------------------------------------------------------
# Test suite for ejson-to-env.sh
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SCRIPT_DIR/ejson-to-env.sh"
TEST_DIR=""
PASSED=0
FAILED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

setup() {
  TEST_DIR="$(mktemp -d)"
  cp "$SCRIPT" "$TEST_DIR/"
  cd "$TEST_DIR"
}

teardown() {
  cd "$SCRIPT_DIR" || true
  [[ -n "$TEST_DIR" && -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
  TEST_DIR=""
}

pass() {
  echo -e "${GREEN}✓ PASS${NC}: $1"
  ((PASSED++))
}

fail() {
  echo -e "${RED}✗ FAIL${NC}: $1"
  echo "  Expected: $2"
  echo "  Got: $3"
  ((FAILED++))
}

assert_file_exists() {
  if [[ -f "$1" ]]; then
    pass "$2"
  else
    fail "$2" "file '$1' exists" "file not found"
  fi
}

assert_file_not_exists() {
  if [[ ! -f "$1" ]]; then
    pass "$2"
  else
    fail "$2" "file '$1' not exists" "file exists"
  fi
}

assert_file_contains() {
  if grep -q "$2" "$1" 2>/dev/null; then
    pass "$3"
  else
    fail "$3" "file contains '$2'" "not found in file"
  fi
}

assert_file_not_contains() {
  if ! grep -q "$2" "$1" 2>/dev/null; then
    pass "$3"
  else
    fail "$3" "file does not contain '$2'" "found in file"
  fi
}

assert_equals() {
  if [[ "$1" == "$2" ]]; then
    pass "$3"
  else
    fail "$3" "$2" "$1"
  fi
}

assert_not_empty() {
  if [[ -n "$1" ]]; then
    pass "$2"
  else
    fail "$2" "non-empty string" "empty string"
  fi
}

assert_exit_code() {
  if [[ "$1" -eq "$2" ]]; then
    pass "$3"
  else
    fail "$3" "exit code $2" "exit code $1"
  fi
}

# -----------------------------------------------------------------------------
# Test: gen-keys
# -----------------------------------------------------------------------------
test_gen_keys_creates_keypair() {
  setup
  local output
  output="$(./ejson-to-env.sh gen-keys 2>&1)"

  assert_file_exists "env.ejson" "gen-keys creates env.ejson"
  assert_file_contains "env.ejson" "_public_key" "gen-keys adds _public_key to env.ejson"
  assert_file_contains "env.ejson" "BEGIN PUBLIC KEY" "gen-keys stores valid public key"
  if echo "$output" | grep -qE "BEGIN (RSA )?PRIVATE KEY"; then
    pass "gen-keys outputs private key to terminal"
  else
    fail "gen-keys outputs private key to terminal" "private key in output" "not found"
  fi
  teardown
}

test_gen_keys_updates_existing_ejson() {
  setup
  echo '{"EXISTING_KEY": "value"}' > env.ejson
  ./ejson-to-env.sh gen-keys >/dev/null 2>&1

  assert_file_contains "env.ejson" "_public_key" "gen-keys adds _public_key to existing file"
  assert_file_contains "env.ejson" "EXISTING_KEY" "gen-keys preserves existing keys"
  teardown
}

test_gen_keys_custom_output_file() {
  setup
  ./ejson-to-env.sh gen-keys --output-ejson custom.ejson >/dev/null 2>&1

  assert_file_exists "custom.ejson" "gen-keys respects --output-ejson"
  assert_file_contains "custom.ejson" "_public_key" "gen-keys writes public key to custom file"
  teardown
}

test_gen_keys_custom_bits() {
  setup
  ./ejson-to-env.sh gen-keys --bits 3072 >/dev/null 2>&1

  assert_file_exists "env.ejson" "gen-keys with --bits creates file"
  # Verify key is larger (3072-bit key produces longer base64)
  local key_length
  key_length=$(jq -r '._public_key' env.ejson | wc -c)
  if [[ $key_length -gt 500 ]]; then
    pass "gen-keys --bits 3072 creates larger key"
  else
    fail "gen-keys --bits 3072 creates larger key" ">500 chars" "$key_length chars"
  fi
  teardown
}

test_gen_keys_fails_on_invalid_json() {
  setup
  echo "not valid json" > env.ejson
  local exit_code=0
  ./ejson-to-env.sh gen-keys >/dev/null 2>&1 || exit_code=$?

  assert_equals "$exit_code" "1" "gen-keys fails on invalid JSON"
  teardown
}

test_gen_keys_fails_on_non_object_json() {
  setup
  echo '["array", "not", "object"]' > env.ejson
  local exit_code=0
  ./ejson-to-env.sh gen-keys >/dev/null 2>&1 || exit_code=$?

  assert_equals "$exit_code" "1" "gen-keys fails on non-object JSON"
  teardown
}

# -----------------------------------------------------------------------------
# Test: encrypt
# -----------------------------------------------------------------------------
test_encrypt_adds_encrypted_key() {
  setup
  ./ejson-to-env.sh gen-keys >/dev/null 2>&1
  ./ejson-to-env.sh encrypt --key DB_PASSWORD --value "secret123" >/dev/null 2>&1

  assert_file_contains "env.ejson" "DB_PASSWORD" "encrypt adds key to ejson"
  assert_file_contains "env.ejson" 'EJ\[1:' "encrypt wraps value with EJ[1:...]"
  teardown
}

test_encrypt_with_stdin() {
  setup
  ./ejson-to-env.sh gen-keys >/dev/null 2>&1
  echo "secret_from_stdin" | ./ejson-to-env.sh encrypt --key API_KEY --value-stdin >/dev/null 2>&1

  assert_file_contains "env.ejson" "API_KEY" "encrypt --value-stdin adds key"
  assert_file_contains "env.ejson" 'EJ\[1:' "encrypt --value-stdin encrypts value"
  teardown
}

test_encrypt_fails_without_key() {
  setup
  ./ejson-to-env.sh gen-keys >/dev/null 2>&1
  local exit_code=0
  ./ejson-to-env.sh encrypt --value "secret" 2>/dev/null || exit_code=$?

  assert_equals "$exit_code" "1" "encrypt fails without --key"
  teardown
}

test_encrypt_fails_without_value() {
  setup
  ./ejson-to-env.sh gen-keys >/dev/null 2>&1
  local exit_code=0
  ./ejson-to-env.sh encrypt --key MYKEY 2>/dev/null || exit_code=$?

  assert_equals "$exit_code" "1" "encrypt fails without --value"
  teardown
}

test_encrypt_fails_on_missing_input() {
  setup
  local exit_code=0
  ./ejson-to-env.sh encrypt --key MYKEY --value "secret" 2>/dev/null || exit_code=$?

  assert_equals "$exit_code" "1" "encrypt fails when input file missing"
  teardown
}

test_encrypt_fails_on_missing_public_key() {
  setup
  echo '{"OTHER_KEY": "value"}' > env.ejson
  local exit_code=0
  ./ejson-to-env.sh encrypt --key MYKEY --value "secret" 2>/dev/null || exit_code=$?

  assert_equals "$exit_code" "1" "encrypt fails when _public_key missing"
  teardown
}

test_encrypt_custom_input_file() {
  setup
  ./ejson-to-env.sh gen-keys --output-ejson custom.ejson >/dev/null 2>&1
  ./ejson-to-env.sh encrypt -i custom.ejson --key SECRET --value "mysecret" >/dev/null 2>&1

  assert_file_contains "custom.ejson" "SECRET" "encrypt -i respects custom input file"
  teardown
}

# -----------------------------------------------------------------------------
# Test: decrypt
# -----------------------------------------------------------------------------
test_decrypt_produces_env_file() {
  setup
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"
  ./ejson-to-env.sh encrypt --key DB_PASSWORD --value "supersecret" >/dev/null 2>&1

  EJ_PRIVATE_KEY="$priv_key" ./ejson-to-env.sh decrypt >/dev/null 2>&1

  assert_file_exists ".env" "decrypt creates .env file"
  assert_file_contains ".env" "DB_PASSWORD" "decrypt includes key in .env"
  assert_file_contains ".env" "supersecret" "decrypt decrypts value correctly"
  teardown
}

test_decrypt_plain_text_passthrough() {
  setup
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"

  # Add a plain text value directly to ejson
  jq '. + {"PLAIN_KEY": "plain_value"}' env.ejson > tmp.json && mv tmp.json env.ejson

  EJ_PRIVATE_KEY="$priv_key" ./ejson-to-env.sh decrypt >/dev/null 2>&1

  assert_file_contains ".env" 'PLAIN_KEY="plain_value"' "decrypt passes through plain text values"
  teardown
}

test_decrypt_with_private_key_file() {
  setup
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"
  echo "$priv_key" > private.pem
  ./ejson-to-env.sh encrypt --key SECRET --value "file_key_test" >/dev/null 2>&1

  ./ejson-to-env.sh decrypt --private-key-file private.pem >/dev/null 2>&1

  assert_file_contains ".env" "file_key_test" "decrypt --private-key-file works"
  teardown
}

test_decrypt_custom_input_output() {
  setup
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys --output-ejson prod.ejson 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"
  ./ejson-to-env.sh encrypt -i prod.ejson --key TOKEN --value "custom_io_test" >/dev/null 2>&1

  EJ_PRIVATE_KEY="$priv_key" ./ejson-to-env.sh decrypt -i prod.ejson -o .env.prod >/dev/null 2>&1

  assert_file_exists ".env.prod" "decrypt respects -o option"
  assert_file_contains ".env.prod" "custom_io_test" "decrypt writes to custom output"
  teardown
}

test_decrypt_fails_without_private_key() {
  setup
  ./ejson-to-env.sh gen-keys >/dev/null 2>&1
  ./ejson-to-env.sh encrypt --key SECRET --value "test" >/dev/null 2>&1

  local exit_code=0
  ./ejson-to-env.sh decrypt 2>/dev/null || exit_code=$?

  assert_equals "$exit_code" "1" "decrypt fails without private key"
  teardown
}

test_decrypt_fails_on_missing_input() {
  setup
  local exit_code=0
  EJ_PRIVATE_KEY="dummy" ./ejson-to-env.sh decrypt 2>/dev/null || exit_code=$?

  assert_equals "$exit_code" "1" "decrypt fails when input file missing"
  teardown
}

test_decrypt_fails_on_missing_public_key() {
  setup
  echo '{"SECRET": "value"}' > env.ejson
  local exit_code=0
  EJ_PRIVATE_KEY="dummy" ./ejson-to-env.sh decrypt 2>/dev/null || exit_code=$?

  assert_equals "$exit_code" "1" "decrypt fails when _public_key missing in input"
  teardown
}

test_decrypt_fails_with_wrong_private_key() {
  setup
  ./ejson-to-env.sh gen-keys >/dev/null 2>&1
  ./ejson-to-env.sh encrypt --key SECRET --value "test" >/dev/null 2>&1

  # Generate a different keypair
  local wrong_key
  wrong_key="$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)"

  local exit_code=0
  EJ_PRIVATE_KEY="$wrong_key" ./ejson-to-env.sh decrypt 2>/dev/null || exit_code=$?

  assert_equals "$exit_code" "1" "decrypt fails with wrong private key"
  teardown
}

test_decrypt_fails_on_non_string_value() {
  setup
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"

  # Add a non-string value
  jq '. + {"NUMBER": 123}' env.ejson > tmp.json && mv tmp.json env.ejson

  local exit_code=0
  EJ_PRIVATE_KEY="$priv_key" ./ejson-to-env.sh decrypt 2>/dev/null || exit_code=$?

  assert_equals "$exit_code" "1" "decrypt fails on non-string value"
  teardown
}

test_decrypt_save_private_key() {
  setup
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"

  EJ_PRIVATE_KEY="$priv_key" ./ejson-to-env.sh decrypt --save-private-key saved.pem >/dev/null 2>&1

  assert_file_exists "saved.pem" "decrypt --save-private-key creates file"
  assert_file_contains "saved.pem" "BEGIN" "saved private key is valid PEM"
  teardown
}

test_decrypt_handles_special_characters() {
  setup
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"

  # Value with quotes, backslashes, and special chars
  ./ejson-to-env.sh encrypt --key SPECIAL --value 'pass"word\with$pecial' >/dev/null 2>&1

  EJ_PRIVATE_KEY="$priv_key" ./ejson-to-env.sh decrypt >/dev/null 2>&1

  assert_file_contains ".env" "SPECIAL=" "decrypt handles special characters"
  teardown
}

test_decrypt_excludes_public_key_from_output() {
  setup
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"

  EJ_PRIVATE_KEY="$priv_key" ./ejson-to-env.sh decrypt >/dev/null 2>&1

  assert_file_not_contains ".env" "_public_key" "decrypt excludes _public_key from .env"
  teardown
}

test_decrypt_adds_header_comment() {
  setup
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"

  EJ_PRIVATE_KEY="$priv_key" ./ejson-to-env.sh decrypt >/dev/null 2>&1

  assert_file_contains ".env" "# Generated from:" "decrypt adds header comment"
  assert_file_contains ".env" "# Do not edit directly" "decrypt adds edit warning"
  teardown
}

# -----------------------------------------------------------------------------
# Test: default command and help
# -----------------------------------------------------------------------------
test_default_command_is_decrypt() {
  setup
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"
  ./ejson-to-env.sh encrypt --key TEST --value "default_cmd" >/dev/null 2>&1

  # Run without specifying command
  EJ_PRIVATE_KEY="$priv_key" ./ejson-to-env.sh >/dev/null 2>&1

  assert_file_exists ".env" "default command is decrypt"
  assert_file_contains ".env" "default_cmd" "default decrypt works correctly"
  teardown
}

test_help_flag() {
  setup
  local output
  output="$(./ejson-to-env.sh --help 2>&1)"

  if echo "$output" | grep -q "Usage:"; then
    pass "--help shows usage"
  else
    fail "--help shows usage" "Usage text" "not found"
  fi
  teardown
}

test_help_flag_for_commands() {
  setup
  local output

  output="$(./ejson-to-env.sh gen-keys --help 2>&1)"
  if echo "$output" | grep -q "Usage:"; then
    pass "gen-keys --help shows usage"
  else
    fail "gen-keys --help shows usage" "Usage text" "not found"
  fi

  output="$(./ejson-to-env.sh encrypt --help 2>&1)"
  if echo "$output" | grep -q "Usage:"; then
    pass "encrypt --help shows usage"
  else
    fail "encrypt --help shows usage" "Usage text" "not found"
  fi

  output="$(./ejson-to-env.sh decrypt --help 2>&1)"
  if echo "$output" | grep -q "Usage:"; then
    pass "decrypt --help shows usage"
  else
    fail "decrypt --help shows usage" "Usage text" "not found"
  fi
  teardown
}

test_unknown_command_fails() {
  setup
  local exit_code=0
  ./ejson-to-env.sh unknown-cmd 2>/dev/null || exit_code=$?

  assert_equals "$exit_code" "1" "unknown command fails"
  teardown
}

test_unknown_option_fails() {
  setup
  local exit_code=0
  ./ejson-to-env.sh decrypt --unknown-option 2>/dev/null || exit_code=$?

  assert_equals "$exit_code" "1" "unknown option fails"
  teardown
}

# -----------------------------------------------------------------------------
# Test: round-trip (full workflow)
# -----------------------------------------------------------------------------
test_full_round_trip() {
  setup

  # Generate keys
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"

  # Encrypt multiple values
  ./ejson-to-env.sh encrypt --key DB_HOST --value "localhost" >/dev/null 2>&1
  ./ejson-to-env.sh encrypt --key DB_USER --value "admin" >/dev/null 2>&1
  ./ejson-to-env.sh encrypt --key DB_PASS --value "super_secret_password_123!" >/dev/null 2>&1

  # Add a plain text value
  jq '. + {"DEBUG": "true"}' env.ejson > tmp.json && mv tmp.json env.ejson

  # Decrypt
  EJ_PRIVATE_KEY="$priv_key" ./ejson-to-env.sh decrypt >/dev/null 2>&1

  # Verify all values
  assert_file_contains ".env" 'DB_HOST="localhost"' "round-trip: DB_HOST correct"
  assert_file_contains ".env" 'DB_USER="admin"' "round-trip: DB_USER correct"
  assert_file_contains ".env" 'DB_PASS="super_secret_password_123!"' "round-trip: DB_PASS correct"
  assert_file_contains ".env" 'DEBUG="true"' "round-trip: plain text DEBUG correct"

  teardown
}

test_multiple_encrypt_same_key_overwrites() {
  setup
  local priv_key
  priv_key="$(./ejson-to-env.sh gen-keys 2>&1 | sed -n '/-----BEGIN/,/-----END/p')"

  ./ejson-to-env.sh encrypt --key PASSWORD --value "first" >/dev/null 2>&1
  ./ejson-to-env.sh encrypt --key PASSWORD --value "second" >/dev/null 2>&1

  EJ_PRIVATE_KEY="$priv_key" ./ejson-to-env.sh decrypt >/dev/null 2>&1

  assert_file_contains ".env" 'PASSWORD="second"' "encrypting same key overwrites"
  assert_file_not_contains ".env" "first" "old value is not present"
  teardown
}

# -----------------------------------------------------------------------------
# Run all tests
# -----------------------------------------------------------------------------
echo -e "${YELLOW}Running ejson-to-env.sh test suite${NC}"
echo "=============================================="

# gen-keys tests
test_gen_keys_creates_keypair
test_gen_keys_updates_existing_ejson
test_gen_keys_custom_output_file
test_gen_keys_custom_bits
test_gen_keys_fails_on_invalid_json
test_gen_keys_fails_on_non_object_json

# encrypt tests
test_encrypt_adds_encrypted_key
test_encrypt_with_stdin
test_encrypt_fails_without_key
test_encrypt_fails_without_value
test_encrypt_fails_on_missing_input
test_encrypt_fails_on_missing_public_key
test_encrypt_custom_input_file

# decrypt tests
test_decrypt_produces_env_file
test_decrypt_plain_text_passthrough
test_decrypt_with_private_key_file
test_decrypt_custom_input_output
test_decrypt_fails_without_private_key
test_decrypt_fails_on_missing_input
test_decrypt_fails_on_missing_public_key
test_decrypt_fails_with_wrong_private_key
test_decrypt_fails_on_non_string_value
test_decrypt_save_private_key
test_decrypt_handles_special_characters
test_decrypt_excludes_public_key_from_output
test_decrypt_adds_header_comment

# general tests
test_default_command_is_decrypt
test_help_flag
test_help_flag_for_commands
test_unknown_command_fails
test_unknown_option_fails

# integration tests
test_full_round_trip
test_multiple_encrypt_same_key_overwrites

# Summary
echo "=============================================="
echo -e "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"

if [[ $FAILED -gt 0 ]]; then
  exit 1
fi
