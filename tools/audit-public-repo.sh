#!/usr/bin/env bash
# Public-repo compliance audit — encodes this project's publication rules.
# Exits non-zero on any violation. Run locally before pushing, or in CI.
#
# Rules enforced:
#   1. PowerShell/batch sources are ASCII-only (no Cyrillic/Unicode).
#   2. No internal organisation markers (dpsu / dpsugov / adps).
#   3. No committed private key material.
#   4. No hardcoded credentials (passwords / API keys / tokens as literals).
set -uo pipefail

self='tools/audit-public-repo.sh'   # excluded from content scans below
fail=0

echo "[audit] 1/4 ASCII-only PowerShell/batch sources..."
while IFS= read -r f; do
    [ -z "$f" ] && continue
    if LC_ALL=C grep -nP '[^\x00-\x7F]' "$f" >/dev/null 2>&1; then
        echo "  [FAIL] non-ASCII bytes in $f:"
        LC_ALL=C grep -nP '[^\x00-\x7F]' "$f" | sed 's/^/    /'
        fail=1
    fi
done < <(git ls-files '*.ps1' '*.bat' '*.cmd')

echo "[audit] 2/4 internal organisation markers..."
if git grep -nIP '(?i)dpsugov|\bdpsu\b|\badps\b|kms\.dpsu' -- . ":(exclude)$self" >/dev/null 2>&1; then
    echo "  [FAIL] internal org markers found:"
    git grep -nIP '(?i)dpsugov|\bdpsu\b|\badps\b|kms\.dpsu' -- . ":(exclude)$self" | sed 's/^/    /'
    fail=1
fi

echo "[audit] 3/4 committed private key material..."
if git grep -nIP 'BEGIN [A-Z ]*PRIVATE KEY' -- . ":(exclude)$self" >/dev/null 2>&1; then
    echo "  [FAIL] private key material committed"
    fail=1
fi

echo "[audit] 4/4 hardcoded credentials..."
# Match a contiguous quoted literal (no spaces) assigned to a secret-like key.
# Log lines like  console.log('token:', x)  do not match (value has spaces/punctuation).
# The (?![$_<%{]) lookahead skips variable refs ($x), placeholders (__X__), templates.
cred=$(git grep -nIP '(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*["\x27](?![$_<%{])[^"\x27\s]{7,}["\x27]' -- . ":(exclude)$self" 2>/dev/null \
    | grep -viE 'example|placeholder|your|change_?me|dummy|test_|_test|/tests?/|<|process\.env|os\.getenv|getenv|env\(|\$\{|:\?|:-|Read-Host|ConvertTo-Secure' || true)
if [ -n "$cred" ]; then
    echo "  [FAIL] possible hardcoded credential:"
    echo "$cred" | sed 's/^/    /'
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "[audit] PASS — repo complies with publication rules."
else
    echo "[audit] FAIL — fix the issues above before pushing."
fi
exit "$fail"
