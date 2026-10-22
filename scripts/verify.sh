#!/bin/bash
# verify.sh — Automated verification for the php2shell PoC lab
# Runs after `docker compose up -d` to confirm everything works.

set -euo pipefail

TARGET="${1:-http://localhost:8080}"
RED='\033[0;91m'
GRN='\033[0;92m'
YLW='\033[0;93m'
RST='\033[0m'

pass() { echo -e "  ${GRN}[PASS]${RST} $1"; }
fail() { echo -e "  ${RED}[FAIL]${RST} $1"; FAILURES=$((FAILURES+1)); }
info() { echo -e "  ${YLW}[INFO]${RST} $1"; }

FAILURES=0

echo ""
echo "============================================"
echo "  php2shell Lab Verification"
echo "============================================"
echo ""
echo "Target: ${TARGET}"
echo ""

# --- 1. Connectivity ---
echo "[1/6] Connectivity"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/" --max-time 5 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    pass "Target reachable (HTTP ${HTTP_CODE})"
else
    fail "Target not reachable (HTTP ${HTTP_CODE})"
fi

# --- 2. PHP version & config ---
echo "[2/6] PHP Configuration"
BODY=$(curl -s "${TARGET}/index.php" --max-time 5 2>/dev/null || echo "")
if echo "$BODY" | grep -q "PHP Version"; then
    PHP_VER=$(echo "$BODY" | grep -oP 'PHP Version:\s*\K[\d.]+' | head -1)
    pass "PHP ${PHP_VER:-unknown} detected"
else
    fail "Cannot detect PHP version"
fi

if echo "$BODY" | grep -q "upload_progress:.*ON"; then
    pass "session.upload_progress.enabled = ON"
else
    fail "session.upload_progress not ON"
fi

if echo "$BODY" | grep -q "progress.cleanup:.*OFF"; then
    pass "session.upload_progress.cleanup = OFF"
else
    fail "session.upload_progress.cleanup not OFF"
fi

# --- 3. Upload endpoint ---
echo "[3/6] Upload Endpoint"
UPLOAD_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/upload.php" --max-time 5 2>/dev/null || echo "000")
if [ "$UPLOAD_CODE" = "200" ]; then
    pass "upload.php reachable"
else
    fail "upload.php not reachable (HTTP ${UPLOAD_CODE})"
fi

# --- 4. LFI endpoint ---
echo "[4/6] LFI Endpoint"
LFI_RESP=$(curl -s "${TARGET}/view.php?file=/etc/hostname" --max-time 5 2>/dev/null || echo "")
if [ -n "$LFI_RESP" ] && ! echo "$LFI_RESP" | grep -q "Warning.*include"; then
    pass "LFI working (/etc/hostname included)"
else
    info "LFI returned warning or empty — check file permissions"
fi

# --- 5. Session injection ---
echo "[5/6] Session Injection"
SID="verify$(date +%s)"
INJECT_RESP=$(curl -s -o /dev/null -w "%{http_code}" \
    -b "PHPSESSID=${SID}" \
    -F "PHP_SESSION_UPLOAD_PROGRESS=VERIFY_PAYLOAD" \
    -F "file=@/dev/null;filename=test.bin" \
    "${TARGET}/upload.php" --max-time 5 2>/dev/null || echo "000")

if [ "$INJECT_RESP" = "200" ]; then
    pass "Injection POST accepted (HTTP 200)"
else
    fail "Injection POST failed (HTTP ${INJECT_RESP})"
fi

# Check if session file was created
SESS_CHECK=$(curl -s "${TARGET}/debug.php" --max-time 5 2>/dev/null || echo "")
if echo "$SESS_CHECK" | grep -q "sess_${SID}"; then
    pass "Session file created: sess_${SID}"
else
    fail "Session file not found — upload_progress may not be writing"
fi

# --- 6. Full RCE chain ---
echo "[6/6] Full RCE Chain"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)/exploit"
if [ -f "${SCRIPT_DIR}/php2shell.py" ]; then
    RCE_OUTPUT=$(python3 "${SCRIPT_DIR}/php2shell.py" -t "${TARGET}" -c "echo php2shell_verify" -q 2>&1 || echo "")
    if echo "$RCE_OUTPUT" | grep -q "php2shell_verify"; then
        pass "RCE confirmed — command output received"
    else
        fail "RCE chain did not return expected output"
        info "Output: ${RCE_OUTPUT:0:200}"
    fi
else
    info "Skipping RCE test — php2shell.py not found at ${SCRIPT_DIR}"
fi

# --- Summary ---
echo ""
echo "============================================"
if [ "$FAILURES" -eq 0 ]; then
    echo -e "  ${GRN}All checks passed.${RST}"
else
    echo -e "  ${RED}${FAILURES} check(s) failed.${RST}"
fi
echo "============================================"
echo ""

exit $FAILURES
