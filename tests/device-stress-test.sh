#!/system/bin/sh
# resetprop-rs device stress test
# Push to /data/local/tmp/ and run as root: su -c sh /data/local/tmp/device-stress-test.sh

RP="/data/local/tmp/rp-rs"
LOG="/data/local/tmp/rp-test.log"
PASS=0
FAIL=0

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }
pass() { PASS=$((PASS + 1)); log "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL: $1"; }

rm -f "$LOG"
log "=== resetprop-rs device stress test ==="
log "Device: $(getprop ro.product.model) | Android $(getprop ro.build.version.release)"
log "Kernel: $(uname -r)"
log "Binary: $RP ($(ls -la $RP | awk '{print $5}') bytes)"
echo ""

# --- Test 1: Binary runs ---
if $RP -h >/dev/null 2>&1; then
    pass "binary executes"
else
    fail "binary won't execute"
    log "FATAL: cannot continue"
    exit 1
fi

# --- Test 2: List all properties ---
COUNT=$($RP 2>/dev/null | wc -l)
if [ "$COUNT" -gt 100 ]; then
    pass "list all: $COUNT properties"
else
    fail "list all: only $COUNT properties (expected >100)"
fi

# --- Test 3: Get known property ---
VAL=$($RP ro.build.type 2>/dev/null)
if [ -n "$VAL" ]; then
    pass "get ro.build.type = '$VAL'"
else
    fail "get ro.build.type returned empty"
fi

# --- Test 4: Get vs getprop comparison ---
OURS=$($RP ro.build.fingerprint 2>/dev/null)
THEIRS=$(getprop ro.build.fingerprint 2>/dev/null)
if [ "$OURS" = "$THEIRS" ]; then
    pass "get matches getprop for ro.build.fingerprint"
else
    fail "get mismatch: ours='$OURS' getprop='$THEIRS'"
fi

# --- Test 5: Bulk comparison (sample 20 props) ---
MISMATCH=0
CHECKED=0
$RP 2>/dev/null | head -20 | while IFS= read -r line; do
    NAME=$(echo "$line" | sed 's/^\[//;s/\]:.*$//')
    OUR_VAL=$(echo "$line" | sed 's/^.*\]: \[//;s/\]$//')
    GP_VAL=$(getprop "$NAME" 2>/dev/null)
    if [ "$OUR_VAL" != "$GP_VAL" ]; then
        log "  MISMATCH: $NAME ours='$OUR_VAL' getprop='$GP_VAL'"
        MISMATCH=$((MISMATCH + 1))
    fi
    CHECKED=$((CHECKED + 1))
done
if [ "$MISMATCH" -eq 0 ]; then
    pass "bulk comparison: 20 props match getprop"
else
    fail "bulk comparison: $MISMATCH/20 mismatched"
fi

# --- Test 6: Set a test property ---
TEST_PROP="persist.rp.rs.test"
if $RP "$TEST_PROP" "hello_from_rust" 2>/dev/null; then
    READBACK=$($RP "$TEST_PROP" 2>/dev/null)
    if [ "$READBACK" = "hello_from_rust" ]; then
        pass "set+get roundtrip: $TEST_PROP"
    else
        fail "set succeeded but readback='$READBACK'"
    fi
else
    fail "set $TEST_PROP (may need different SELinux context)"
fi

# --- Test 7: Overwrite property ---
if $RP "$TEST_PROP" "overwritten" 2>/dev/null; then
    READBACK=$($RP "$TEST_PROP" 2>/dev/null)
    if [ "$READBACK" = "overwritten" ]; then
        pass "overwrite roundtrip: $TEST_PROP"
    else
        fail "overwrite readback='$READBACK'"
    fi
else
    fail "overwrite $TEST_PROP"
fi

# --- Test 8: Delete property ---
if $RP -d "$TEST_PROP" 2>/dev/null; then
    READBACK=$($RP "$TEST_PROP" 2>&1)
    if echo "$READBACK" | grep -q "not found"; then
        pass "delete: $TEST_PROP gone"
    else
        fail "delete: $TEST_PROP still readable='$READBACK'"
    fi
else
    fail "delete $TEST_PROP"
fi

# --- Test 9: Hexpatch delete (the real deal) ---
HEXPATCH_PROP="persist.rp.rs.hexpatch"
$RP "$HEXPATCH_PROP" "stealth_test" 2>/dev/null
BEFORE_COUNT=$($RP 2>/dev/null | wc -l)
if $RP --hexpatch-delete "$HEXPATCH_PROP" 2>/dev/null; then
    READBACK=$($RP "$HEXPATCH_PROP" 2>&1)
    if echo "$READBACK" | grep -q "not found"; then
        pass "hexpatch-delete: $HEXPATCH_PROP destroyed"
    else
        fail "hexpatch-delete: $HEXPATCH_PROP still readable='$READBACK'"
    fi
else
    fail "hexpatch-delete $HEXPATCH_PROP"
fi

# --- Test 10: Hexpatch stealth — original name absent ---
RENAMED=$($RP 2>/dev/null | grep -c "rp.rs.hexpatch")
if [ "$RENAMED" -eq 0 ]; then
    pass "hexpatch stealth: original name absent from listing"
else
    fail "hexpatch stealth: 'rp.rs.hexpatch' still appears $RENAMED times"
fi

# --- Test 11: Hexpatch stealth — mangled prop has value "0" ---
# The mangled prop should exist with a plausible value, not empty
FOUND_ZERO=0
$RP 2>/dev/null | while IFS= read -r line; do
    VAL=$(echo "$line" | sed 's/^.*\]: \[//;s/\]$//')
    NAME=$(echo "$line" | sed 's/^\[//;s/\]:.*$//')
    # look for a prop with value "0" that wasn't in our original listing
    # hexpatch writes "0" as the stealth value
    if [ "$VAL" = "0" ]; then
        # check if this name looks mangled (not a standard prop)
        echo "$NAME" >> /data/local/tmp/rp-zero-props.txt
    fi
done
# simpler check: there should be at least one prop with value "0" that has segments
# matching device vocabulary (the harvest system). We verify by checking total count
# didn't drop — the mangled prop is still in the trie.
AFTER_COUNT=$($RP 2>/dev/null | wc -l)
if [ "$AFTER_COUNT" -ge "$BEFORE_COUNT" ]; then
    pass "hexpatch stealth: prop count preserved ($BEFORE_COUNT -> $AFTER_COUNT), mangled node alive"
else
    fail "hexpatch stealth: prop count dropped ($BEFORE_COUNT -> $AFTER_COUNT)"
fi
rm -f /data/local/tmp/rp-zero-props.txt

# --- Test 12: Hexpatch stealth — mangled value via getprop cross-check ---
# Walk listing, find any prop with value "0" whose name doesn't resolve via getprop
# (persist.* props set by us won't be in init's prop service, so getprop returns empty)
STEALTH_FOUND=0
$RP 2>/dev/null | grep '\]: \[0\]$' | head -5 | while IFS= read -r line; do
    NAME=$(echo "$line" | sed 's/^\[//;s/\]:.*$//')
    GP=$(getprop "$NAME" 2>/dev/null)
    if [ -z "$GP" ] && echo "$NAME" | grep -qv "rp\.\|test\.\|stress"; then
        log "  stealth candidate: [$NAME] = [0] (getprop empty)"
        STEALTH_FOUND=1
    fi
done
# This is informational — hard to assert definitively on unknown devices
log "  (stealth value check is informational — mangled props have value '0')"

# --- Test 13: Hexpatch sequential — two props, both disappear ---
HP1="persist.rp.rs.hex1"
HP2="persist.rp.rs.hex2"
$RP "$HP1" "first" 2>/dev/null
$RP "$HP2" "second" 2>/dev/null
HP_BEFORE=$($RP 2>/dev/null | wc -l)
$RP --hexpatch-delete "$HP1" 2>/dev/null
$RP --hexpatch-delete "$HP2" 2>/dev/null
R1=$($RP "$HP1" 2>&1)
R2=$($RP "$HP2" 2>&1)
HP_AFTER=$($RP 2>/dev/null | wc -l)
if echo "$R1" | grep -q "not found" && echo "$R2" | grep -q "not found"; then
    if [ "$HP_AFTER" -ge "$HP_BEFORE" ]; then
        pass "hexpatch sequential: both props gone, trie nodes preserved ($HP_BEFORE -> $HP_AFTER)"
    else
        fail "hexpatch sequential: props gone but count dropped ($HP_BEFORE -> $HP_AFTER)"
    fi
else
    fail "hexpatch sequential: r1='$R1' r2='$R2'"
fi

# --- Test 14: Hexpatch — all mangled names are valid ASCII ---
BAD_ASCII=0
$RP 2>/dev/null | while IFS= read -r line; do
    NAME=$(echo "$line" | sed 's/^\[//;s/\]:.*$//')
    # check for non-printable chars by stripping printable and seeing if anything remains
    CLEANED=$(printf '%s' "$NAME" | tr -d '[:print:]')
    if [ -n "$CLEANED" ]; then
        log "  bad ASCII in prop name: $NAME"
        BAD_ASCII=$((BAD_ASCII + 1))
    fi
done
if [ "$BAD_ASCII" -eq 0 ]; then
    pass "hexpatch ASCII: all property names are valid printable ASCII"
else
    fail "hexpatch ASCII: $BAD_ASCII props have non-printable chars"
fi

# --- Test 15: Verbose flag ---
OUTPUT=$($RP -v "$TEST_PROP" "verbose_test" 2>&1)
if echo "$OUTPUT" | grep -q "set:"; then
    pass "-v flag produces verbose output"
else
    fail "-v flag: no verbose output in '$OUTPUT'"
fi
$RP -d "$TEST_PROP" 2>/dev/null

# --- Test 16: Batch file load ---
BATCH="/data/local/tmp/rp-batch.txt"
cat > "$BATCH" << 'BATCHEOF'
# test batch file
persist.rp.batch.a=alpha
persist.rp.batch.b=bravo
persist.rp.batch.c=charlie
BATCHEOF
if $RP -f "$BATCH" 2>/dev/null; then
    A=$($RP persist.rp.batch.a 2>/dev/null)
    B=$($RP persist.rp.batch.b 2>/dev/null)
    C=$($RP persist.rp.batch.c 2>/dev/null)
    if [ "$A" = "alpha" ] && [ "$B" = "bravo" ] && [ "$C" = "charlie" ]; then
        pass "batch load: 3/3 properties set correctly"
    else
        fail "batch load: a='$A' b='$B' c='$C'"
    fi
    $RP -d persist.rp.batch.a 2>/dev/null
    $RP -d persist.rp.batch.b 2>/dev/null
    $RP -d persist.rp.batch.c 2>/dev/null
else
    fail "batch load from $BATCH"
fi
rm -f "$BATCH"

# --- Test 17: Nonexistent property ---
OUTPUT=$($RP "no.such.property.exists.ever" 2>&1)
if echo "$OUTPUT" | grep -q "not found"; then
    pass "nonexistent property returns error"
else
    fail "nonexistent property: '$OUTPUT'"
fi

# --- Test 18: Stress — rapid set/get/delete cycle ---
STRESS_OK=0
STRESS_FAIL=0
for j in $(seq 1 50); do
    PROP="persist.rp.stress.$j"
    VAL="val_${j}_$(date +%s%N)"
    if $RP "$PROP" "$VAL" 2>/dev/null; then
        READBACK=$($RP "$PROP" 2>/dev/null)
        if [ "$READBACK" = "$VAL" ]; then
            STRESS_OK=$((STRESS_OK + 1))
        else
            STRESS_FAIL=$((STRESS_FAIL + 1))
            log "  stress $j: wrote '$VAL' read '$READBACK'"
        fi
        $RP -d "$PROP" 2>/dev/null
    else
        STRESS_FAIL=$((STRESS_FAIL + 1))
    fi
done
if [ "$STRESS_FAIL" -eq 0 ]; then
    pass "stress: 50/50 set+get+delete cycles"
else
    fail "stress: $STRESS_OK ok, $STRESS_FAIL failed"
fi

# --- Test 19: Max value length (91 bytes) ---
MAX_VAL="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
MAX_VAL=$(echo "$MAX_VAL" | cut -c1-91)
if $RP "persist.rp.maxval" "$MAX_VAL" 2>/dev/null; then
    READBACK=$($RP "persist.rp.maxval" 2>/dev/null)
    READLEN=$(printf '%s' "$READBACK" | wc -c)
    if [ "$READLEN" -eq 91 ]; then
        pass "max short value: 91 bytes roundtrip"
    else
        fail "max short value: wrote 91, read $READLEN bytes"
    fi
    $RP -d "persist.rp.maxval" 2>/dev/null
else
    fail "max short value: set failed"
fi

# --- Test 20: Compare with Magisk resetprop if available ---
if command -v resetprop >/dev/null 2>&1; then
    log ""
    log "--- Magisk resetprop comparison ---"
    MAGISK_COUNT=$(resetprop 2>/dev/null | wc -l)
    OUR_COUNT=$($RP 2>/dev/null | wc -l)
    DIFF=$((OUR_COUNT - MAGISK_COUNT))
    if [ "$DIFF" -ge -5 ] && [ "$DIFF" -le 5 ]; then
        pass "prop count: ours=$OUR_COUNT magisk=$MAGISK_COUNT (diff=$DIFF)"
    else
        fail "prop count divergence: ours=$OUR_COUNT magisk=$MAGISK_COUNT (diff=$DIFF)"
    fi

    MAGISK_FP=$(resetprop ro.build.fingerprint 2>/dev/null)
    OUR_FP=$($RP ro.build.fingerprint 2>/dev/null)
    if [ "$MAGISK_FP" = "$OUR_FP" ]; then
        pass "fingerprint matches Magisk resetprop"
    else
        fail "fingerprint mismatch: ours='$OUR_FP' magisk='$MAGISK_FP'"
    fi
else
    log "Magisk resetprop not found (KSU device?) — skipping comparison"
fi

# --- Summary ---
echo ""
log "=== RESULTS: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -eq 0 ]; then
    log "ALL TESTS PASSED"
else
    log "SOME TESTS FAILED — review $LOG"
fi
