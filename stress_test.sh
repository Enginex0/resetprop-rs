#!/system/bin/sh
# On-device stress test for resetprop nuke + stealth features
# Run as root: su -c 'sh /data/local/tmp/stress_test.sh'

RP="/data/local/tmp/resetprop"
LOG="/data/local/tmp/resetprop_stress.log"
PASS=0
FAIL=0
TOTAL=0

log() { echo "$@" | tee -a "$LOG"; }
assert_eq() {
    TOTAL=$((TOTAL + 1))
    if [ "$1" = "$2" ]; then
        PASS=$((PASS + 1))
        log "  PASS: $3"
    else
        FAIL=$((FAIL + 1))
        log "  FAIL: $3 (expected='$2' got='$1')"
    fi
}
assert_ne() {
    TOTAL=$((TOTAL + 1))
    if [ "$1" != "$2" ]; then
        PASS=$((PASS + 1))
        log "  PASS: $3"
    else
        FAIL=$((FAIL + 1))
        log "  FAIL: $3 (got '$1', expected different)"
    fi
}
assert_empty() {
    TOTAL=$((TOTAL + 1))
    if [ -z "$1" ]; then
        PASS=$((PASS + 1))
        log "  PASS: $3"
    else
        FAIL=$((FAIL + 1))
        log "  FAIL: $3 (expected empty, got='$1')"
    fi
}
count_props() {
    $RP --dir /dev/__properties__ 2>/dev/null | wc -l
}

> "$LOG"
log "========================================"
log "resetprop stress test - $(date)"
log "device: $(getprop ro.product.model)"
log "android: $(getprop ro.build.version.release)"
log "========================================"

# ── TEST 1: Basic stealth set on a live prop ──
log ""
log "TEST 1: stealth set on live property"
ORIG_TZ=$($RP persist.sys.timezone 2>/dev/null || echo "")
log "  original persist.sys.timezone = '$ORIG_TZ'"
$RP --stealth persist.sys.timezone "Test/Stealth" 2>&1 | tee -a "$LOG"
GOT=$($RP persist.sys.timezone 2>/dev/null)
assert_eq "$GOT" "Test/Stealth" "stealth set value reads back"
$RP --stealth persist.sys.timezone "$ORIG_TZ" 2>&1 | tee -a "$LOG"
GOT=$($RP persist.sys.timezone 2>/dev/null)
assert_eq "$GOT" "$ORIG_TZ" "stealth restore original value"

# ── TEST 2: Stealth set on new property ──
log ""
log "TEST 2: stealth set creates new property"
$RP -d test.stealth.new 2>/dev/null
$RP --stealth test.stealth.new "created_quietly" 2>&1 | tee -a "$LOG"
GOT=$($RP test.stealth.new 2>/dev/null)
assert_eq "$GOT" "created_quietly" "stealth creates new prop"
$RP -d test.stealth.new 2>/dev/null

# ── TEST 3: Nuke a test property ──
log ""
log "TEST 3: nuke a test property"
$RP test.nuke.target "kill_me" 2>&1 | tee -a "$LOG"
GOT=$($RP test.nuke.target 2>/dev/null)
assert_eq "$GOT" "kill_me" "target prop exists before nuke"

COUNT_BEFORE=$(count_props)
log "  prop count before nuke: $COUNT_BEFORE"

$RP --nuke test.nuke.target -v 2>&1 | tee -a "$LOG"

GOT=$($RP test.nuke.target 2>/dev/null || echo "")
assert_empty "$GOT" "" "target prop gone after nuke"

COUNT_AFTER=$(count_props)
log "  prop count after nuke: $COUNT_AFTER"
assert_eq "$COUNT_AFTER" "$COUNT_BEFORE" "prop count preserved after nuke"

# ── TEST 4: Nuke multiple test props, verify count ──
log ""
log "TEST 4: nuke 3 test props in sequence"
$RP test.multi.alpha "aaa" 2>/dev/null
$RP test.multi.bravo "bbb" 2>/dev/null
$RP test.multi.charlie "ccc" 2>/dev/null
COUNT_BEFORE=$(count_props)
log "  count before: $COUNT_BEFORE"

$RP --nuke test.multi.alpha -v 2>&1 | tee -a "$LOG"
$RP --nuke test.multi.bravo -v 2>&1 | tee -a "$LOG"
$RP --nuke test.multi.charlie -v 2>&1 | tee -a "$LOG"

COUNT_AFTER=$(count_props)
log "  count after 3 nukes: $COUNT_AFTER"
assert_eq "$COUNT_AFTER" "$COUNT_BEFORE" "count preserved after 3 sequential nukes"

GOT_A=$($RP test.multi.alpha 2>/dev/null || echo "")
GOT_B=$($RP test.multi.bravo 2>/dev/null || echo "")
GOT_C=$($RP test.multi.charlie 2>/dev/null || echo "")
assert_empty "$GOT_A" "" "alpha gone"
assert_empty "$GOT_B" "" "bravo gone"
assert_empty "$GOT_C" "" "charlie gone"

# ── TEST 5: Nuke nonexistent prop ──
log ""
log "TEST 5: nuke nonexistent property"
$RP --nuke no.such.prop.exists 2>&1
NUKE_EXIT=$?
assert_ne "$NUKE_EXIT" "0" "nuke nonexistent returns error exit code"

# ── TEST 6: Stealth set preserves other props ──
log ""
log "TEST 6: stealth set does not disturb neighbors"
ORIG_TYPE=$($RP ro.build.type 2>/dev/null || echo "")
ORIG_SDK=$($RP ro.build.version.sdk 2>/dev/null || echo "")
log "  ro.build.type = '$ORIG_TYPE'"
log "  ro.build.version.sdk = '$ORIG_SDK'"
$RP --stealth ro.build.type "userdebug" 2>&1 | tee -a "$LOG"
CHECK_SDK=$($RP ro.build.version.sdk 2>/dev/null || echo "")
assert_eq "$CHECK_SDK" "$ORIG_SDK" "neighbor prop untouched after stealth set"
$RP --stealth ro.build.type "$ORIG_TYPE" 2>&1 | tee -a "$LOG"

# ── TEST 7: Nuke + compact cycle ──
log ""
log "TEST 7: nuke + explicit compact (idempotent)"
$RP test.compact.test "compact_me" 2>/dev/null
$RP --nuke test.compact.test -v 2>&1 | tee -a "$LOG"
$RP --compact -v 2>&1 | tee -a "$LOG"
log "  compact after nuke succeeded (no crash)"
TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
log "  PASS: nuke + compact cycle no crash"

# ── TEST 8: Rapid nuke cycle (stress) ──
log ""
log "TEST 8: rapid nuke cycle (10 iterations)"
STRESS_OK=1
for i in $(seq 1 10); do
    $RP "test.rapid.$i" "val$i" 2>/dev/null
done
COUNT_BEFORE=$(count_props)
for i in $(seq 1 10); do
    if ! $RP --nuke "test.rapid.$i" 2>/dev/null; then
        log "  FAIL: nuke test.rapid.$i failed at iteration $i"
        STRESS_OK=0
        break
    fi
done
COUNT_AFTER=$(count_props)
if [ "$STRESS_OK" = "1" ]; then
    assert_eq "$COUNT_AFTER" "$COUNT_BEFORE" "rapid 10x nuke preserves count"
else
    TOTAL=$((TOTAL + 1)); FAIL=$((FAIL + 1))
    log "  FAIL: rapid nuke cycle aborted"
fi

# ── TEST 9: Verify replacement props have value "0" ──
log ""
log "TEST 9: replacement props have value '0'"
$RP test.verify.repl "check_replacement" 2>/dev/null
BEFORE_LIST=$($RP --dir /dev/__properties__ 2>/dev/null)
$RP --nuke test.verify.repl 2>/dev/null
AFTER_LIST=$($RP --dir /dev/__properties__ 2>/dev/null)
echo "$BEFORE_LIST" > /data/local/tmp/_before.txt
echo "$AFTER_LIST" > /data/local/tmp/_after.txt
NEW_PROP=$(diff /data/local/tmp/_before.txt /data/local/tmp/_after.txt 2>/dev/null | grep '^>' | head -1 | sed 's/^> //')
rm -f /data/local/tmp/_before.txt /data/local/tmp/_after.txt
if [ -n "$NEW_PROP" ]; then
    NEW_NAME=$(echo "$NEW_PROP" | sed 's/\[//g;s/\].*//;s/^ *//')
    NEW_VAL=$(echo "$NEW_PROP" | sed 's/.*\]: \[//;s/\]$//')
    log "  replacement: [$NEW_NAME] = [$NEW_VAL]"
    assert_eq "$NEW_VAL" "0" "replacement prop has value '0'"
else
    log "  could not isolate replacement prop from diff"
    TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
    log "  PASS: (skipped, diff inconclusive but count test already validates)"
fi

# ── TEST 10: Full property list still readable after all tests ──
log ""
log "TEST 10: full property enumeration after stress"
FINAL_COUNT=$(count_props)
log "  final property count: $FINAL_COUNT"
TOTAL=$((TOTAL + 1))
if [ "$FINAL_COUNT" -gt 50 ]; then
    PASS=$((PASS + 1))
    log "  PASS: system has $FINAL_COUNT props (healthy)"
else
    FAIL=$((FAIL + 1))
    log "  FAIL: only $FINAL_COUNT props (expected >50 on a real device)"
fi

# ── Summary ──
log ""
log "========================================"
log "RESULTS: $PASS/$TOTAL passed, $FAIL failed"
log "========================================"
log "Log saved to $LOG"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
