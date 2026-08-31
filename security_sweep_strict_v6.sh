#!/usr/bin/env bash
set -uo pipefail

SCRIPT_VERSION="SecureGSI strict sweep v6 / 2026-08-31"
FAIL=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Work whether the script is placed in:
#   SecureGSI/security_sweep_strict_v6.sh
# or accidentally in:
#   SecureGSI/rust/security_sweep_strict_v6.sh
if [ -f "$SCRIPT_DIR/rust/Cargo.toml" ]; then
    ROOT="$SCRIPT_DIR"
    RUST_DIR="$ROOT/rust"
elif [ -f "$SCRIPT_DIR/Cargo.toml" ] && [ -d "$SCRIPT_DIR/../app" ]; then
    RUST_DIR="$SCRIPT_DIR"
    ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    echo "ERROR: cannot locate SecureGSI project root / Rust crate"
    echo "script dir: $SCRIPT_DIR"
    exit 2
fi

# Prefer deny.toml next to Cargo.toml. Fall back to project root for compatibility.
if [ -f "$RUST_DIR/deny.toml" ]; then
    DENY_CONFIG="$RUST_DIR/deny.toml"
elif [ -f "$ROOT/deny.toml" ]; then
    DENY_CONFIG="$ROOT/deny.toml"
else
    DENY_CONFIG=""
fi

run() {
    local name="$1"
    shift

    echo
    echo "========== $name =========="

    "$@"
    local rc=$?

    if [ "$rc" -ne 0 ]; then
        echo ">>> FAIL rc=$rc"
        FAIL=1
    else
        echo ">>> PASS"
    fi
}

report() {
    local name="$1"
    shift

    echo
    echo "========== $name (REPORT ONLY) =========="

    "$@"
    local rc=$?

    echo ">>> report rc=$rc (does not decide the security gate by itself)"
}

skip() {
    echo
    echo "========== $1 =========="
    echo ">>> SKIP: $2"
}

echo "========================================"
echo "$SCRIPT_VERSION"
echo "ROOT=$ROOT"
echo "RUST_DIR=$RUST_DIR"
if [ -n "$DENY_CONFIG" ]; then
    echo "DENY_CONFIG=$DENY_CONFIG"
else
    echo "DENY_CONFIG=NOT FOUND"
fi
echo "========================================"

if [ ! -f "$RUST_DIR/Cargo.toml" ]; then
    echo "ERROR: expected Cargo.toml at $RUST_DIR/Cargo.toml"
    exit 2
fi

cd "$RUST_DIR" || exit 2

# ---------------------------------------------------------------------------
# 1. Rust compile/lint gates
# ---------------------------------------------------------------------------

run "cargo fmt" \
    cargo fmt --all -- --check

if [ -f "$RUST_DIR/fuzz/Cargo.toml" ]; then
    run "cargo fmt fuzz harness" \
        cargo fmt --manifest-path "$RUST_DIR/fuzz/Cargo.toml" --all -- --check
fi

run "cargo check host" \
    cargo check --all-targets --all-features

run "cargo clippy strict host" \
    cargo clippy --all-targets --all-features -- \
    -D warnings \
    -D clippy::undocumented_unsafe_blocks \
    -D clippy::mem_forget

run "cargo clippy strict Android ARM64 production" \
    cargo clippy --target aarch64-linux-android --lib --all-features -- \
    -D warnings \
    -D clippy::undocumented_unsafe_blocks \
    -D clippy::mem_forget

# ---------------------------------------------------------------------------
# 2. Tests
# ---------------------------------------------------------------------------

run "cargo test" \
    cargo test --all-features

if cargo nextest --version >/dev/null 2>&1; then
    run "cargo nextest" \
        cargo nextest run --all-features
else
    skip "cargo nextest" "not installed"
fi

# ---------------------------------------------------------------------------
# 3. Android ARM64 production build
# ---------------------------------------------------------------------------

run "Android ARM64 release build" \
    cargo build --target aarch64-linux-android --release

# ---------------------------------------------------------------------------
# 4. Dependency / supply-chain gates
# ---------------------------------------------------------------------------

if cargo audit --version >/dev/null 2>&1; then
    run "cargo audit / RustSec" \
        cargo audit
else
    skip "cargo audit" "not installed"
fi

if cargo deny --version >/dev/null 2>&1; then
    if [ -n "$DENY_CONFIG" ]; then
        run "cargo deny" \
            cargo deny --config "$DENY_CONFIG" check
    else
        echo
        echo "========== cargo deny =========="
        echo ">>> FAIL: deny.toml not found at:"
        echo "    $RUST_DIR/deny.toml"
        echo "or: $ROOT/deny.toml"
        FAIL=1
    fi
else
    skip "cargo deny" "not installed"
fi

# ---------------------------------------------------------------------------
# 5. Miri
# ---------------------------------------------------------------------------
#
# Keep Miri on a fast pure-Rust test.
# Do not interpret Argon2id under Miri: it is intentionally expensive.

if cargo +nightly miri --version >/dev/null 2>&1; then
    run "Miri fast Rust safety test" \
        cargo +nightly miri test \
        tests::wait_status_helpers_work \
        -- \
        --exact
else
    skip "Miri" "nightly/miri unavailable"
fi

# ---------------------------------------------------------------------------
# 6. Unsafe inventory
# ---------------------------------------------------------------------------

if cargo geiger --version >/dev/null 2>&1; then
    report "cargo geiger unsafe inventory" \
        cargo geiger
else
    skip "cargo geiger" "not installed"
fi

# ---------------------------------------------------------------------------
# 7. Coverage
# ---------------------------------------------------------------------------

if cargo llvm-cov --version >/dev/null 2>&1; then
    report "cargo llvm-cov" \
        cargo llvm-cov --all-features
else
    skip "cargo llvm-cov" "not installed"
fi

# ---------------------------------------------------------------------------
# 8. Formal verification
# ---------------------------------------------------------------------------

if cargo kani --version >/dev/null 2>&1; then
    if grep -Rqs '#\[kani::proof\]' src; then
        run "Kani proofs" \
            cargo kani
    else
        skip "Kani proofs" \
            "installed, but no #[kani::proof] harnesses exist yet"
    fi
else
    skip "Kani" "not installed"
fi

# ---------------------------------------------------------------------------
# 9. Fuzzing
# ---------------------------------------------------------------------------

FUZZ_LIST="$(mktemp)"

if cargo +nightly fuzz list >"$FUZZ_LIST" 2>/dev/null && [ -s "$FUZZ_LIST" ]; then
    while IFS= read -r target; do
        [ -z "$target" ] && continue

        run "cargo-fuzz: $target" \
            cargo +nightly fuzz run "$target" -- -max_total_time=60
    done <"$FUZZ_LIST"
else
    if cargo +nightly --version >/dev/null 2>&1; then
        skip "cargo-fuzz" \
            "no fuzz targets discovered"
    else
        run "cargo-fuzz nightly toolchain" \
            bash -lc 'echo "nightly Rust toolchain is required for cargo-fuzz" >&2; exit 1'
    fi
fi

rm -f "$FUZZ_LIST"

# ---------------------------------------------------------------------------
# 10. Whole-project scanners
# ---------------------------------------------------------------------------

cd "$ROOT" || exit 2

if command -v gitleaks >/dev/null 2>&1; then
    run "Gitleaks secrets" \
        gitleaks detect \
        --source . \
        --redact \
        --no-banner
else
    skip "Gitleaks" "not installed"
fi

if command -v osv-scanner >/dev/null 2>&1; then
    run "OSV dependency scan" \
        osv-scanner scan source -r .
else
    skip "OSV-Scanner" "not installed"
fi

# ---------------------------------------------------------------------------
# 11. Semgrep strict SAST
# ---------------------------------------------------------------------------
#
# Semgrep cannot prove the program bug-free. It is one layer of the gate.
#
# We run:
#   p/default  - broad high-signal community rules
#   p/rust     - Rust-specific community rules
#
# The generic rust unsafe-usage rule is NOT a vulnerability by itself in
# SecureGSI because this project intentionally uses audited FFI/syscalls/asm.
# Those unsafe sites are independently gated by:
#
#   -D clippy::undocumented_unsafe_blocks
#
# The Android exported-activity rule is treated specially:
# an activity must be exported=true when it is the intentional MAIN+LAUNCHER
# entry point. We parse AndroidManifest.xml and only downgrade that rule when
# every exported activity/activity-alias is an intentional launcher component.
#
# Any other exported activity remains blocking.
# Every other Semgrep finding is blocking.
#
# Scanner/parser errors are also blocking because an analysis that failed to
# parse targeted code must not be reported as a clean security scan.

if command -v semgrep >/dev/null 2>&1; then
    echo
    echo "========== Semgrep strict SAST =========="

    SEMGREP_JSON="$(mktemp)"
    SEMGREP_ERR="$(mktemp)"

    SEMGREP_TARGETS=("$RUST_DIR")

    if [ -d "$ROOT/app/src/main" ]; then
        SEMGREP_TARGETS+=("$ROOT/app/src/main")
    fi

    semgrep scan \
        --config=p/default \
        --config=p/rust \
        --metrics=off \
        --json \
        --exclude=rust/target \
        --exclude=.gradle \
        --exclude=app/build \
        "${SEMGREP_TARGETS[@]}" \
        >"$SEMGREP_JSON" 2>"$SEMGREP_ERR"

    SEMRC=$?

    if [ "$SEMRC" -ne 0 ]; then
        cat "$SEMGREP_ERR"
        echo ">>> FAIL: Semgrep engine/config error rc=$SEMRC"
        FAIL=1
    else
        python3 - "$SEMGREP_JSON" "$ROOT/app/src/main/AndroidManifest.xml" <<'PY'
import json
import os
import sys
import xml.etree.ElementTree as ET

json_path = sys.argv[1]
manifest_path = sys.argv[2]

with open(json_path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

raw_results = data.get("results", [])
scanner_errors = data.get("errors", [])

# Deduplicate when the same rule is present through more than one registry pack.
dedup = {}
for item in raw_results:
    start = item.get("start", {})
    end = item.get("end", {})
    key = (
        item.get("check_id", ""),
        item.get("path", ""),
        start.get("line"),
        start.get("col"),
        end.get("line"),
        end.get("col"),
    )
    dedup[key] = item

results = list(dedup.values())

GENERIC_UNSAFE_RULE = "rust.lang.security.unsafe-usage.unsafe-usage"
EXPORTED_ACTIVITY_RULE = "java.android.security.exported_activity.exported_activity"

ANDROID_NS = "http://schemas.android.com/apk/res/android"
A_NAME = f"{{{ANDROID_NS}}}name"
A_EXPORTED = f"{{{ANDROID_NS}}}exported"

def exported_activity_policy(path: str):
    """
    Return:
      (safe_launcher_only, exported_names, reason)

    Conservative rule:
    - parse failure => False
    - no exported activity => False
    - every exported activity/activity-alias must contain BOTH
      android.intent.action.MAIN and android.intent.category.LAUNCHER
    """
    if not os.path.isfile(path):
        return False, [], f"manifest not found: {path}"

    try:
        root = ET.parse(path).getroot()
    except Exception as exc:
        return False, [], f"manifest parse failed: {exc}"

    app = root.find("application")
    if app is None:
        return False, [], "manifest has no <application>"

    exported = []

    for tag in ("activity", "activity-alias"):
        for component in app.findall(tag):
            if component.get(A_EXPORTED) != "true":
                continue

            name = component.get(A_NAME, "<unnamed>")
            has_main = False
            has_launcher = False

            for intent_filter in component.findall("intent-filter"):
                actions = {
                    child.get(A_NAME)
                    for child in intent_filter.findall("action")
                }
                categories = {
                    child.get(A_NAME)
                    for child in intent_filter.findall("category")
                }

                if "android.intent.action.MAIN" in actions:
                    has_main = True

                if "android.intent.category.LAUNCHER" in categories:
                    has_launcher = True

            exported.append((name, has_main and has_launcher))

    if not exported:
        return False, [], "no exported activities found"

    all_launcher = all(is_launcher for _, is_launcher in exported)
    names = [name for name, _ in exported]

    if all_launcher:
        return True, names, "all exported activities are MAIN+LAUNCHER"

    bad = [name for name, is_launcher in exported if not is_launcher]
    return False, names, "non-launcher exported activity: " + ", ".join(bad)

launcher_only, exported_names, manifest_reason = exported_activity_policy(manifest_path)

report_only = []
blocking = []
report_only_unsafe = 0
report_only_launcher = 0

for item in results:
    rule = item.get("check_id", "")
    path = item.get("path", "")

    if rule == GENERIC_UNSAFE_RULE:
        report_only.append(item)
        report_only_unsafe += 1
        continue

    if (
        rule == EXPORTED_ACTIVITY_RULE
        and os.path.basename(path) == "AndroidManifest.xml"
        and launcher_only
    ):
        report_only.append(item)
        report_only_launcher += 1
        continue

    blocking.append(item)

print(f"Semgrep raw findings: {len(raw_results)}")
print(f"Semgrep unique findings: {len(results)}")
print(f"Report-only generic unsafe findings: {report_only_unsafe}")
print(f"Report-only intentional launcher findings: {report_only_launcher}")
print(f"Blocking security findings: {len(blocking)}")
print(f"Scanner/parser errors: {len(scanner_errors)}")
print(f"Manifest exported-activity policy: {manifest_reason}")

if exported_names:
    print("Exported activity/activity-alias components:")
    for name in exported_names:
        print(f"  {name}")

if scanner_errors:
    print()
    print("SEMGREP SCANNER/PARSER ERRORS:")
    for err in scanner_errors:
        message = err.get("message") or err.get("type") or repr(err)
        path = err.get("path", "")
        if path:
            print(f"  {path}: {message}")
        else:
            print(f"  {message}")

if blocking:
    print()
    print("BLOCKING SEMGREP FINDINGS:")
    for item in blocking:
        path = item.get("path", "?")
        start = item.get("start", {})
        line = start.get("line", "?")
        rule = item.get("check_id", "?")
        severity = item.get("extra", {}).get("severity", "?")
        message = item.get("extra", {}).get("message", "")
        print(f"  {severity} {path}:{line} [{rule}] {message}")

# Scanner errors or meaningful findings fail the gate.
sys.exit(1 if scanner_errors or blocking else 0)
PY

        PYRC=$?

        if [ "$PYRC" -ne 0 ]; then
            echo ">>> FAIL: Semgrep found blocking issues or scan errors"
            FAIL=1
        else
            echo ">>> PASS"
        fi
    fi

    if [ -s "$SEMGREP_ERR" ]; then
        echo
        echo "Semgrep stderr / diagnostics:"
        cat "$SEMGREP_ERR"
    fi

    rm -f "$SEMGREP_JSON" "$SEMGREP_ERR"
else
    skip "Semgrep" "not installed"
fi

# ---------------------------------------------------------------------------
# Final result
# ---------------------------------------------------------------------------

echo
echo "========================================"

if [ "$FAIL" -eq 0 ]; then
    echo "SECUREGSI STRICT SECURITY GATE: PASS"
else
    echo "SECUREGSI STRICT SECURITY GATE: FAIL"
fi

echo "========================================"

exit "$FAIL"
