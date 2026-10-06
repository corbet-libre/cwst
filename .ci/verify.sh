#!/usr/bin/env bash
set -euo pipefail
# Merge stderr into stdout so failure messages stay in the kept log.
# Output routing only; commands and gates unchanged.
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"

# native gate (ci.yml native job). The resolve step's cargo update is
# intentionally not preserved: verify runs against the committed snapshot.
python3 .github/scripts/check-lock.py
python3 .github/scripts/check-lock.py
python3 .github/scripts/test-lock.py
node --test .github/scripts/test-auto-merge.mjs
python3 .github/scripts/test-coverage.py
rustc --version --verbose
cargo fmt --all -- --check || { cargo fmt --all; git diff > formatting.patch; exit 1; }
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked

# wasm gate (ci.yml wasm job). chromedriver/chromium come from the runner;
# google-chrome resolves to the pinned chromium via the runner compat shim.
# These tools report on stderr, which the kept log did not contain for the
# failed run, so keep the merge here (same commands and flags) to keep the
# next failure diagnosable.
echo 'stage: wasm clippy+vectors'
# The nix wrapper `clang` on PATH breaks the wasm32 C build (host glibc
# headers, minicov hardcodes `clang`); resolve `clang` to the pinned
# unwrapped compiler for this leg only: the subshell keeps native builds
# and nightly coverage on the wrapper.
: "${CWST_WASM_CLANG_BIN:?Missing unwrapped wasm clang from run-cached.sh}"
(
export PATH="$CWST_WASM_CLANG_BIN:$PATH"
cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D warnings 2>&1
wasm-pack test --headless --chrome -- --locked -- --nocapture 2>&1
)

# coverage gate (ci.yml coverage job, nightly branch instrumentation).
# Product builds stay on stable; only this gate uses nightly.
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --branch --json --output-path coverage.json --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --lcov --output-path coverage.lcov --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --text --output-path coverage.txt --ignore-filename-regex '/tests/'
python3 .github/scripts/check-coverage.py coverage.lcov coverage.json coverage.txt

# wasm-coverage gate (ci.yml wasm-coverage job, current nightly). CI installs
# cargo-llvm-cov and the lock-matched wasm-bindgen-cli via install-action
# (prebuilt upstream release assets); cargo-llvm-cov comes from the runner and
# the identical byte-pinned wasm-bindgen asset is fetched with its published
# checksum. CHROMEDRIVER points at the runner driver instead of /usr/bin.
# The wasm-coverage CI job runs entirely on the nightly toolchain; select it
# here with the same RUSTC/CARGO/PATH/RUSTUP_TOOLCHAIN pattern so every
# bare `cargo`/`rustc` below resolves nightly exactly as in CI.
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
version=$(python3 -c 'import tomllib; print(next(p["version"] for p in tomllib.load(open("Cargo.lock", "rb"))["package"] if p["name"] == "wasm-bindgen"))')
archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
base="https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}"
runner_tmp="${RUNNER_TEMP}/cwst-wasm-runner"
mkdir -p "$runner_tmp"
cd "$runner_tmp"
curl -A 'dependency-ci' --fail --location --retry 3 --remote-name "$base/$archive"
curl -A 'dependency-ci' --fail --location --retry 3 --remote-name "$base/$archive.sha256sum"
checksum=$(cut -d ' ' -f1 "$archive.sha256sum")
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check
tar -xzf "$archive" --strip-components=1
echo "$PWD" >> "$GITHUB_PATH"
export PATH="$PWD:$PATH"
cd "$OLDPWD"
rustc --version --verbose
"$NIGHTLY_CARGO" llvm-cov --version
clang --version
command -v clang >/dev/null || { echo 'missing clang' >&2; exit 2; }
# requirements.txt pins `selenium>=4.49.0`; the runner supplies a pinned
# python3.withPackages env (selenium plus transitive deps and pip), so the
# import below succeeds without network. The pip install stays as the CI fallback.
python3 -c 'import selenium; print(selenium.__version__)' || python3 -m pip install -r .github/requirements.txt
# browser-coverage-runner.py hardcodes Service("/usr/bin/chromedriver") and
# sets no binary_location. Adapt exactly those two narrowly-checked facts in
# a job-temp copy: driver service path -> $CHROMEDRIVER, and binary_location
# -> $CHROME_BIN (resolved pinned chromium executable). Any other source
# drift fails the gate; Chrome options and all tests are preserved byte for
# byte (diff audit: exactly one removed line, two added lines).
export CHROMEDRIVER="${CHROMEDRIVER:-$(command -v chromedriver || echo /usr/bin/chromedriver)}"
export CHROME_BIN="${CHROME_BIN:-$(command -v chromium || command -v chromium-browser || command -v google-chrome || echo chromium)}"
test -x "$CHROMEDRIVER" || { echo "missing chromedriver at $CHROMEDRIVER" >&2; exit 2; }
test -x "$CHROME_BIN" || { echo "chromium not executable at $CHROME_BIN" >&2; exit 2; }
runner_src=.github/scripts/browser-coverage-runner.py
runner_copy="$RUNNER_TEMP/browser-coverage-runner.py"
anchor_hits=$(grep -cF 'driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)' "$runner_src" || true)
test "$anchor_hits" -eq 1
existing_binary_location=$(grep -cF 'binary_location' "$runner_src" || true)
test "$existing_binary_location" -eq 0
python3 - "$runner_src" "$runner_copy" "$CHROMEDRIVER" "$CHROME_BIN" <<'PYEOF'
import sys
src, dst, driver, chrome = sys.argv[1:5]
text = open(src).read()
anchor = 'driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)'
assert text.count(anchor) == 1, 'runner driver-construction text drifted'
replacement = 'options.binary_location = "' + chrome + '"\n        driver = webdriver.Chrome(service=Service("' + driver + '"), options=options)'
open(dst, 'w').write(text.replace(anchor, replacement))
PYEOF
drift_removed=$(diff "$runner_src" "$runner_copy" | grep -c '^<' || true)
drift_added=$(diff "$runner_src" "$runner_copy" | grep -c '^>' || true)
test "$drift_removed" -eq 1
test "$drift_added" -eq 2
grep -F "$CHROMEDRIVER" "$runner_copy"
grep -F "$CHROME_BIN" "$runner_copy"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="python3 $runner_copy"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="-Zno-profiler-runtime -Clink-args=--no-gc-sections --cfg=owned_browser_coverage"
export WASM_BINDGEN_TEST_ONLY_WEB="1"
export WASM_BINDGEN_SPLIT_LINKED_MODULES="1"
export CC_wasm32_unknown_unknown="$CWST_WASM_CLANG"
: "${CWST_WASM_CLANG_BIN:?Missing unwrapped wasm clang from run-cached.sh}"
(
export PATH="$CWST_WASM_CLANG_BIN:$PATH"
"$NIGHTLY_CARGO" llvm-cov test --locked --branch --coverage-target-only --target wasm32-unknown-unknown --json --output-path wasm-coverage.json --ignore-filename-regex '/tests/'
)
"$NIGHTLY_CARGO" llvm-cov report --target wasm32-unknown-unknown --lcov --output-path wasm-coverage.lcov --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --target wasm32-unknown-unknown --text --output-path wasm-coverage.txt --ignore-filename-regex '/tests/'
)
python3 .github/scripts/check-coverage.py wasm-coverage.lcov wasm-coverage.json wasm-coverage.txt wasm

# browser-coverage gate (ci.yml browser-coverage job). No toolchain: plain npm.
export RUSTUP_TOOLCHAIN=stable
npm ci --ignore-scripts --no-audit --no-fund
npm test
