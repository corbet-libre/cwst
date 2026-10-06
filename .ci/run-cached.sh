#!/usr/bin/env bash
# Execute the manifest's selected checks with content-keyed result reuse.
set -euo pipefail
# Merge stderr into stdout so failure messages stay in the kept log.
# Output routing only; commands and gates unchanged.
exec 2>&1
: "${CCID_BIN:?Missing verified ccid job runtime}"
: "${CI_COMMIT_SHA:?Missing verified source revision}"
: "${CI_REPOSITORY_URL:?Missing canonical repository identity}"
: "${CHECKS:?Missing declared check selection}"
if [ "$CHECKS" != "verify" ]; then
  echo "CHECKS must be exactly 'verify', got: $CHECKS" >&2
  exit 2
fi
cache_root=${CI_CACHE_ROOT:-${CARGO_HOME:-}}
[[ $cache_root = /* ]] || { echo 'An absolute persistent CI_CACHE_ROOT or CARGO_HOME is required' >&2; exit 2; }
namespace=$(printf '%s' "$CI_REPOSITORY_URL" | sha256sum | cut -c1-24)
state="$cache_root/ccid-cached/$namespace"
toolchains=${CI_TOOLCHAIN_ROOT:-$cache_root/ccid-cached/toolchains}
[[ $toolchains = /* ]] || { echo 'CI_TOOLCHAIN_ROOT must be absolute' >&2; exit 2; }
mkdir -p "$state" "$toolchains"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
exec 9>"$state/lock"
flock -w "${CI_TIMEOUT:-2700}" 9
mkdir -p "$state/moon-cache/hashes" "$state/moon-cache/outputs" "$state/moon-home"
mkdir -p .moon/cache
ln -s "$state/moon-cache/hashes" .moon/cache/hashes
ln -s "$state/moon-cache/outputs" .moon/cache/outputs
# Tool installation is an explicit part of this job, in persistent CI storage.
# Node 24 matches the ci.yml lts/* setup-node step; npm ships with nix nodejs
# and serves the `npm ci` + `npm test` browser-coverage gate (see verify.sh).
# wasm-pack + chromedriver/chromium serve the headless-chrome wasm gate and
# the browser-coverage vectors; curl fetches the lock-matched wasm runner;
# clang is the wasm-coverage C linker (CC_wasm32_unknown_unknown, see
# verify.sh).
tool_source=github:NixOS/nixpkgs/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436
tool_paths=$(nix build --no-link --print-out-paths "$tool_source#moon" "$tool_source#proto" "$tool_source#nodejs_24" "$tool_source#curl" "$tool_source#wasm-pack" "$tool_source#clang" "$tool_source#chromedriver" "$tool_source#chromium" "$tool_source#cargo-llvm-cov")
for path in $tool_paths; do PATH="$path/bin:$PATH"; done
# requirements.txt pins `selenium>=4.49.0`; supply a pinned python env with
# selenium plus its transitive deps (urllib3/trio/websocket-client/
# certifi/…) and pip (probe + CI pip fallback) so the gate needs no PyPI round
# trip. A singular python3Packages.selenium site-packages dir on PYTHONPATH is
# insufficient: transitive imports would fail. Same nixpkgs revision.
python_env=$(nix build --no-link --print-out-paths --impure --expr '(builtins.getFlake "'"$tool_source"'").legacyPackages.${builtins.currentSystem}.python3.withPackages (p: [ p.selenium p.pip ])')
test -n "$python_env" || { echo 'nix python selenium env resolution failed' >&2; exit 2; }
PATH="$python_env/bin:$PATH"
python3 -c 'import selenium; print(selenium.__version__)'
export PROTO_HOME="$toolchains/proto" RUSTUP_HOME="$toolchains/rustup"
shared_cargo_home=${CARGO_HOME:-}
export CARGO_HOME="$toolchains/cargo" MOON_HOME="$state/moon-home"
export PROTO_AUTO_CLEAN=false PROTO_TELEMETRY=false PROTO_YES=true
export RUSTUP_INIT_SKIP_PATH_CHECK=yes RUSTUP_TOOLCHAIN=stable
export PATH="$(dirname "$CCID_BIN"):$CARGO_HOME/bin:$PROTO_HOME/shims:$PROTO_HOME/bin:$PATH"
export CI_JOBS="${CI_JOBS:-2}" CARGO_BUILD_JOBS="${CI_JOBS:-2}"
export RUST_TEST_THREADS="${CI_TEST_THREADS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
if [ -n "${GIT_CONFIG_COUNT:-}" ]; then
  echo 'GIT_CONFIG_COUNT is already set; refusing to overwrite job git config' >&2
  exit 2
fi
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0='url.https://git.corbet.ch/corbet-libs/.insteadOf'
export GIT_CONFIG_VALUE_0='https://github.com/corbet-libs/'
export GIT_CONFIG_KEY_1='url.https://git.corbet.ch/corbet-foss/.insteadOf'
export GIT_CONFIG_VALUE_1='https://github.com/corbet-foss/'
# Shared-first toolchain lock: jobs share a provisioned toolchain and take
# exclusive only to provision missing pieces. Same lock file, so old
# whole-job-exclusive runners interoperate (they just serialize).
TOOLCHAIN_LOCK_FILE="$toolchains/install.lock"
TOOLCHAIN_LOCK_TIMEOUT="${CI_TIMEOUT:-2700}"
TOOLCHAIN_WANT_NIGHTLY=1
TOOLCHAIN_WASM_TARGETS="stable:wasm32-unknown-unknown nightly:wasm32-unknown-unknown"
# shellcheck source=toolchain-lock.sh
source "$(dirname "${BASH_SOURCE[0]}")/toolchain-lock.sh"
toolchain_ensure
# Per-repo helper installs: no helper cargo installs in this job (wasm runner
# arrives via byte-pinned curl tarball in verify.sh under $RUNNER_TEMP);
# keep a per-repo install root on PATH so any future helper never mutates
# shared CARGO_HOME.
export CARGO_INSTALL_ROOT="$state/install-bin"
mkdir -p "$CARGO_INSTALL_ROOT/bin"
export PATH="$CARGO_INSTALL_ROOT/bin:$PATH"
cargo_bin=$("$CARGO_HOME/bin/rustup" which --toolchain stable cargo)
test -x "$cargo_bin"
export PATH="$(dirname "$cargo_bin"):$PATH"
export CCID_SOURCE_REVISION="$CI_COMMIT_SHA"
# CI resolves chrome from the ubuntu image (/usr/bin/google-chrome,
# /usr/bin/chromedriver); point both at the pinned nix binaries. The shim
# keeps PATH-resolved `google-chrome` working; CHROME_BIN serves the
# playwright executablePath override (see browser/checkpoint.test.js).
mkdir -p "$RUNNER_TEMP/chrome-shim"
printf '#!/bin/sh\nexec chromium "$@"\n' > "$RUNNER_TEMP/chrome-shim/google-chrome"
chmod +x "$RUNNER_TEMP/chrome-shim/google-chrome"
export PATH="$RUNNER_TEMP/chrome-shim:$PATH"
export CHROMEDRIVER="${CHROMEDRIVER:-$(command -v chromedriver)}"
export CHROME_BIN="${CHROME_BIN:-$(command -v chromium)}"
test -x "$CHROMEDRIVER" || { echo "nix chromedriver not executable at $CHROMEDRIVER" >&2; exit 2; }
test -x "$CHROME_BIN" || { echo "nix chromium not executable at $CHROME_BIN" >&2; exit 2; }
"$CCID_BIN" render --repo "$PWD" --check
proto --version
moon --version
rustc -vV
cargo --version
wasm-pack --version
node --version
npm --version
python3 --version
python3 -m pip --version
curl --version
clang --version
chromedriver --version
chromium --version
rustup run nightly rustc -vV
rustup run nightly cargo llvm-cov --version
"$CCID_BIN" cached --repo "$PWD" --check verify
test -s ".ccid/results/verify.jsonl"
