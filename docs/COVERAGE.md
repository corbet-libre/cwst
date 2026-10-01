# Coverage contract

CI measures production Rust lines and branches with cargo-llvm-cov and requires
100% of both. A zero-count report fails. Test harness files are excluded from the
production denominator. No production paths are excluded at this stage. Browser
vectors execute in headless Chrome; a compile check is not execution evidence.
Native coverage does not establish coverage of wasm-only adapters.

Stable Rust runs product validation. Nightly is used only for upstream Rust's
experimental branch instrumentation. CI resolves dependencies once and uploads
Cargo.lock; all jobs consume that exact snapshot with --locked. Weekly CI refreshes
the snapshot and Dependabot proposes manifest/lock updates. A failed coverage gate
is an open requirement, never evidence of complete coverage.

## Unreachable defensive mapping

The gate uses LLVM LCOV line/branch evidence and excludes only the exact
RustCrypto encryption error mapping in veilid_crypt. An explicit 8 MiB bound
precedes encryption, far below ChaCha's counter-exhaustion limit. Allocation
failure aborts and does not return this Result error. The production mapping
remains fail-closed. The source-pinned allowlist fails if it moves or becomes
covered. Native tests inject failures in the established Entropy port at secret
generation, key wrapping and data encryption; none of those failures is excluded.
All format, corruption, file failure, bounds, race and acknowledgement paths
remain measured. This exclusion is subject to independent review.

Native LLVM evidence measures the cross-platform engine and native adapter.
The wasm-only Rust IndexedDB glue and JavaScript transaction adapter require the
separate actual-browser vectors; native line coverage does not measure them.
No whole-library cross-platform 100% claim follows from a green native report.

The wasm-coverage job additionally instruments the real browser Rust execution
using wasm-bindgen's experimental minicov runtime and cargo-llvm-cov. It follows
upstream's documented flags and temporary nightly-2026-02-18 coverage-runtime
workaround; this does not pin product dependencies or change stable checks.
See https://wasm-bindgen.github.io/wasm-bindgen/wasm-bindgen-test/coverage.html and
https://github.com/wasm-bindgen/wasm-bindgen/blob/main/.github/workflows/codecov.yml.
The strict gate remains red until this additional report is complete; JavaScript
transaction coverage remains a separate measurement requirement.

JavaScript is measured separately with Istanbul instrumentation inside actual
Chrome contexts using Playwright. The transaction tests exercise missing storage,
malformed existing values, predecessor mismatch, simultaneous tabs and a platform
fault that ignores requested strict durability. The strict gate checks statements,
lines, functions and branches. No IndexedDB implementation or domain logic is
replaced. The versionless opener has no blocked-upgrade callback: it never asks
to upgrade an existing database, and aborts accidental initial creation.
