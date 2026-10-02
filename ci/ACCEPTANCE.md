# Fixed Crow acceptance

The `.crow/acceptance.yaml` workflow verifies the exact committed source and
reviewed canonical dependency closure, runs original locked preflight, performs
one original CCID fresh Cargo resolution, then runs fixed native, Wasm, browser,
coverage and dependency-policy phases against that same candidate lock. No caller
can choose or omit gates. Native and Wasm coverage use original 100% checkers and
unchanged exclusions; actual browser execution is mandatory. Changed locks must
be reviewed and committed, then the new exact source must qualify before merge.

The maintained wasm-bindgen CLI/runner is selected only from the candidate lock,
its official release SHA is verified, only exact regular binary members are read,
and versions/binary/archive/checksum identities are retained outside source before
any owner compilation. Browser setup is the actual qualified Crow4114 immutable
closure; coverage-only setup is Crow4116, which exercised actual browser profile
capture and matching nightly/LLVM branch export. Product coverage is still required.
Preflight refuses missing stable/nightly Wasm stdlib and browser/driver tools.
These workflow files are source-ready, not executed acceptance or release proof.
Final audit retains native/Wasm coverage reports, original/resolved metadata,
all phase logs, matching runner identity and source/resolution receipts. No
protection transition or merger follows merely from the existence of this file.

Storage also copies its exact original JS browser project into external artifacts,
performs one npm lock refresh, retains both locks, then runs original Playwright/
Istanbul real IndexedDB CAS/race/durability tests and npm advisories. Every phase
binds the npm candidate lock and exact input hashes. The final audit independently
compares executed JS/manifest input hashes with the original source archive and
requires all four original JS coverage metrics at 100%. A changed npm candidate
must likewise be committed and the new exact source requalified. Qualified wasm-pack addon4118 is sourced after the original stable/browser setup.
Its no-install launcher receives both exact candidate CLI/runner hashes, lock hash,
a fresh owned /tmp cache and the original Chrome capability file. The original
launcher input receipt is retained and checked against the same candidate; it is
preflight evidence only, never a substitute for the actual browser phase.
