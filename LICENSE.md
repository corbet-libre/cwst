# Licensing

Copyright 2026 Julian Y. Richard Corbet.

cwst is licensed under **LGPL-3.0-only WITH LGPL-3.0-linking-exception**, except
for one file (below). This covers the library's Rust implementation, tests and
documentation. The complete [LGPL version 3](LICENSES/LGPL-3.0-only.txt) incorporates
[GPL version 3](LICENSES/GPL-3.0-only.txt); the
[linking exception](LICENSES/LGPL-3.0-linking-exception.txt) waives the
Minimal Corresponding Source, Minimal Application Code and
installation-information duties (LGPLv3 §§4d/4e) for combined works that
link statically or dynamically.

Applications may use the library under different licenses subject to the LGPL's
conditions. Distribution must preserve the library's notices and the openness
of library modifications, including reverse engineering to debug such changes.
The application license must not restrict those library rights. No relinking
route or object files are required for combined works under the exception.

## MPL-2.0 file

[`src/veilid_crypt.rs`](src/veilid_crypt.rs) is derived from the table store of
[Veilid](https://gitlab.com/veilid/veilid) (the Veilid Team) and stays under the
[Mozilla Public License 2.0](LICENSES/MPL-2.0.txt), file by file as the MPL requires. Its
header lists the source files, the upstream commit and our modifications. The MPL is
compatible with the LGPL for the combined library (MPL-2.0 §3.3).
