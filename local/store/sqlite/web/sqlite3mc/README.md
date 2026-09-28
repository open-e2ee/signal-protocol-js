# Vendored SQLite3 Multiple Ciphers Wasm engine

`sqlite3.mjs` and `sqlite3.wasm` come from the
[SQLite3 Multiple Ciphers v2.5.1 release](https://github.com/utelle/SQLite3MultipleCiphers/releases/tag/v2.5.1),
archive `sqlite3mc-2.5.1-sqlite-3.53.4-wasm.zip`, directory
`sqlite3mc-wasm-3530400/jswasm/`. The build is SQLite 3.53.4 with the
SQLite3 Multiple Ciphers amalgamation, compiled with Emscripten.

`sqlite3.wasm` is unmodified. `sqlite3.mjs` carries the patches that
`PATCHES` in [`scripts/sqlite-engine.mjs`](../../../../../scripts/sqlite-engine.mjs)
records, each with its reason:

- `keep-pool-on-failed-install`: when the `opfs-sahpool` install fails, the
  release deletes the pool directory, and the database with it. The patched
  glue releases the VFS and keeps the directory.
- `settle-handles-before-release`: when one access handle of the pool fails
  to open, the patched glue waits for every other open to settle before it
  releases the handles, so no handle stays open in a paused pool.
- `report-quota-as-full`: when a write to the origin private file system
  exceeds the storage quota, the release reports `SQLITE_IOERR`. The patched
  glue reports `SQLITE_FULL`, so the store rejects with
  `StorageQuotaExceededError`.

`pins.json` records the archive sha256, the signer of the release
`SHA256SUMS`, and for each file the released sha256, its patches, and the
vendored sha256:

- `npm run build` checks each file against its pin, and checks that removing
  its patches gives the released file, before it copies the files into `dist`.
- `node ./scripts/sqlite-engine.mjs verify-release` downloads the release,
  checks the Sigstore signature of `SHA256SUMS` with `cosign`, checks the
  archive and each released file against the pins, and checks that the patches
  turn each released file into the vendored file.
- `node ./scripts/sqlite-engine.mjs vendor` makes the same checks, then writes
  the patched files and their pins.

`sqlite3.d.mts` declares only the part of the engine API that
`../worker.ts` uses.

The licenses of the engine and of the sources compiled into it are in
[`THIRD_PARTY_NOTICES.md`](../../../../../THIRD_PARTY_NOTICES.md).

To update the engine, update the release fields of `pins.json` and each
`releaseSha256`, run `vendor`, fix any patch that no longer applies, run
`verify-release`, and update the notices. Never edit a vendored file by hand:
the build rejects an edit that `PATCHES` does not record.
