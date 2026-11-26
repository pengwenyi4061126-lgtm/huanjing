# Claude delivery reconciliation

- Run: g6-reconciliation-local-rev32-20261126-resume
- Contract: 2026-11-25.32
- Contract Markdown hash matches JSON declaration: True
- Mode: read-only reconciliation; no build, deployment, service mutation, rollback, or cleanup was performed by this script.

## Results

- Source native/dist files: 66
- Core installed .cac/native sync: **pass**
- Full native/dist tree sync: **unverified**; missing: 2; mismatched: 0
- Driver payload comparison: **same-bytes**; mismatches: 0; missing: 0
- Claude actual loaded-module evidence: **observed-controlled-run-file-and-memory-hash**
- Memory-loaded module hash: **pass-mapped-image-hash-controlled-run**
- Live rollback: **pass-executable-live-rollback**

## Blocking boundary

This artifact consumes separately captured runtime and rollback evidence. The core installed set follows Sync-NativeLayer's six-file deployment contract; the full dist tree is reported separately because auxiliary probes are not copied into .cac/native. Mapped-image SHA-256 remains distinct from raw PE file SHA-256; the live rollback result is bounded to installed-file mutation/restoration and service/process cleanup.