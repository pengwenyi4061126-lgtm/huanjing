# Ordinary-account local verdict

- Contract: 2026-11-25.32
- Contract Markdown SHA256: A9EFBD95EE670816B23C9BF7F0B57642AD6DDCACACFE5B8819EEE777587D48F3
- Target: Claude Desktop 5.1231.2.0 Windows x64 MSIX
- Raw MSIX: read-only
- Account/Profile: ordinary account, Profile 1, known-good cache baseline

## Result

- prelogin_local_profile_pass: **pass-bounded**
- ordinary_account_local_verdict: **local-scope-pass-with-explicit-boundaries**
- supported_subset_pass: **false**
- anti_association_pass: **false**
- functional_pass: **false**

## CRR 61

- 41 pass, 0 fail, 9 unverified, 9 unsupported, 2 N/A.
- Unverified entries are blocked-external-input and are not silently downgraded.
- Unsupported entries retain their boundary evidence and do not count as pass.

## G6 boundary

- Current-revision file sync, actual module load, mapped-image hashes, and executable live rollback pass.
- Profile 1 lifecycle: two direct launches succeeded with stable ant-did; graceful stop returned rc=2 in both runs, then Profile-scoped controlled stop returned rc=0 with zero Claude residuals.

## Deferred

- Cowork, computer-use, real MCP, post-login feature flags, real TelemetryEvent, server opaque body, and second-account switch tests remain deferred.
- No CDP, pushState, shim, or probe self-call is used to manufacture evidence.

## Evidence

- coverage-contract-json: CLAUDE-COVERAGE-GOAL-V2.json (34B2817762A9D653D9C4D84B6A8CC4ECA2AB1DBBF596B5267E4274BED2788B11)
- coverage-contract-markdown: CLAUDE-COVERAGE-GOAL-V2.md (A9EFBD95EE670816B23C9BF7F0B57642AD6DDCACACFE5B8819EEE777587D48F3)
- G0-source-and-profile-freeze: native/evidence/claude-coverage/g0-freeze-current-20261126-112215/g0-freeze.json (9F95FF717FBABB59E52C45BD14570E5B90D225016DA1FACCEEAD6471B1F0C69A)
- G5c-alternating-profile-verification: native/evidence/claude-coverage/g5c-v231-alternating-20261125-0500/g5c-verification.json (C0AF52BF23A7B2CB7391C1DC41733EF5669684062514E7F022763213B3BAF22C)
- G6-current-delivery-reconciliation: native/evidence/claude-coverage/g6-reconciliation-local-rev32-20261126-resume/delivery-reconciliation.json (0426BF8B1683F5F04CF86AE578794D8995DE6EDC751430E7768DD6321507489B)
- G6-current-mapped-memory-ledger: native/evidence/claude-coverage/g6-memory-module-existing-20261126-continue-local-r2/actual-memory-module-ledger.json (04E9A6B927E8A8DFCEC933FF81548E548FFC08AEBE8FFF2FDF2F956108DBE037)
- G1b-current-revision-closure: native/evidence/claude-coverage/g1b-current-rev32-20261126-continue/closure.json (C66E50144CCDD5820D598D3E5E5F8DE75F9EA1AE08B1A0AAD4E66362D6782184)
- current-Profile1-runtime-readonly: native/evidence/claude-coverage/current-profile1-runtime-20261126-continue-r3/current-profile1-runtime.json (4ABEC30DD5D23D18261B771FE49326B1A6C2F580EFFD81F44D947870F85171D0)
- Profile1-direct-lifecycle-regression: native/evidence/claude-coverage/profile1-direct-lifecycle-20261126-130141067/verification.json (58EF75BD28D138658F35549119EB8106F7FC1D7E02E0F7781D4E18C409C490DC)
- G7-independent-review: native/evidence/claude-coverage/g7-review-v232-20261126-continue/g7-review.json (9932849D436E1F3E2BF9FF0E7358141EFC2320EF6030C67C6A1B017D7E04C14B)
- P2-external-input-gate: native/evidence/claude-coverage/p2-input-gate-20261125-0520/requirements.json (A2D94AE32E3E462EAA8C09E5328EFEFF117D817F37ED7529C62A953BD3B94CCA)
