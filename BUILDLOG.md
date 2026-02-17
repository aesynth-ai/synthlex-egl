# BUILDLOG

Template for audit-friendly PR receipts.

## Entry Template

- Date:
- PR/Branch:
- Commands:
  - node runner.mjs --pack <pack> --run-id <id>
  - node tests/packs/golden.mjs --pack <pack> --runA A --runB B
- Artifacts:
  - out/<pack_id>/<run_id>/metrics.json
  - out/<pack_id>/<run_id>/plan.freeze.json
  - out/<pack_id>/<run_id>/spe.ledger.jsonl
  - out/<pack_id>/<run_id>/artifact.hashes.json
- Hashes:
  - plan_freeze:
  - ledger_canonical:
- Invariants preserved:
  - Mapping logic unchanged
  - Refusal logic unchanged
  - Tier rules unchanged

## Receipt
- Date: 2026-02-13
- PR/Branch: (uncommitted local scaffold)
- Commands:
  - node runner.mjs --pack tests/packs/TH-001B.pack.json --run-id A
  - node runner.mjs --pack tests/packs/TH-001B.pack.json --run-id B
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA E --runB F
- Artifacts:
  - out/TH-001B/A/metrics.json
  - out/TH-001B/A/plan.freeze.json
  - out/TH-001B/A/spe.ledger.jsonl
  - out/TH-001B/A/artifact.hashes.json
- Hashes (golden):
  - plan_freeze: 6939c4b8f59dd4698046afe5e007649c967c17637c70a9bcb66eec0d200a1ae0
  - ledger_canonical: 48db1779f0b1467d823aa0fb5716abf71a89dd443ced6e104c3d61055f57f335
  - ledger_chain: a5ee81e2622db8ea87762ecb8b14f2c8a25628d316861c46256861092fa09d44
- Invariants preserved:
  - Mapping logic unchanged
  - Refusal logic unchanged
  - Tier rules unchanged


## Receipt (Replay-Proof Upgrade)
- Date: 2026-02-13
- Commands:
  - node runner.mjs --pack tests/packs/TH-001B.pack.json --run-id A
  - node runner.mjs --pack tests/packs/TH-001B.pack.json --run-id B
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA M --runB N
- Artifacts:
  - out/TH-001B/A/metrics.json
  - out/TH-001B/A/plan.freeze.json
  - out/TH-001B/A/spe.ledger.jsonl
  - out/TH-001B/A/artifact.hashes.json
- Golden hashes:
  - plan_freeze: 3c7c83a904f28e1622e12648722aee32f41787f5a6bd5871d1b29e0420a2645e
  - ledger_canonical: ef0fd71704d8a2582b235d1d8c82e135dbadfadf1a1c77a9777b55bc2f7c2db6
  - ledger_chain: a376dd28df0d164c6291ad03d435be5c15d9180c527f6b44fabe6cb67fe00998
- Invariants preserved:
  - Mapping logic unchanged
  - Refusal logic unchanged
  - Tier rules unchanged


## Receipt (Refusal Semantics Expansion)
- Date: 2026-02-13
- Commands:
  - node runner.mjs --pack tests/packs/TH-001B.pack.json --run-id Q
  - node runner.mjs --pack tests/packs/TH-001B.pack.json --run-id R
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA Q --runB R
- Artifact directories:
  - out/TH-001B/Q/
  - out/TH-001B/R/
- Golden hashes:
  - plan_freeze: ed5ff044021ca71b3951091aa21c8d1c8fcd2f6c2fad978b92b0a9338141a4f6
  - ledger_canonical: 9dc41c2c031ab8aab3a6a570e6bb474afabc2e921582354b63835d7d184cacd8
  - ledger_chain: 7645a133b704885dca6825873037a71f4e316af97e1d66a1bbd81af34d3f36f2
- Invariants preserved:
  - Tool surface mapping refusal semantics unchanged (unmapped => REFUSE_HARD/UNMAPPED_TOOL_SURFACE)
  - Existing determinism and canonicalization unchanged

## Receipt (TH-001C Proxy-Sourced Golden)
- Date: 2026-02-13
- Commands:
  - node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id PC --attest mock --source proxy
  - node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id PD --attest mock --source proxy
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA PC --runB PD
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA BA --runB BB
- Artifacts:
  - out/TH-001C/<run_id>/fixtures/<fixture_id>/envelope.json
- Golden hashes (proxy-source, mock attest):
  - plan_freeze: 988b94ff195dc5d8fd45bcbb8fafd592dd4ced31ac79bb1e9361e568bd4fec57
  - ledger_canonical: b9f716ec4958ba41fed33144faeeaf867d502e960815b9af0272bda4fb9bad91

## Receipt (TH-001C Stub Execution Enforcement)
- Date: 2026-02-13
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA PI --runB PJ
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA BG --runB BH
- Evidence:
  - out/TH-001C/<run_id>/fixtures/<fixture_id>/execution.json (always)
  - out/TH-001C/<run_id>/fixtures/<fixture_id>/result.json (only when admitted)
  - out/TH-001C/<run_id>/metrics.json includes no_side_effect_on_refusal_score == 1.0
- Invariants preserved:
  - executor invoked iff ALLOW (admitted)
  - REFUSE_HARD/DEFER_HITL never invoke execution

## Receipt (TH-001C Live Attestation + Path-Leak Guard)
- Date: 2026-02-13
- Commands:
  - node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE1 --source proxy --attest live
- Checks:
  - out/TH-001C/LIVE1/metrics.json: no_absolute_path_leak_score == 1.0

## Receipt (TH-001C TOCTOU Re-attest-at-Execute)
- Date: 2026-02-13
- Commands:
  - node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE_TOCTOU --source proxy --attest live
- Evidence:
  - out/TH-001C/LIVE_TOCTOU/fixtures/toctou_symlink_swap/attestation.json
  - out/TH-001C/LIVE_TOCTOU/fixtures/toctou_symlink_swap/attestation.recheck.json
  - out/TH-001C/LIVE_TOCTOU/fixtures/toctou_symlink_swap/decision.json (TOCTOU_DETECTED)
  - out/TH-001C/LIVE_TOCTOU/fixtures/toctou_symlink_swap/execution.json (executor_invoked: false)
- Checks:
  - out/TH-001C/LIVE_TOCTOU/metrics.json: toctou_block_score == 1.0
  - out/TH-001C/LIVE_TOCTOU/metrics.json: no_absolute_path_leak_score == 1.0

## Receipt (TH-001C Replay/Lane/Expiry Enforcement)
- Date: 2026-02-13
- Commands:
  - node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE_REPLAY --source proxy --attest live
- Artifacts:
  - out/TH-001C/LIVE_REPLAY/nonce_registry.jsonl
- Checks:
  - out/TH-001C/LIVE_REPLAY/metrics.json: replay_block_score == 1.0
  - out/TH-001C/LIVE_REPLAY/metrics.json: no_absolute_path_leak_score == 1.0

## Receipt (TH-001C Supply Chain Stub)
- Date: 2026-02-13
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA A --runB B
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA A --runB B
  - node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE_SKILL --source proxy --attest live
- Evidence:
  - skill.install fixtures produce no `result.json` and have `executor_invoked: false`
  - out/TH-001C/<run_id>/metrics.json includes supply_chain_block_score == 1.0

## Receipt (TH-001C SCE + Ledger Binding)
- Date: 2026-02-13
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA A --runB B
- Evidence:
  - out/TH-001C/<run_id>/fixtures/<fixture_id>/sce.json
  - out/TH-001C/<run_id>/spe.ledger.jsonl records sce_hash_sha256 for skill.install fixtures
  - out/TH-001C/<run_id>/metrics.json includes supply_chain_evidence_score == 1.0

## Receipt (TH-001C HITL Quorum Gate)
- Date: 2026-02-13
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA Q7 --runB Q8
- Evidence:
  - out/TH-001C/<run_id>/fixtures/skill_install_quorum_two_tokens/skill_install_stub_receipt.json
  - out/TH-001C/<run_id>/spe.ledger.jsonl binds skill_install_stub_receipt_hash_sha256 + ratification_token_hashes + ratification_approvers
  - out/TH-001C/<run_id>/metrics.json includes hitl_quorum_gate_score == 1.0

## Receipt (TH-001C Authority Diff Gate)
- Date: 2026-02-13
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA Q7 --runB Q8
- Evidence:
  - out/TH-001C/<run_id>/fixtures/skill_install_token_authority_drift/decision.json (HITL_AUTHORITY_DIFF_MISMATCH)
  - out/TH-001C/<run_id>/metrics.json includes hitl_authority_gate_score == 1.0

## Receipt (TH-001C Policy Version Binding + Law Bundle)
- Date: 2026-02-14
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA Q31 --runB Q32
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA CUT --runB CVT
- Artifacts:
  - out/TH-001C/<run_id>/law.bundle.json
  - out/TH-001C/<run_id>/law.bundle.hash.json
- Evidence:
  - out/TH-001C/<run_id>/plan.freeze.json entries include binding.law_bundle_sha256 (+ sub-bundles)
  - out/TH-001C/<run_id>/spe.ledger.jsonl records include law_bundle_sha256 (+ sub-bundles)
  - fixture policy_version_mismatch refused with POLICY_VERSION_MISMATCH (expected vs actual hashes recorded)
  - out/TH-001C/<run_id>/metrics.json includes policy_version_binding_score == 1.0
- Golden hashes (proxy-source, mock attest):
  - plan_freeze: cdc3468011634446a23aef53fec5fc418ddbf71cbf669f3ab38bedf0b0593c5d
  - ledger_canonical: 82f217faf855c98c35a03ac554e677eca06bf6fe9ad8b89d65c8f4f7ce0240ce

## Receipt (TH-001C Execution Permit + Real Sandbox Executor)
- Date: 2026-02-14
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA Q37 --runB Q38
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA CUU --runB CVU
- Evidence:
  - Permit gating refusals: `PERMIT_REQUIRED`, `INVALID_PERMIT`, `PERMIT_BINDING_MISMATCH`, `PERMIT_SCOPE_VIOLATION`
  - Real sandbox write (valid permit): `out/TH-001C/<run_id>/fixtures/exec_permit_write_valid/file_receipt.json`
  - Sandbox temp reset: `out/TH-001C/<run_id>/sandbox.reset.json` (root `sandbox/_th_tmp/`)
  - Pack-level law bundle: `out/TH-001C/<run_id>/law.bundle.json`
- Golden hashes (proxy-source, mock attest):
  - plan_freeze: 8154aafcf9fe5a576efcf6b2b73e2a1c43dbd61b6c6058b03776e60bab7ebdfa
  - ledger_canonical: 2aa4eb7f15aed5c1b543562db80356dc320636e83f6f75695d531091a54cf1c7

## Receipt (TH-001C Diff Preview + Permit-Scoped Patch Apply)
- Date: 2026-02-14
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA Q43 --runB Q44
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA CUW --runB CVW
- Evidence:
  - out/TH-001C/<run_id>/fixtures/<write_fixture>/diff.preview.json (always for admitted write attempts)
  - Refusals after preview: PERMIT_OP_NOT_ALLOWED, DIFF_TOO_LARGE (no side effects, no result.json)
  - Successful apply: out/TH-001C/<run_id>/fixtures/diff_write_valid_apply/file_receipt.json includes diff bindings
- Golden hashes (proxy-source, mock attest):
  - plan_freeze: 40ec370802a3a7b4c16c62c08192ff5939c030818de9195a24d3a56cf89361a0
  - ledger_canonical: b3512f58bc9610f6752ccd9d891967cfd9cae905a9bf1b9d460baf50e4d23f31

## Receipt (TH-001C Governed Git Surface Gate)
- Date: 2026-02-14
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA Q53 --runB Q54
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA Q55 --runB Q56
- Evidence:
  - out/TH-001C/<run_id>/fixtures/git_pipeline_*/git.execution.json (always)
  - out/TH-001C/<run_id>/fixtures/git_pipeline_*/git.receipt.json absent in mock
  - out/TH-001C/<run_id>/metrics.json includes git_gate_score == 1.0
- Golden hashes (proxy-source, mock attest):
  - plan_freeze: 6e107ff005b89017d83731b4734e6cbeb343c01d989fbef940bba88a967763ce
  - ledger_canonical: 58c25a54bf16723bf51b6f4dfc4697216efd82b97b8198332b0a425af4f95d8f
- Live manual check (branch-only, no remote ops):
  - node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE_GIT --source proxy --attest live --git live

## Receipt (TH-001C Publish Draft Surface, No Post)
- Date: 2026-02-15
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA S19G --runB S19H
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA S19BI --runB S19BJ
- Evidence:
  - Draft writes are sandbox-only under `sandbox/_publish_drafts/`
  - `out/TH-001C/<run_id>/fixtures/publish_draft_create_valid/diff.preview.json`
  - `out/TH-001C/<run_id>/fixtures/publish_draft_create_valid/file_receipt.json`
  - `out/TH-001C/<run_id>/spe.ledger.jsonl` contains a `kind:"publish_draft"` record
  - `out/TH-001C/<run_id>/metrics.json` includes publish_draft_score == 1.0
- Golden hashes (proxy-source, mock attest):
  - plan_freeze: de3368da1374667908daee3b294399b613e68a9ea47085be79143fe0a33b3365
  - ledger_canonical: aeb2e37e60b2a5077ae8b70cfc840fcc022facbdb2969588f2630f3b242a2fda

## Receipt (TH-001C Draft → Commit Chain, No Post)
- Date: 2026-02-15
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA S20E --runB S20F
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA S20BI --runB S20BJ
- Evidence (mock):
  - Draft stage executes for `publish_draft_commit_valid_*` (diff.preview + file_receipt + draft file)
  - Git stage is gated with no side effects:
    - `out/TH-001C/<run_id>/fixtures/publish_draft_commit_valid_*/git.execution.json` has `reason_code: HITL_REQUIRED_GIT_COMMIT`
    - no `git.receipt.json`
    - no `draft_commit_receipt.json`
  - `out/TH-001C/<run_id>/metrics.json` includes draft_commit_chain_score == 1.0
- Golden hashes (proxy-source, mock attest):
  - plan_freeze: 7066b2d6247a39aeed2984fd7679bf29d1890077aa935365bab4ee26599967bf
  - ledger_canonical: f2f509152845666733206e8a8ba691a606c880c08a85aa39e459faab9aff6ce6
- Live manual check (branch-only, no remote ops):
  - node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE_DRAFT_COMMIT --source proxy --attest live --git live

## Receipt (TH-001C Post Surface Stub, No Network)
- Date: 2026-02-15
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA S21C --runB S21D
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA S21BI --runB S21BJ
- Evidence (mock):
  - Post fixtures emit `post.execution.json` (always) and never emit `post_stub_receipt.json` (mock is gated).
  - Post gating outcomes:
    - Missing permit: `REFUSE_HARD/PERMIT_REQUIRED`
    - Missing token: `DEFER_HITL/HITL_REQUIRED_PUBLISH_POST`
    - Invalid token binding: `REFUSE_HARD/HITL_TOKEN_BINDING_MISMATCH`
- Golden hashes (proxy-source, mock attest):
  - plan_freeze: 9426f00139cf3914c795f777092b46ae57e6f01c25741e53d24565356ed1ae99
  - ledger_canonical: 65aba0999701a61a22712cb09cb2fb8607d3a0e1a8a014efedd4f76d71afea6e

## Receipt (TH-001C Network Egress Gate, Stubbed)
- Date: 2026-02-16
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA S22G --runB S22H
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA S22BI --runB S22BJ
- Evidence (mock):
  - `browser.navigate` attempts are permit-bound and always emit `egress.check.json`.
  - Exact allowlist semantics preserved: `example.com` ≠ `example.com:443`.
  - Protocol gate: HTTP refused unless permit explicitly allows it.
  - Localhost gate: `localhost` refused unless permit explicitly allows it.
- Golden hashes (proxy-source, mock attest):
  - plan_freeze: deee6498bd33a8df6cf3a62b4af0c197e6dcf3636583f69b37eda0ccb7cebbe8
  - ledger_canonical: ccc86163e1532e38c8c45fe4d612ecc3fd0cdc7970c7d6a499f025cafa631177

## Receipt (TH-001C Governed Coding Surfaces: Patch + Test)
- Date: 2026-02-16
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA S23G --runB S23H
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA S23BI --runB S23BJ
- Evidence (mock):
  - `code.patch.apply` always emits `diff.preview.json` for patch attempts; admitted applies emit `file_receipt.json`.
  - `code.test.run` is permit-gated and allowlisted; admitted runs emit `test.result.json` + `test_receipt.json`.
- Artifacts:
  - Patch: `out/TH-001C/<run_id>/fixtures/<fixture_id>/diff.preview.json`
  - Patch: `out/TH-001C/<run_id>/fixtures/<fixture_id>/file_receipt.json` (admitted only)
  - Test: `out/TH-001C/<run_id>/fixtures/<fixture_id>/test.execution.json`
  - Test: `out/TH-001C/<run_id>/fixtures/<fixture_id>/test.result.json` (admitted only)
  - Test: `out/TH-001C/<run_id>/fixtures/<fixture_id>/test_receipt.json` (admitted only)
- Golden hashes (proxy-source, mock attest):
  - plan_freeze: fce06aa6c3e6bf98925c4212af841bfbe2a60d74068b52241d628c17654cd254
  - ledger_canonical: a19b213c9d05878e36e81e3d096dfc6fdd524664a7afdb075908d5af143945d7

## Receipt (TH-001C Controlled Dependency Fetch + Live Test Executor Gate)
- Date: 2026-02-16
- Commands:
  - node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA S24G --runB S24H
  - node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA S24BI --runB S24BJ
- Evidence (mock):
  - `code.deps.fetch` is permit-gated, lockfile-hash-bound, and egress-allowlisted (stubbed execution in mock).
  - `code.test.run` remains deterministic in mock; live execution is behind `--exec live` and still allowlisted.
- Artifacts:
  - `out/TH-001C/<run_id>/fixtures/<fixture_id>/deps.execution.json` (always for deps fixtures)
  - `out/TH-001C/<run_id>/fixtures/<fixture_id>/deps.egress.check.json` (always for deps fixtures)
  - `out/TH-001C/<run_id>/fixtures/<fixture_id>/deps.receipt.json` (admitted only)
  - `out/TH-001C/<run_id>/fixtures/<fixture_id>/test.execution.json` (always for test fixtures)
- Golden hashes (proxy-source, mock attest):
  - plan_freeze: 62106608609e9d1d453cb3b91495b37c7f2540282e6a54d105bb6a89c56348ed
  - ledger_canonical: 76e1783b5930001b93928c6aad83944698d576ea63a93761f9d0371a474893b2
