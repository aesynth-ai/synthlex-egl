# Proxy (Mode-2) — Step-04

This proxy is a dry-run governor. It does not execute tools.

## Runner attestation mode

- node runner.mjs --pack tests/packs/TH-001B.pack.json --run-id BA --attest mock
- node runner.mjs --pack tests/packs/TH-001B.pack.json --run-id A --attest live

Golden determinism is tied to --attest mock.

## Proxy dry-run

Single tool-call (stdin JSON):

- node harness/tdi/proxy/proxy.mjs < tool_call.json

Fixture-to-envelope (canonical, minified):

- node harness/tdi/proxy/proxy.mjs --fixture tests/fixtures/proxy/TH-001C.fs.read.json --out out/tmp/fs_read
  - writes: out/tmp/fs_read/envelope.json

Pack mode:

- node harness/tdi/proxy/proxy.mjs --pack tests/packs/TH-001C.proxy.pack.json --run-id A

Runner proxy-source mode (TH-001C):

- node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id PC --attest mock --source proxy

## Real sandbox execution (permit-gated)

In `--source proxy` mode, sandbox-only execution is real (filesystem) but permit-gated and invoked **iff** the fixture is admitted.

Per-fixture evidence:

- `out/TH-001C/<run_id>/fixtures/<fixture_id>/execution.json` (always present)
- `out/TH-001C/<run_id>/fixtures/<fixture_id>/permit.validation.json` (always present)
- `out/TH-001C/<run_id>/fixtures/<fixture_id>/result.json` (present only when admitted)
- `out/TH-001C/<run_id>/fixtures/<fixture_id>/file_receipt.json` (present only when admitted file ops)

Sandbox temp reset (deterministic, per run):

- `out/TH-001C/<run_id>/sandbox.reset.json`
- Sandbox root used for real execution: `sandbox/_th_tmp/`

## Diff preview + permit-scoped patch

Sandbox writes are two-stage:

1) `diff.preview.json` is generated deterministically (no side effects)
2) The execution permit must authorize applying that diff (allowed ops + size/line thresholds)
3) Only then is the patch applied and `file_receipt.json` emitted

## Governed Git surface (branch-only, no remote)

Git operations are available only via the `git.pipeline_commit_from_diff` surface and are permit-bound + HITL-gated.

Mock golden remains side-effect-free (git is gated in mock mode):

- node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA A --runB B

Live integration (manual; allows local branch-only commit, no remote ops):

- node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE_GIT --source proxy --attest live --git live

Per-fixture evidence:

- `out/TH-001C/<run_id>/fixtures/<fixture_id>/git.execution.json` (always)
- `out/TH-001C/<run_id>/fixtures/<fixture_id>/git.receipt.json` (success only)

## Publish draft surface (no post)

`publish.draft.create` generates deterministic markdown drafts under `sandbox/_publish_drafts/` via the existing diff-first, permit-scoped write pipeline.

Evidence (fixture `publish_draft_create_valid`):

- draft file: `sandbox/_publish_drafts/x_post_<slug>.md`
- `out/TH-001C/<run_id>/fixtures/publish_draft_create_valid/diff.preview.json`
- `out/TH-001C/<run_id>/fixtures/publish_draft_create_valid/file_receipt.json`
- `out/TH-001C/<run_id>/spe.ledger.jsonl` includes a `kind:"publish_draft"` record

No posting/network integration exists in this step.

## Draft → Commit chain (no post, live-only git)

`publish.draft.commit` performs a draft write (diff-first + permit-scoped) and then attempts a governed local git commit.

- Mock golden: draft write executes, git stage is gated (no git side effects, no receipts)
- Live integration: requires `--attest live --git live` plus a permit with git scope and a valid git HITL token

Manual live run:

- node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE_DRAFT_COMMIT --source proxy --attest live --git live

Evidence (per fixture):

- `out/TH-001C/<run_id>/fixtures/<fixture_id>/git.execution.json`
- `out/TH-001C/<run_id>/fixtures/<fixture_id>/draft_commit_receipt.json` (success only)

## Post surface (stub only, no network)

`publish.post.x` and `publish.post.x_thread` are pure stubs: they never perform network calls. They are permit-bound and HITL-gated, and only emit a deterministic stub receipt when admitted in live mode.

Mock golden (always gated, no receipt):

- node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA A --runB B

Optional live stub run (still no network; emits `post_stub_receipt.json` only if permit + valid post HITL token are provided):

- node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE_POST_STUB --source proxy --attest live

Per-fixture evidence (post fixtures):

- `out/TH-001C/<run_id>/fixtures/<fixture_id>/post.execution.json` (always)
- `out/TH-001C/<run_id>/fixtures/<fixture_id>/post_stub_receipt.json` (admitted live only)

## Network egress gate (permit-bound, stubbed)

Any outbound attempt is governed by an explicit permit `scope.egress` allowlist (exact-match, no DNS). `browser.navigate` is stubbed (no sockets) but always emits deterministic evidence in `egress.check.json`.

Canonical target examples (host-only vs explicit port):

- `https://example.com/...` → `example.com`
- `https://example.com:443/...` → `example.com:443`
- `example.com` ≠ `example.com:443` (distinct grants)

Mock golden:

- node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA A --runB B

Per-fixture evidence (egress fixtures):

- `out/TH-001C/<run_id>/fixtures/<fixture_id>/egress.check.json` (always for browser.navigate fixtures)

## Governed coding surfaces (patch/test)

Two developer-friendly coding surfaces are available in `--source proxy` mode:

- `code.patch.apply`: diff-first preview and permit-scoped apply (reuses the Step-17 write pipeline).
- `code.test.run`: permit-gated, allowlisted test execution (stubbed in mock golden; live integration can be added separately).
- `code.deps.fetch`: permit-gated, allowlisted dependency fetch (stubbed in mock golden) with lockfile hash binding and egress allowlist checks.

Mock golden (replay-proof, proxy-source):

- node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA A --runB B

Live integration (manual):

- node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE_CODE --source proxy --attest live --exec live --deps live

Per-fixture evidence:

- Patch: `diff.preview.json` (always for patch attempts), `file_receipt.json` (admitted only)
- Test: `test.execution.json` (always), `test.result.json` + `test_receipt.json` (admitted only)
- Deps: `deps.execution.json` (always), `deps.result.json` + `deps.receipt.json` (admitted only), `deps.egress.check.json`

## Live attestation (integration)

Golden remains pinned to `--attest mock` only. Live is integration-only:

- node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE1 --source proxy --attest live

## TOCTOU live test (re-attest at execute)

Simulates a swap between the initial live attestation snapshot and the execution boundary re-attestation.

- node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE_TOCTOU --source proxy --attest live

Evidence (fixture `toctou_symlink_swap`):

- `out/TH-001C/<run_id>/fixtures/toctou_symlink_swap/attestation.json` (initial snapshot)
- `out/TH-001C/<run_id>/fixtures/toctou_symlink_swap/attestation.recheck.json` (pre-exec re-attest)
- `out/TH-001C/<run_id>/fixtures/toctou_symlink_swap/decision.json` has `reason_code: TOCTOU_DETECTED`
- `out/TH-001C/<run_id>/fixtures/toctou_symlink_swap/execution.json` has `executor_invoked: false`

## Nonce + replay + lane + expiry (live integration)

Mock golden remains pinned to `--attest mock` only:

- node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA A --runB B

Live integration run (writes `nonce_registry.jsonl` and proves `NONCE_REPLAY`, `LANE_MISMATCH`, `PLAN_EXPIRED`):

- node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id LIVE_REPLAY --source proxy --attest live

## Governed skill.install (supply chain stub)

`skill.install` is mapped and evaluated, but never executes. Even when the artifact hash matches and a capability diff is present, the default outcome is `DEFER_HITL`.

Skill install attempts emit `sce.json` and the ledger binds `sce_hash_sha256`.

## Law bundle binding (policy + authority + mapping)

In `--source proxy` runs, every plan-freeze entry, ledger record, and execution evidence is bound to the exact policy + authority + mapping set by hash. If a fixture supplies an `expected_law_bundle_sha256` that does not match the computed bundle, it is refused with `POLICY_VERSION_MISMATCH`.

Pack-level artifacts:

- `out/TH-001C/<run_id>/law.bundle.json`
- `out/TH-001C/<run_id>/law.bundle.hash.json`

For T4 / `SURFACE_EXPANSION`, human ratification is quorum-gated:

- 0 tokens: `DEFER_HITL` (`HITL_REQUIRED_SURFACE_EXPANSION`)
- 1 valid token: `DEFER_HITL` (`HITL_QUORUM_NOT_MET`)
- 2 valid tokens with distinct `approver_id`: admitted (`HITL_QUORUM_ACCEPTED`) and emits `skill_install_stub_receipt.json` (still no install)

Authority-diff egress normalization note: host-only entries (e.g. `example.com`) are canonicalized as `example.com` (no implicit port). `example.com` and `example.com:443` are distinct grants. URL forms are accepted; if no explicit port is present (e.g. `https://Example.COM/path`), the canonical form is still host-only (`example.com`), and if a port is explicit (e.g. `https://Example.COM:443/`), it is preserved (`example.com:443`).
