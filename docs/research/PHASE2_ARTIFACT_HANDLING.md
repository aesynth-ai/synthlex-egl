# ClawLab Phase II -- Artifact Handling Convention (EGL / Synthlex-EGL)
Status: Research Context (Non-binding)

Phase II is **observational + diagnostic**. The purpose of artifacts is forensic traceability:
we want to reconstruct *exactly* what happened (and when), without editorial cleanup.

**Rule:** Artifacts are **raw and unedited**. If something is sensitive, do not "clean" it -- store it safely offline and summarize safely in docs.

---

## 1) Core Principle

Phase II artifacts are treated as **evidence**, not documentation.

Documentation may quote or summarize artifacts, but artifacts themselves must remain:
- **timestamped**
- **complete**
- **unaltered**
- **locally stored**
- **outside git by default**

---

## 2) Where Artifacts Live (Local Only)

Artifacts MUST be stored under a local-only folder that is ignored by git.

Recommended default (Windows):
- `sandbox/_clawlab_artifacts/`

Each run creates a unique subfolder:

- `sandbox/_clawlab_artifacts/PH2-A1_YYYYMMDD_HHMMSS/`

This repo's `.gitignore` is configured to ignore:
- `**/_clawlab_artifacts/`
- `**/*.log`, `**/*.trace`, `**/*.har`
- `**/*.receipt.json`, `**/*.permit.json`

**Do not change this behavior** without explicit governance review.

---

## 3) Minimum Artifact Bundle (Required After Each Scenario)

After every Phase II scenario (A1, A2, B1, ...), capture the following bundle:

### A) Prompt (exact)
- The exact user prompt sent to the agent framework.

File:
- `prompt.txt`

### B) Full gateway logs (timestamped)
- Must include the full segment from:
  - immediately before prompt
  - tool selection (if any)
  - execution attempt
  - completion or refusal

File (examples):
- `gateway.log`
- or `gateway.PH2-A1.log`

### C) Tool invocation payload (raw JSON)
- The exact tool call payload(s) emitted by the agent runtime.

File:
- `tool_payload.raw.json`
- If multiple: `tool_payload.001.raw.json`, `tool_payload.002.raw.json`

### D) Permit request (if generated)
- If EGL generated a permit request, store it raw.

File:
- `permit_request.raw.json`

### E) Workspace diff (before/after)
Capture both snapshots and the diff:

Files:
- `workspace.pre.tree.txt`
- `workspace.post.tree.txt`
- `workspace.tree.diff.txt`

### F) Network traces (if any)
If network operations occurred, capture the trace.

Files (examples):
- `netstat.pre.txt`, `netstat.post.txt`
- `egress.trace`
- `request.har` (if applicable)

### G) Execution timing breakdown
Prefer tool-provided step timings (raw).
At minimum capture wall-time stamps.

Files:
- `t0.timestamp.txt` (UTC ISO8601)
- `t1.timestamp.txt` (UTC ISO8601)
- `timing.raw.txt` (if runtime provides)

---

## 4) Naming Convention (Non-Negotiable)

Folder:
- `PH2-<CASE>_YYYYMMDD_HHMMSS`

Case examples:
- `PH2-A1_20260217_141233`
- `PH2-C3_20260217_151005`

Within a folder, file names should be consistent across cases.
This allows automated parsing later.

---

## 5) What Never Goes Into Git

Never commit:
- `.env` or any real keys/tokens
- raw artifact bundles under `_clawlab_artifacts/`
- logs that contain secrets
- HAR files with headers if they contain tokens
- vendor SDK caches, local registries, node_modules

If you need to preserve something for external review:
- store it offline
- create a sanitized excerpt
- write a short summary in `docs/` or `BUILDLOG.md`

---

## 6) What *Does* Go Into Git (Summaries Only)

Git should include:
- protocols and procedures (Phase docs)
- schemas and parsers
- surface maps (tool_surface_map, allowlists) **only if they do not contain secrets**
- sanitized findings summaries
- classification results (BEP tags)

Recommended summary file:
- `docs/PHASE2_FINDINGS.md`

Optional log-style summary:
- `BUILDLOG.md` (high-level progress, no raw payloads)

---

## 7) Phase II Evidence Rules

Artifacts must be:
- **raw**
- **complete**
- **unaltered**
- **time-ordered**
- **captured immediately** after the run

If you must redact for sharing:
- create a second file named:
  - `*.shared.redacted.*`
- and keep the raw version local-only.

---

## 8) "Stop at First Violated Invariant" (BEP)

During analysis, stop at the first violated invariant and classify the anomaly:

- **L1 Structural** (authority boundary / scope violation)
- **L2 Relational** (plan -> action mismatch)
- **L3 Temporal** (retry storms, oscillation, TOCTOU-like sequencing)
- **L4 Perceptual** (phantom success, path confusion, misbelief)

This file defines storage conventions only; classification belongs in findings docs.

---

## 9) Example Folder Contents (PH2-A1)

`sandbox/_clawlab_artifacts/PH2-A1_YYYYMMDD_HHMMSS/`
- `prompt.txt`
- `gateway.log`
- `tool_payload.raw.json`
- `permit_request.raw.json` (if any)
- `workspace.pre.tree.txt`
- `workspace.post.tree.txt`
- `workspace.tree.diff.txt`
- `netstat.pre.txt`
- `netstat.post.txt`
- `t0.timestamp.txt`
- `t1.timestamp.txt`
- `timing.raw.txt` (if any)

---

## 10) Why This Matters

Phase II is building the factual record needed to decide interception placement:
- **Plane A** (pre-tool selection)
- **Plane B** (post-selection / pre-execution)

Bad artifacts produce fake conclusions.
Good artifacts produce "execution physics."
