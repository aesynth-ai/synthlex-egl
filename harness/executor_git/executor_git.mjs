import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { sha256_hex, stableStringify } from "../intent_compiler/hash.mjs";

function runGit({ repoRoot, args }) {
  const env = {
    ...process.env,
    GIT_TERMINAL_PROMPT: "0",
    GIT_OPTIONAL_LOCKS: "0",
  };
  const r = spawnSync("git", args, {
    cwd: repoRoot,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "utf8",
  });
  return {
    status: r.status ?? 1,
    stdout: String(r.stdout ?? ""),
    stderr: String(r.stderr ?? ""),
  };
}

function assertOk(step, r) {
  if (r.status !== 0) {
    const err = new Error(`git ${step} failed`);
    err.meta = { step, status: r.status, stdout: r.stdout, stderr: r.stderr };
    throw err;
  }
}

function toPosix(p) {
  return String(p ?? "").replace(/\\/g, "/");
}

function isRepoRelativePath(p) {
  const s = toPosix(p).trim();
  if (!s) return false;
  if (/^[a-zA-Z]:\\/.test(s) || /^\\\\/.test(s) || /[a-zA-Z]:\\/.test(s)) return false;
  if (s.startsWith("/")) return false;
  if (s.includes("\u0000")) return false;
  const parts = s.split("/").filter(Boolean);
  if (parts.some((x) => x === "." || x === "..")) return false;
  return true;
}

function extractPathsFromUnifiedDiff(diff_unified) {
  const out = new Set();
  const lines = String(diff_unified ?? "").split(/\r?\n/);
  for (const line of lines) {
    if (!line.startsWith("+++ ")) continue;
    const rhs = line.slice(4).trim();
    if (!rhs.startsWith("b/")) continue;
    const p = rhs.slice(2);
    if (p === "dev/null") continue;
    if (!isRepoRelativePath(p)) continue;
    out.add(toPosix(p));
  }
  return [...out].sort((a, b) => a.localeCompare(b));
}

export function git_pipeline_commit_from_diff({
  repoRoot,
  base_branch,
  new_branch,
  diff_unified,
  commit_message,
}) {
  const steps = [];

  const head0 = runGit({ repoRoot, args: ["rev-parse", "--abbrev-ref", "HEAD"] });
  assertOk("rev-parse-head0", head0);
  const original_branch = head0.stdout.trim();

  // Ensure base branch exists locally.
  assertOk("rev-parse", runGit({ repoRoot, args: ["rev-parse", "--verify", `refs/heads/${base_branch}`] }));

  // Create branch from base (no checkout of base).
  assertOk("branch-create", runGit({ repoRoot, args: ["branch", new_branch, base_branch] }));
  steps.push("branch_create");

  // Checkout new branch.
  assertOk("checkout", runGit({ repoRoot, args: ["checkout", new_branch] }));

  // Apply patch via git apply from stdin (no index yet).
  const patchPath = path.resolve(repoRoot, "sandbox", "_th_tmp", "git_patch.diff");
  fs.mkdirSync(path.dirname(patchPath), { recursive: true });
  fs.writeFileSync(patchPath, String(diff_unified ?? ""), "utf8");
  assertOk("apply", runGit({ repoRoot, args: ["apply", "--whitespace=nowarn", patchPath] }));
  steps.push("apply_patch");

  // Stage only paths touched by the diff.
  const paths = extractPathsFromUnifiedDiff(diff_unified);
  assertOk("stage", runGit({ repoRoot, args: ["add", "--", ...paths] }));
  steps.push("stage");

  // Commit.
  assertOk("commit", runGit({ repoRoot, args: ["commit", "--no-gpg-sign", "--no-verify", "-m", String(commit_message ?? "EGL commit")] }));
  steps.push("commit");

  const head = runGit({ repoRoot, args: ["rev-parse", "HEAD"] });
  assertOk("rev-parse-head", head);
  const commit_hash = head.stdout.trim();

  const changed = runGit({ repoRoot, args: ["show", "--name-only", "--pretty=format:", "HEAD"] });
  assertOk("show-changed", changed);
  const changed_files = changed.stdout
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b));

  // Restore original branch (best-effort).
  try {
    runGit({ repoRoot, args: ["checkout", original_branch] });
  } catch {
    // ignore
  }

  return {
    ok: true,
    steps,
    commit_hash,
    changed_files,
  };
}

export function git_execution_evidence({
  branch_created,
  patch_applied,
  staged,
  committed,
  new_branch,
  base_branch,
  reason_code,
}) {
  return {
    schema_id: "EGL.GIT_EXECUTION",
    version: "0.1.0",
    base_branch: base_branch ?? null,
    new_branch: new_branch ?? null,
    branch_created: Boolean(branch_created),
    patch_applied: Boolean(patch_applied),
    staged: Boolean(staged),
    commit_created: Boolean(committed),
    reason_code: reason_code ?? null,
  };
}

export function stableGitReceipt({
  branch,
  base_branch,
  commit_hash,
  changed_files,
  diff_sha256s,
  law_bundle_sha256,
  plan_hash,
  intent_hash,
  permit_sha256,
}) {
  return {
    branch,
    base_branch,
    commit_hash,
    changed_files: Array.isArray(changed_files) ? changed_files : [],
    diff_sha256s: Array.isArray(diff_sha256s) ? diff_sha256s : [],
    law_bundle_sha256,
    plan_hash,
    intent_hash,
    permit_sha256,
  };
}

export function stableGitReceiptHashSha256(receipt) {
  // Canonical/minified.
  const canonical = stableStringify(receipt);
  return `sha256:${sha256_hex(Buffer.from(canonical, "utf8"))}`;
}
