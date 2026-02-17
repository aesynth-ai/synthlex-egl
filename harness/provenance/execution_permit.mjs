import { sha256_hex, stableStringify } from "../intent_compiler/hash.mjs";

function hasAbsWindowsPathString(s) {
  if (typeof s !== "string") return false;
  return /^[a-zA-Z]:\\/.test(s) || /^\\\\/.test(s) || /[a-zA-Z]:\\/.test(s);
}

function toPosix(p) {
  return String(p ?? "").replace(/\\/g, "/");
}

function isRepoRelativePath(p) {
  const s = toPosix(p).trim();
  if (!s) return false;
  if (hasAbsWindowsPathString(s)) return false;
  if (s.startsWith("/")) return false;
  if (s.includes("\u0000")) return false;
  const parts = s.split("/").filter(Boolean);
  if (parts.some((x) => x === "." || x === "..")) return false;
  return true;
}

function sha256HexUtf8(text) {
  return sha256_hex(Buffer.from(String(text ?? ""), "utf8"));
}

export function canonicalize_permit_payload(permit) {
  if (!permit || typeof permit !== "object") return stableStringify(null);
  const p = { ...permit };
  delete p.permit_sha256;
  return stableStringify(p);
}

export function compute_permit_sha256(permit) {
  const canonical = canonicalize_permit_payload(permit);
  return `sha256:${sha256HexUtf8(canonical)}`;
}

export function validate_execution_permit({ permit, expected, now_iso }) {
  if (!permit) return { ok: false, code: "PERMIT_REQUIRED", reason: "execution permit required" };
  if (typeof permit !== "object") {
    return { ok: false, code: "INVALID_PERMIT", reason: "execution permit must be an object" };
  }
  if (permit.schema_id !== "EGL.EXECUTION_PERMIT" || (permit.version !== "0.1.0" && permit.version !== "0.2.0")) {
    return { ok: false, code: "INVALID_PERMIT", reason: "permit schema_id/version mismatch" };
  }

  const provided = typeof permit.permit_sha256 === "string" ? permit.permit_sha256 : "";
  const computed = compute_permit_sha256(permit);
  if (provided !== computed) {
    return { ok: false, code: "INVALID_PERMIT", reason: "permit self-hash mismatch", computed, provided };
  }

  const expiry_ts = typeof permit.expiry_ts === "string" ? permit.expiry_ts : "";
  if (expiry_ts) {
    const expMs = Date.parse(expiry_ts);
    const nowMs = Date.parse(String(now_iso ?? ""));
    if (!Number.isNaN(expMs) && !Number.isNaN(nowMs) && nowMs > expMs) {
      return { ok: false, code: "PERMIT_EXPIRED", reason: "permit expired" };
    }
  }

  const lane_id = typeof permit.lane_id === "string" ? permit.lane_id : "";
  const attestation_nonce = typeof permit.attestation_nonce === "string" ? permit.attestation_nonce : "";
  const bindings = permit.bindings && typeof permit.bindings === "object" ? permit.bindings : {};
  const scope = permit.scope && typeof permit.scope === "object" ? permit.scope : {};

  if (expected) {
    if (typeof expected.lane_id === "string" && expected.lane_id.length > 0 && lane_id !== expected.lane_id) {
      return { ok: false, code: "PERMIT_BINDING_MISMATCH", reason: "lane_id binding mismatch" };
    }
    if (
      typeof expected.attestation_nonce === "string" &&
      expected.attestation_nonce.length > 0 &&
      attestation_nonce !== expected.attestation_nonce
    ) {
      return { ok: false, code: "PERMIT_BINDING_MISMATCH", reason: "attestation_nonce binding mismatch" };
    }

    if (
      typeof expected.law_bundle_sha256 === "string" &&
      expected.law_bundle_sha256.length > 0 &&
      String(bindings.law_bundle_sha256 ?? "") !== expected.law_bundle_sha256
    ) {
      return { ok: false, code: "PERMIT_BINDING_MISMATCH", reason: "law bundle binding mismatch" };
    }
    if (
      typeof expected.plan_hash_sha3_512 === "string" &&
      expected.plan_hash_sha3_512.length > 0 &&
      String(bindings.plan_hash_sha3_512 ?? "") !== expected.plan_hash_sha3_512
    ) {
      return { ok: false, code: "PERMIT_BINDING_MISMATCH", reason: "plan hash binding mismatch" };
    }
    if (
      typeof expected.intent_hash_sha3_512 === "string" &&
      expected.intent_hash_sha3_512.length > 0 &&
      String(bindings.intent_hash_sha3_512 ?? "") !== expected.intent_hash_sha3_512
    ) {
      return { ok: false, code: "PERMIT_BINDING_MISMATCH", reason: "intent hash binding mismatch" };
    }
  }

  if (String(scope.execution_target ?? "") !== "SANDBOX") {
    return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "execution_target must be SANDBOX" };
  }

  const fsScope = scope.filesystem && typeof scope.filesystem === "object" ? scope.filesystem : {};
  const read_roots = Array.isArray(fsScope.read_roots) ? fsScope.read_roots : [];
  const write_roots = Array.isArray(fsScope.write_roots) ? fsScope.write_roots : [];
  const deny_paths = Array.isArray(fsScope.deny_paths) ? fsScope.deny_paths : [];

  for (const r of [...read_roots, ...write_roots, ...deny_paths]) {
    if (!isRepoRelativePath(r)) {
      return { ok: false, code: "INVALID_PERMIT", reason: "permit contains non-repo-relative paths" };
    }
  }

  return { ok: true, permit_sha256: computed };
}

export function validate_git_scope({
  permit,
  expected_base_branch,
  expected_branch,
}) {
  if (!permit || typeof permit !== "object") {
    return { ok: false, code: "INVALID_PERMIT", reason: "permit missing" };
  }
  if (permit.version !== "0.2.0") {
    return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "git scope requires permit version 0.2.0" };
  }
  const scope = permit.scope && typeof permit.scope === "object" ? permit.scope : {};
  const git = scope.git && typeof scope.git === "object" ? scope.git : null;
  if (!git) return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "git scope missing" };

  if (git.deny_remote !== true || git.deny_push !== true) {
    return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "git deny_remote/deny_push must be true" };
  }
  if (git.allow !== true) {
    return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "git.allow must be true" };
  }

  const base = String(git.allowed_base_branch ?? "");
  if (expected_base_branch && base !== expected_base_branch) {
    return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "base branch not allowed by permit" };
  }

  const prefix = String(git.allowed_branch_prefix ?? "");
  if (!prefix || typeof expected_branch !== "string" || !expected_branch.startsWith(prefix)) {
    return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "branch prefix not allowed" };
  }

  const repoRoot = String(git.repo_root ?? "");
  if (repoRoot !== ".") {
    return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "git.repo_root must be '.'" };
  }

  const flags = [
    "allow_create_branch",
    "allow_apply_patch",
    "allow_stage",
    "allow_commit",
  ];
  for (const f of flags) {
    if (git[f] !== true) {
      return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: `git.${f} must be true` };
    }
  }

  return { ok: true, code: null, reason: null };
}

export function validate_publish_scope({ permit, surface, payload_bytes, commit_binding }) {
  if (!permit || typeof permit !== "object") {
    return { ok: false, code: "INVALID_PERMIT", reason: "permit missing" };
  }
  const scope = permit.scope && typeof permit.scope === "object" ? permit.scope : {};
  const publish = scope.publish && typeof scope.publish === "object" ? scope.publish : null;
  if (!publish) return { ok: false, code: "PUBLISH_SCOPE_VIOLATION", reason: "publish scope missing" };

  if (publish.allow !== true) {
    return { ok: false, code: "PUBLISH_SCOPE_VIOLATION", reason: "publish.allow must be true" };
  }

  const allowed = Array.isArray(publish.allowed_surfaces) ? publish.allowed_surfaces.map(String) : [];
  const want = surface === "x_thread" ? "x_thread" : "x";
  if (!allowed.includes(want) && !allowed.includes("x")) {
    return { ok: false, code: "PUBLISH_SCOPE_VIOLATION", reason: "surface not allowed by permit" };
  }

  const max_payload_bytes = Number(publish.max_payload_bytes);
  if (Number.isFinite(max_payload_bytes) && max_payload_bytes > 0) {
    if (Number(payload_bytes ?? 0) > max_payload_bytes) {
      return { ok: false, code: "PAYLOAD_TOO_LARGE", reason: "payload exceeds max_payload_bytes" };
    }
  }

  if (publish.require_commit_binding === true && !commit_binding) {
    return { ok: false, code: "MISSING_POST_BINDING", reason: "commit/receipt binding required" };
  }

  return { ok: true, code: null, reason: null };
}

export function validate_egress_scope({ permit }) {
  if (!permit || typeof permit !== "object") {
    return { ok: false, code: "INVALID_PERMIT", reason: "permit missing" };
  }
  const scope = permit.scope && typeof permit.scope === "object" ? permit.scope : {};
  const egress = scope.egress && typeof scope.egress === "object" ? scope.egress : null;
  if (!egress) return { ok: false, code: "EGRESS_SCOPE_VIOLATION", reason: "egress scope missing" };
  if (egress.allow !== true) return { ok: false, code: "EGRESS_SCOPE_VIOLATION", reason: "egress.allow must be true" };
  const allowlist = Array.isArray(egress.allowlist) ? egress.allowlist : [];
  if (!allowlist.every((x) => typeof x === "string")) {
    return { ok: false, code: "INVALID_PERMIT", reason: "egress.allowlist must be string[]" };
  }
  return { ok: true, code: null, reason: null };
}

export function validate_exec_scope({ permit, env_profile, cmd }) {
  if (!permit || typeof permit !== "object") {
    return { ok: false, code: "INVALID_PERMIT", reason: "permit missing" };
  }
  const scope = permit.scope && typeof permit.scope === "object" ? permit.scope : {};
  const exec = scope.exec && typeof scope.exec === "object" ? scope.exec : null;
  if (!exec) return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "exec scope missing" };
  if (exec.allow !== true) return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "exec.allow must be true" };

  const profiles = Array.isArray(exec.profiles) ? exec.profiles.map(String) : [];
  if (typeof env_profile !== "string" || env_profile.length === 0) {
    return { ok: false, code: "EXEC_PROFILE_NOT_ALLOWED", reason: "env_profile required" };
  }
  if (!profiles.includes(env_profile)) {
    return { ok: false, code: "EXEC_PROFILE_NOT_ALLOWED", reason: "env_profile not allowed by permit" };
  }

  const allowed_cmds = Array.isArray(exec.allowed_cmds) ? exec.allowed_cmds.map(String) : [];
  if (!allowed_cmds.includes(String(cmd ?? ""))) {
    return { ok: false, code: "EXEC_CMD_NOT_ALLOWED", reason: "cmd not allowed by permit" };
  }

  return { ok: true, code: null, reason: null };
}

export function validate_deps_scope({ permit, env_profile, cmd, lockfile_path }) {
  if (!permit || typeof permit !== "object") {
    return { ok: false, code: "INVALID_PERMIT", reason: "permit missing" };
  }
  const scope = permit.scope && typeof permit.scope === "object" ? permit.scope : {};
  const deps = scope.deps && typeof scope.deps === "object" ? scope.deps : null;
  if (!deps) return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "deps scope missing" };
  if (deps.allow !== true) return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "deps.allow must be true" };

  const profiles = Array.isArray(deps.profiles) ? deps.profiles.map(String) : [];
  if (typeof env_profile !== "string" || env_profile.length === 0) {
    return { ok: false, code: "EXEC_PROFILE_NOT_ALLOWED", reason: "env_profile required" };
  }
  if (!profiles.includes(env_profile)) {
    return { ok: false, code: "EXEC_PROFILE_NOT_ALLOWED", reason: "env_profile not allowed by permit" };
  }

  const allowed_cmds = Array.isArray(deps.allowed_cmds) ? deps.allowed_cmds.map(String) : [];
  if (!allowed_cmds.includes(String(cmd ?? ""))) {
    return { ok: false, code: "EXEC_CMD_NOT_ALLOWED", reason: "cmd not allowed by permit" };
  }

  const lockRoots = Array.isArray(deps.lockfile_roots) ? deps.lockfile_roots.map(String) : [];
  if (typeof lockfile_path !== "string" || lockfile_path.length === 0 || lockfile_path === "OUTSIDE_REPO") {
    return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "lockfile_path must be repo-relative" };
  }
  if (!isRepoRelativePath(lockfile_path)) {
    return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "lockfile_path must be repo-relative" };
  }
  if (lockRoots.length > 0 && !pathWithinRoots({ relPath: lockfile_path, roots: lockRoots })) {
    return { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "lockfile_path not within permit lockfile_roots" };
  }

  return { ok: true, code: null, reason: null };
}

export function pathWithinRoots({ relPath, roots }) {
  const p = toPosix(relPath);
  const rs = Array.isArray(roots) ? roots.map((r) => toPosix(r)) : [];
  for (const r of rs) {
    const root = r.endsWith("/") ? r : `${r}/`;
    if (p === r || p.startsWith(root)) return true;
  }
  return false;
}
