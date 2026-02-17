import { sha256_hex, stableStringify } from "../intent_compiler/hash.mjs";

function tokenPayload(token) {
  if (!token || typeof token !== "object") return null;
  return {
    schema_id: token.schema_id,
    version: token.version,
    sce_hash_sha256: token.sce_hash_sha256,
    authority_diff_sha256: token.authority_diff_sha256,
    intent_hash: token.intent_hash,
    lane_id: token.lane_id,
    attestation_nonce: token.attestation_nonce,
    expires_ts: token.expires_ts,
    approver_id: token.approver_id,
  };
}

export function ratification_token_sha256(token) {
  const payload = tokenPayload(token);
  if (!payload) return null;
  const canonical = stableStringify(payload);
  return sha256_hex(Buffer.from(canonical, "utf8"));
}

export function build_ratification_token({
  sce_hash_sha256,
  authority_diff_sha256,
  intent_hash,
  lane_id,
  attestation_nonce,
  expires_ts,
  approver_id,
}) {
  const base = {
    schema_id: "EGL.RATIFICATION_TOKEN",
    version: "0.1.0",
    sce_hash_sha256: String(sce_hash_sha256 ?? ""),
    authority_diff_sha256: String(authority_diff_sha256 ?? ""),
    intent_hash: String(intent_hash ?? ""),
    lane_id: String(lane_id ?? ""),
    attestation_nonce: String(attestation_nonce ?? ""),
    expires_ts: String(expires_ts ?? ""),
    approver_id: String(approver_id ?? ""),
  };
  return {
    ...base,
    token_sha256: ratification_token_sha256(base),
  };
}

export function validate_ratification_token({
  token,
  expected,
  now_iso,
}) {
  if (!token || typeof token !== "object") {
    return { ok: false, code: "INVALID_HITL_TOKEN", reason: "token missing or not an object" };
  }
  if (token.schema_id !== "EGL.RATIFICATION_TOKEN" || token.version !== "0.1.0") {
    return { ok: false, code: "INVALID_HITL_TOKEN", reason: "schema_id/version mismatch" };
  }

  const computed = ratification_token_sha256(token);
  if (!computed || typeof token.token_sha256 !== "string" || token.token_sha256 !== computed) {
    return { ok: false, code: "INVALID_HITL_TOKEN", reason: "token_sha256 self-check failed" };
  }

  if (typeof token.approver_id !== "string" || token.approver_id.length === 0) {
    return { ok: false, code: "INVALID_HITL_TOKEN", reason: "approver_id missing" };
  }

  const expMs = Date.parse(String(token.expires_ts ?? ""));
  const nowMs = Date.parse(String(now_iso ?? ""));
  if (!Number.isNaN(expMs) && !Number.isNaN(nowMs) && nowMs > expMs) {
    return { ok: false, code: "HITL_TOKEN_EXPIRED", reason: "token expired" };
  }

  const bind = (field) => String(token[field] ?? "") === String(expected?.[field] ?? "");
  const fields = [
    "authority_diff_sha256",
    "sce_hash_sha256",
    "intent_hash",
    "lane_id",
    "attestation_nonce",
  ];
  for (const f of fields) {
    if (!bind(f)) {
      if (f === "authority_diff_sha256") {
        return { ok: false, code: "HITL_AUTHORITY_DIFF_MISMATCH", reason: `binding mismatch: ${f}` };
      }
      return { ok: false, code: "HITL_TOKEN_BINDING_MISMATCH", reason: `binding mismatch: ${f}` };
    }
  }

  return { ok: true, code: null, reason: null };
}

function gitTokenPayload(token) {
  if (!token || typeof token !== "object") return null;
  return {
    schema_id: String(token.schema_id ?? ""),
    version: String(token.version ?? ""),
    law_bundle_sha256: String(token.law_bundle_sha256 ?? ""),
    plan_hash: String(token.plan_hash ?? ""),
    intent_hash: String(token.intent_hash ?? ""),
    lane_id: String(token.lane_id ?? ""),
    attestation_nonce: String(token.attestation_nonce ?? ""),
    expires_ts: String(token.expires_ts ?? ""),
    approver_id: String(token.approver_id ?? ""),
    git_branch: String(token.git_branch ?? ""),
    diff_sha256: String(token.diff_sha256 ?? ""),
  };
}

export function git_ratification_token_sha256(token) {
  const payload = gitTokenPayload(token);
  if (!payload) return null;
  const canonical = stableStringify(payload);
  return sha256_hex(Buffer.from(canonical, "utf8"));
}

export function build_git_ratification_token({
  law_bundle_sha256,
  plan_hash,
  intent_hash,
  lane_id,
  attestation_nonce,
  expires_ts,
  approver_id,
  git_branch,
  diff_sha256,
}) {
  const base = {
    schema_id: "EGL.GIT_RATIFICATION_TOKEN",
    version: "0.1.0",
    law_bundle_sha256: String(law_bundle_sha256 ?? ""),
    plan_hash: String(plan_hash ?? ""),
    intent_hash: String(intent_hash ?? ""),
    lane_id: String(lane_id ?? ""),
    attestation_nonce: String(attestation_nonce ?? ""),
    expires_ts: String(expires_ts ?? ""),
    approver_id: String(approver_id ?? ""),
    git_branch: String(git_branch ?? ""),
    diff_sha256: String(diff_sha256 ?? ""),
  };
  return {
    ...base,
    token_sha256: git_ratification_token_sha256(base),
  };
}

export function validate_git_ratification_token({ token, expected, now_iso }) {
  if (!token || typeof token !== "object") {
    return { ok: false, code: "INVALID_GIT_HITL_TOKEN", reason: "token missing or not an object" };
  }
  if (token.schema_id !== "EGL.GIT_RATIFICATION_TOKEN" || token.version !== "0.1.0") {
    return { ok: false, code: "INVALID_GIT_HITL_TOKEN", reason: "schema_id/version mismatch" };
  }

  const computed = git_ratification_token_sha256(token);
  if (!computed || typeof token.token_sha256 !== "string" || token.token_sha256 !== computed) {
    return { ok: false, code: "INVALID_GIT_HITL_TOKEN", reason: "token_sha256 self-check failed" };
  }

  if (typeof token.approver_id !== "string" || token.approver_id.length === 0) {
    return { ok: false, code: "INVALID_GIT_HITL_TOKEN", reason: "approver_id missing" };
  }

  const expMs = Date.parse(String(token.expires_ts ?? ""));
  const nowMs = Date.parse(String(now_iso ?? ""));
  if (!Number.isNaN(expMs) && !Number.isNaN(nowMs) && nowMs > expMs) {
    return { ok: false, code: "HITL_TOKEN_EXPIRED", reason: "token expired" };
  }

  const bind = (field) => String(token[field] ?? "") === String(expected?.[field] ?? "");
  const fields = [
    "law_bundle_sha256",
    "plan_hash",
    "intent_hash",
    "lane_id",
    "attestation_nonce",
    "git_branch",
    "diff_sha256",
  ];
  for (const f of fields) {
    if (!bind(f)) {
      return { ok: false, code: "GIT_HITL_TOKEN_BINDING_MISMATCH", reason: `binding mismatch: ${f}` };
    }
  }

  return { ok: true, code: null, reason: null };
}

function publishPostTokenPayload(token) {
  if (!token || typeof token !== "object") return null;
  return {
    schema_id: String(token.schema_id ?? ""),
    version: String(token.version ?? ""),
    law_bundle_sha256: String(token.law_bundle_sha256 ?? ""),
    plan_hash: String(token.plan_hash ?? ""),
    intent_hash: String(token.intent_hash ?? ""),
    lane_id: String(token.lane_id ?? ""),
    attestation_nonce: String(token.attestation_nonce ?? ""),
    expires_ts: String(token.expires_ts ?? ""),
    approver_id: String(token.approver_id ?? ""),
    surface: String(token.surface ?? ""),
    payload_sha256: String(token.payload_sha256 ?? ""),
    source_commit_hash: String(token.source_commit_hash ?? ""),
    source_receipt_hash_sha256: String(token.source_receipt_hash_sha256 ?? ""),
  };
}

export function publish_post_ratification_token_sha256(token) {
  const payload = publishPostTokenPayload(token);
  if (!payload) return null;
  const canonical = stableStringify(payload);
  return sha256_hex(Buffer.from(canonical, "utf8"));
}

export function build_publish_post_ratification_token({
  law_bundle_sha256,
  plan_hash,
  intent_hash,
  lane_id,
  attestation_nonce,
  expires_ts,
  approver_id,
  surface,
  payload_sha256,
  source_commit_hash,
  source_receipt_hash_sha256,
}) {
  const base = {
    schema_id: "EGL.PUBLISH_POST_RATIFICATION_TOKEN",
    version: "0.1.0",
    law_bundle_sha256: String(law_bundle_sha256 ?? ""),
    plan_hash: String(plan_hash ?? ""),
    intent_hash: String(intent_hash ?? ""),
    lane_id: String(lane_id ?? ""),
    attestation_nonce: String(attestation_nonce ?? ""),
    expires_ts: String(expires_ts ?? ""),
    approver_id: String(approver_id ?? ""),
    surface: String(surface ?? ""),
    payload_sha256: String(payload_sha256 ?? ""),
    source_commit_hash: String(source_commit_hash ?? ""),
    source_receipt_hash_sha256: String(source_receipt_hash_sha256 ?? ""),
  };
  return {
    ...base,
    token_sha256: publish_post_ratification_token_sha256(base),
  };
}

export function validate_publish_post_ratification_token({ token, expected, now_iso }) {
  if (!token || typeof token !== "object") {
    return { ok: false, code: "INVALID_HITL_TOKEN", reason: "token missing or not an object" };
  }
  if (token.schema_id !== "EGL.PUBLISH_POST_RATIFICATION_TOKEN" || token.version !== "0.1.0") {
    return { ok: false, code: "INVALID_HITL_TOKEN", reason: "schema_id/version mismatch" };
  }

  const computed = publish_post_ratification_token_sha256(token);
  if (!computed || typeof token.token_sha256 !== "string" || token.token_sha256 !== computed) {
    return { ok: false, code: "INVALID_HITL_TOKEN", reason: "token_sha256 self-check failed" };
  }

  if (typeof token.approver_id !== "string" || token.approver_id.length === 0) {
    return { ok: false, code: "INVALID_HITL_TOKEN", reason: "approver_id missing" };
  }

  const expMs = Date.parse(String(token.expires_ts ?? ""));
  const nowMs = Date.parse(String(now_iso ?? ""));
  if (!Number.isNaN(expMs) && !Number.isNaN(nowMs) && nowMs > expMs) {
    return { ok: false, code: "HITL_TOKEN_EXPIRED", reason: "token expired" };
  }

  const bind = (field) => String(token[field] ?? "") === String(expected?.[field] ?? "");
  const fields = [
    "law_bundle_sha256",
    "plan_hash",
    "intent_hash",
    "lane_id",
    "attestation_nonce",
    "surface",
    "payload_sha256",
  ];
  for (const f of fields) {
    if (!bind(f)) {
      return { ok: false, code: "HITL_TOKEN_BINDING_MISMATCH", reason: `binding mismatch: ${f}` };
    }
  }

  const expCommit = String(expected?.source_commit_hash ?? "");
  const expReceipt = String(expected?.source_receipt_hash_sha256 ?? "");
  if (expCommit) {
    if (String(token.source_commit_hash ?? "") !== expCommit) {
      return { ok: false, code: "HITL_TOKEN_BINDING_MISMATCH", reason: "binding mismatch: source_commit_hash" };
    }
  } else if (expReceipt) {
    if (String(token.source_receipt_hash_sha256 ?? "") !== expReceipt) {
      return {
        ok: false,
        code: "HITL_TOKEN_BINDING_MISMATCH",
        reason: "binding mismatch: source_receipt_hash_sha256",
      };
    }
  } else {
    return { ok: false, code: "HITL_TOKEN_BINDING_MISMATCH", reason: "missing expected commit/receipt binding" };
  }

  return { ok: true, code: null, reason: null };
}
