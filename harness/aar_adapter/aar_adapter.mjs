import { hashCanonical, stableStringify, sha256_hex } from "../intent_compiler/hash.mjs";
import { freezeCompilation } from "./plan_freeze.mjs";
import { buildLedger } from "../provenance/spe_ledger.mjs";
// (artifact hashing occurs upstream; AAR compares declared vs observed digests)
import { build_sce } from "../provenance/sce.mjs";
import { validate_ratification_token } from "../provenance/ratification_token.mjs";

function refusal({ status, code, reason, violated_ref, tier, meta }) {
  const base = {
    schema_id: "EGL.REFUSAL",
    version: "0.1.0",
    status,
    code,
    reason,
    violated_ref,
    ...(tier ? { tier } : {}),
    ...(meta ? { meta } : {}),
  };
  return {
    ...base,
    hashes: {
      refusal: hashCanonical(base).hash,
    },
  };
}

function actionFileOp(action) {
  if (!action) return null;
  if (action.kind !== "file") return null;
  if (!action.file || typeof action.file !== "object") return null;
  return action.file;
}

function isMemoryMdWrite(file) {
  const zone = String(file.zone ?? "");
  const op = String(file.op ?? "");
  const p = String(file.path ?? "");
  return zone === "memory" && op === "write" && p.startsWith("memory/") && p.endsWith(".md");
}

function isSystemCoreDelete(file) {
  const zone = String(file.zone ?? "");
  const op = String(file.op ?? "");
  return zone === "SYSTEM_CORE" && op === "delete";
}

function isUnknownZoneFileOp(file) {
  const zone = file.zone;
  return zone === undefined || zone === null || String(zone) === "UNKNOWN";
}

function skillInstallMeta(compilation) {
  const si = compilation?.meta?.skill_install;
  if (!si || typeof si !== "object") return null;
  return si;
}

function computeSceHashSha256({ fixture_id, skill_install, decision }) {
  const sce = build_sce({
    fixture_id,
    skill_id: skill_install.skill_id ?? "",
    version_lock: skill_install.version_lock ?? "",
    requested_authority_profile: skill_install.requested_authority_profile ?? "",
    declared_sha256: skill_install.declared_sha256 ?? null,
    observed_sha256: skill_install.observed_sha256 ?? null,
    artifact_size_bytes: skill_install.artifact_size_bytes ?? null,
    capability_diff_sha256: skill_install.capability_diff_digest ?? null,
    authority_diff_sha256: skill_install.authority_diff_sha256 ?? null,
    decision,
  });
  const canonical = stableStringify(sce);
  return sha256_hex(Buffer.from(canonical, "utf8"));
}

function validatePlanOrRefuse(compilation) {
  const plan = compilation.plan;
  const actions = Array.isArray(plan?.actions) ? plan.actions : [];

  // 1) zone == UNKNOWN on file ops
  for (const action of actions) {
    const file = actionFileOp(action);
    if (!file) continue;
    if (isUnknownZoneFileOp(file)) {
      return refusal({
        status: "REFUSE_HARD",
        code: "ZONE_UNKNOWN",
        reason: "File operation has UNKNOWN zone",
        violated_ref: "policy:file.zone",
      });
    }
  }

  // 2) SYSTEM_CORE delete
  for (const action of actions) {
    const file = actionFileOp(action);
    if (!file) continue;
    if (isSystemCoreDelete(file)) {
      return refusal({
        status: "REFUSE_HARD",
        code: "SYSTEM_CORE_DELETE",
        reason: "Delete in SYSTEM_CORE is prohibited",
        violated_ref: "policy:file.delete.SYSTEM_CORE",
      });
    }
  }

  // 3) memory/*.md write => DEFER_HITL (T4)
  for (const action of actions) {
    const file = actionFileOp(action);
    if (!file) continue;
    if (isMemoryMdWrite(file)) {
      return refusal({
        status: "DEFER_HITL",
        code: "MEMORY_MD_WRITE",
        reason: "Writes to memory/*.md require human review",
        violated_ref: "policy:file.write.memory_md",
        tier: "T4",
      });
    }
  }

  // 4) lane mismatch
  if (
    compilation.meta &&
    typeof compilation.meta.expected_lane_id === "string" &&
    typeof compilation.meta.lane_id === "string" &&
    compilation.meta.lane_id !== compilation.meta.expected_lane_id
  ) {
    return refusal({
      status: "REFUSE_HARD",
      code: "LANE_MISMATCH",
      reason: "lane_id does not match expected_lane_id",
      violated_ref: "policy:lane.match",
      meta: {
        lane_id: compilation.meta.lane_id,
        expected_lane_id: compilation.meta.expected_lane_id,
      },
    });
  }

  // 5) plan replay
  if (compilation.meta && compilation.meta.prohibit_replay === true) {
    const seen = Array.isArray(compilation.meta.seen_plan_hashes)
      ? compilation.meta.seen_plan_hashes
      : [];
    if (seen.includes(compilation.hashes?.plan)) {
      return refusal({
        status: "REFUSE_HARD",
        code: "PLAN_REPLAY",
        reason: "plan hash already seen; replay prohibited",
        violated_ref: "policy:replay.prohibited",
        meta: { plan_hash: compilation.hashes?.plan },
      });
    }
  }

  // 6) hash mismatch
  if (compilation.meta && typeof compilation.meta.expected_plan_hash === "string") {
    if (compilation.hashes?.plan !== compilation.meta.expected_plan_hash) {
      return refusal({
        status: "REFUSE_HARD",
        code: "HASH_MISMATCH",
        reason: "computed plan hash does not match expected_plan_hash",
        violated_ref: "policy:hash.match",
        meta: {
          expected_plan_hash: compilation.meta.expected_plan_hash,
          plan_hash: compilation.hashes?.plan,
        },
      });
    }
  }

  // 7) skill.install supply chain gate (always dry-run, never ALLOW by default)
  for (const action of actions) {
    if (String(action.tool_surface_id ?? "") !== "skill.install") continue;
    const si = skillInstallMeta(compilation);
    if (!si || si.capability_diff_present !== true || typeof si.capability_diff_digest !== "string" || !si.capability_diff_digest) {
      return refusal({
        status: "REFUSE_HARD",
        code: "MISSING_CAPABILITY_DIFF",
        reason: "capability_diff missing or empty",
        violated_ref: "policy:skill.install.capability_diff",
      });
    }

    const declared = typeof si.declared_sha256 === "string" ? si.declared_sha256 : "";
    const observed = typeof si.observed_sha256 === "string" ? si.observed_sha256 : "";
    if (!declared || !observed) {
      return refusal({
        status: "REFUSE_HARD",
        code: "MISSING_ARTIFACT_HASH",
        reason: "artifact bytes_b64 and declared_sha256 are required",
        violated_ref: "policy:skill.install.artifact_hash",
      });
    }

    if (observed.toLowerCase() !== declared.toLowerCase()) {
      return refusal({
        status: "REFUSE_HARD",
        code: "ARTIFACT_HASH_MISMATCH",
        reason: "declared_sha256 does not match observed artifact bytes",
        violated_ref: "policy:skill.install.artifact_hash.match",
        meta: { declared_sha256: declared, observed_sha256: observed },
      });
    }

    const tokens = Array.isArray(si.ratification_tokens) ? si.ratification_tokens : [];
    if (tokens.length === 0) {
      return refusal({
        status: "DEFER_HITL",
        code: "HITL_REQUIRED_SURFACE_EXPANSION",
        reason: "Skill installation expands execution surface and requires human review",
        violated_ref: "policy:surface_expansion.hitl",
        tier: "T4",
      });
    }

    const fixture_id = typeof compilation?.meta?.fixture_id === "string" ? compilation.meta.fixture_id : "";
    const lane_id =
      typeof compilation?.meta?.binding_lane_id === "string" ? compilation.meta.binding_lane_id : "";
    const attestation_nonce =
      typeof compilation?.meta?.attestation_nonce_candidate === "string"
        ? compilation.meta.attestation_nonce_candidate
        : "";
    const now_iso = typeof compilation?.meta?.now_iso === "string" ? compilation.meta.now_iso : "";

    const expectedSceHash = computeSceHashSha256({
      fixture_id,
      skill_install: si,
      decision: { status: "ALLOW", reason_code: "HITL_QUORUM_ACCEPTED" },
    });

    const expectedBinding = {
      sce_hash_sha256: expectedSceHash,
      authority_diff_sha256: typeof si.authority_diff_sha256 === "string" ? si.authority_diff_sha256 : "",
      intent_hash: compilation.hashes?.intent ?? "",
      lane_id,
      attestation_nonce,
    };

    for (const token of tokens) {
      const verdict = validate_ratification_token({ token, expected: expectedBinding, now_iso });
      if (!verdict.ok) {
        return refusal({
          status: "REFUSE_HARD",
          code: verdict.code ?? "INVALID_HITL_TOKEN",
          reason: verdict.reason ?? "Invalid HITL ratification token",
          violated_ref: "policy:skill.install.hitl_token",
        });
      }
    }

    // Quorum: require two distinct approvers.
    if (tokens.length < 2) {
      return refusal({
        status: "DEFER_HITL",
        code: "HITL_QUORUM_NOT_MET",
        reason: "Skill installation requires 2-key human quorum approval",
        violated_ref: "policy:surface_expansion.hitl.quorum",
        tier: "T4",
      });
    }

    const approvers = tokens.slice(0, 2).map((t) => String(t?.approver_id ?? ""));
    if (approvers.length === 2 && approvers[0] === approvers[1]) {
      return refusal({
        status: "DEFER_HITL",
        code: "HITL_DUPLICATE_APPROVER",
        reason: "Quorum requires distinct approver_id values",
        violated_ref: "policy:surface_expansion.hitl.quorum.distinct",
        tier: "T4",
      });
    }

    // Quorum met: admit, but record the reason code for downstream evidence.
    if (!compilation.meta) compilation.meta = {};
    compilation.meta.admission_reason_code = "HITL_QUORUM_ACCEPTED";
    return null;
  }

  return null;
}

export function adaptCompilationToAAR(compilation) {
  if (compilation.status !== "OK") {
    const ledger = buildLedger({ planFreeze: null, refusal: compilation });
    const aar = {
      schema_id: "EGL.AAR",
      version: "0.1.0",
      status: "rejected",
      refusal: compilation,
      ledger,
    };
    return {
      ...aar,
      hashes: {
        aar: hashCanonical(aar).hash,
      },
    };
  }

  const policyRefusal = validatePlanOrRefuse(compilation);
  if (policyRefusal) {
    const ledger = buildLedger({ planFreeze: null, refusal: policyRefusal });
    const aar = {
      schema_id: "EGL.AAR",
      version: "0.1.0",
      status: "rejected",
      refusal: policyRefusal,
      ledger,
    };
    return {
      ...aar,
      hashes: {
        aar: hashCanonical(aar).hash,
      },
    };
  }

  const freeze = freezeCompilation(compilation);
  const ledger = buildLedger({ planFreeze: freeze, refusal: null });
  const aar = {
    schema_id: "EGL.AAR",
    version: "0.1.0",
    status: "ok",
    plan_freeze: freeze,
    ledger,
    ...(typeof compilation?.meta?.admission_reason_code === "string"
      ? { admission: { code: compilation.meta.admission_reason_code } }
      : {}),
  };
  return {
    ...aar,
    hashes: {
      aar: hashCanonical(aar).hash,
    },
  };
}
