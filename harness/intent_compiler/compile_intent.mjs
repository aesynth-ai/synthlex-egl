import fs from "node:fs";
import path from "node:path";
import { hashCanonical } from "./hash.mjs";
import { loadToolSurfaceMap } from "./tool_surface_map.mjs";

const REFUSAL_SCHEMA_ID = "EGL.REFUSAL";

function sortByKey(items, key) {
  return [...items].sort((a, b) => String(a[key]).localeCompare(String(b[key])));
}

function intentMeta(intent) {
  const meta = {};
  if (typeof intent.lane_id === "string") meta.lane_id = intent.lane_id;
  if (typeof intent.expected_lane_id === "string") meta.expected_lane_id = intent.expected_lane_id;
  if (typeof intent.expected_plan_hash === "string") meta.expected_plan_hash = intent.expected_plan_hash;
  if (Array.isArray(intent.seen_plan_hashes)) {
    meta.seen_plan_hashes = [...intent.seen_plan_hashes].slice().sort();
  }
  if (typeof intent.prohibit_replay === "boolean") meta.prohibit_replay = intent.prohibit_replay;
  if (intent && typeof intent.skill_install === "object" && intent.skill_install !== null) {
    const si = intent.skill_install;
    meta.skill_install = {
      skill_id: typeof si.skill_id === "string" ? si.skill_id : "",
      requested_authority_profile:
        typeof si.requested_authority_profile === "string" ? si.requested_authority_profile : "",
      version_lock: typeof si.version_lock === "string" ? si.version_lock : "",
      declared_sha256: typeof si.declared_sha256 === "string" ? si.declared_sha256 : null,
      observed_sha256: typeof si.observed_sha256 === "string" ? si.observed_sha256 : null,
      artifact_size_bytes:
        typeof si.artifact_size_bytes === "number" ? si.artifact_size_bytes : null,
      capability_diff_present: si.capability_diff_present === true,
      capability_diff_digest:
        typeof si.capability_diff_digest === "string" ? si.capability_diff_digest : null,
      authority_diff_sha256:
        typeof si.authority_diff_sha256 === "string" ? si.authority_diff_sha256 : null,
    };
  }
  return meta;
}

function refuseUnmapped({ surfaceId, intentHash }) {
  return {
    schema_id: REFUSAL_SCHEMA_ID,
    version: "0.1.0",
    status: "REFUSE_HARD",
    code: "UNMAPPED_TOOL_SURFACE",
    tool_surface_id: surfaceId,
    violated_ref: "harness/intent_compiler/tool_surface_map.v1.1.1.yaml#surfaces",
    reason: "No mapping → no execution",
    hashes: {
      intent: intentHash,
      refusal: hashCanonical({
        code: "UNMAPPED_TOOL_SURFACE",
        tool_surface_id: surfaceId,
        intent: intentHash,
      }).hash,
    },
  };
}

export function compileIntent({ intent, toolSurfaceMap }) {
  const meta = intentMeta(intent);
  const { hash: intentHash } = hashCanonical(intent);

  const actions = Array.isArray(intent.actions) ? intent.actions : [];
  const ordered = sortByKey(actions, "action_id");

  if (!toolSurfaceMap || !Array.isArray(toolSurfaceMap.surfaces) || toolSurfaceMap.surfaces.length === 0) {
    const surfaceId = ordered[0]?.tool_surface_id ?? "UNKNOWN";
    return refuseUnmapped({ surfaceId, intentHash });
  }

  const allowed = new Map(toolSurfaceMap.surfaces.map((s) => [s.surface_id, s]));

  for (const action of ordered) {
    const surfaceId = action.tool_surface_id;
    if (!allowed.has(surfaceId)) {
      return refuseUnmapped({ surfaceId, intentHash });
    }
  }

  const plan = {
    schema_id: "EGL.PLAN",
    version: "0.1.0",
    plan_id: intent.intent_id ?? "PLAN",
    actions: ordered.map((a) => ({
      kind: a.kind,
      tool_surface_id: a.tool_surface_id,
      ...(a.process ? { process: a.process } : {}),
      ...(a.file ? { file: a.file } : {}),
      ...(a.net ? { net: a.net } : {}),
    })),
  };

  const { hash: planHash } = hashCanonical(plan);
  return {
    schema_id: "EGL.INTENT_COMPILATION",
    version: "0.1.0",
    status: "OK",
    meta,
    plan,
    hashes: {
      intent: intentHash,
      plan: planHash,
    },
  };
}

export function compileIntentFromFile({ repoRoot, intentPath }) {
  const map = loadToolSurfaceMap(repoRoot);
  const full = path.resolve(repoRoot, intentPath);
  const raw = fs.readFileSync(full, "utf8");
  const intent = JSON.parse(raw);
  return compileIntent({ intent, toolSurfaceMap: map });
}
