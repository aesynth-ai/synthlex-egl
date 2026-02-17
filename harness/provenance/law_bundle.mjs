import fs from "node:fs";
import path from "node:path";
import { sha256_hex, stableStringify } from "../intent_compiler/hash.mjs";

function stripUtf8Bom(s) {
  return typeof s === "string" && s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}

function canonicalizeTextForHashing(text) {
  const t = stripUtf8Bom(String(text ?? ""));
  // Normalize line endings then trim trailing whitespace per line (deterministic).
  const normalized = t.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = normalized.split("\n").map((l) => l.replace(/[ \t]+$/g, ""));
  return lines.join("\n");
}

function sha256HexUtf8(text) {
  return sha256_hex(Buffer.from(String(text), "utf8"));
}

function hashFileCanonicalUtf8({ repoRoot, relPath }) {
  const abs = path.resolve(repoRoot, relPath);
  const raw = fs.readFileSync(abs, "utf8");
  const canonical = canonicalizeTextForHashing(raw);
  return `sha256:${sha256HexUtf8(canonical)}`;
}

export function computeLawBundle({ repoRoot }) {
  const policyFiles = ["policies/default.policy.yaml", "policies/tiers.policy.yaml"];
  const authorityProfileFiles = [
    "authority/sandbox.profile.yaml",
    "authority/host.profile.yaml",
    "authority/skill_install.profile.yaml",
  ];
  const toolSurfaceMapFiles = ["harness/intent_compiler/tool_surface_map.v1.1.1.yaml"];

  const policies = {};
  for (const relPath of policyFiles) policies[relPath] = hashFileCanonicalUtf8({ repoRoot, relPath });

  const authority_profiles = {};
  for (const relPath of authorityProfileFiles) {
    authority_profiles[relPath] = hashFileCanonicalUtf8({ repoRoot, relPath });
  }

  const tool_surface_map = {};
  for (const relPath of toolSurfaceMapFiles) {
    tool_surface_map[relPath] = hashFileCanonicalUtf8({ repoRoot, relPath });
  }

  const bundle = {
    schema_id: "EGL.LAW_BUNDLE",
    version: "0.1.0",
    components: {
      policies,
      authority_profiles,
      tool_surface_map,
    },
  };

  const law_bundle_sha256 = `sha256:${sha256HexUtf8(stableStringify(bundle))}`;
  const policy_bundle_sha256 = `sha256:${sha256HexUtf8(stableStringify(policies))}`;
  const authority_profiles_sha256 = `sha256:${sha256HexUtf8(stableStringify(authority_profiles))}`;
  // Single-file bundle (still versionable via the key).
  const tool_surface_map_sha256 =
    tool_surface_map[toolSurfaceMapFiles[0]] ?? `sha256:${sha256HexUtf8(stableStringify(tool_surface_map))}`;

  return {
    bundle,
    law_bundle_sha256,
    policy_bundle_sha256,
    authority_profiles_sha256,
    tool_surface_map_sha256,
  };
}

