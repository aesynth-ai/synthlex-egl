export function build_sce({
  fixture_id,
  skill_id,
  version_lock,
  requested_authority_profile,
  declared_sha256,
  observed_sha256,
  artifact_size_bytes,
  capability_diff_sha256,
  authority_diff_sha256,
  decision,
}) {
  return {
    schema_id: "EGL.SCE",
    version: "0.1.0",
    fixture_id: String(fixture_id ?? ""),
    action_type: "INSTALL_SKILL",
    skill: {
      skill_id: String(skill_id ?? ""),
      version_lock: String(version_lock ?? ""),
    },
    capability: {
      requested_authority_profile: String(requested_authority_profile ?? ""),
      capability_diff_sha256: capability_diff_sha256 ?? null,
      authority_diff_sha256: authority_diff_sha256 ?? null,
    },
    artifact: {
      declared_sha256: declared_sha256 ?? null,
      observed_sha256: observed_sha256 ?? null,
      size_bytes: typeof artifact_size_bytes === "number" ? artifact_size_bytes : null,
    },
    decision: {
      status: String(decision?.status ?? ""),
      reason_code: decision?.reason_code ?? null,
    },
  };
}
