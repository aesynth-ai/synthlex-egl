import fs from "node:fs";
import path from "node:path";
import { decode_b64_to_bytes, sha256_hex } from "../../provenance/artifact_hash.mjs";
import { capability_diff_sha256, authority_diff_sha256 } from "../../provenance/capability_diff.mjs";

function toPosix(p) {
  return p.replace(/\\/g, "/");
}

function safeRelPath(repoRoot, inputPath) {
  const repo = path.resolve(repoRoot);
  const target = path.resolve(repoRoot, inputPath);
  const repoLower = repo.toLowerCase();
  const targetLower = target.toLowerCase();
  if (targetLower === repoLower || targetLower.startsWith(repoLower + path.sep.toLowerCase())) {
    return toPosix(path.relative(repo, target));
  }
  return null;
}

function hasAbsWindowsPathString(s) {
  if (typeof s !== "string") return false;
  // Drive letter (e.g., C:\) or UNC path (\\server\share)
  return /^[a-zA-Z]:\\/.test(s) || /^\\\\/.test(s) || /[a-zA-Z]:\\/.test(s);
}

function assertNoAbsWindowsPaths(value, where = "value") {
  if (typeof value === "string") {
    if (hasAbsWindowsPathString(value)) {
      throw new Error(`Absolute Windows path is not allowed in artifacts (${where})`);
    }
    return;
  }
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) assertNoAbsWindowsPaths(value[i], `${where}[${i}]`);
    return;
  }
  for (const k of Object.keys(value)) {
    assertNoAbsWindowsPaths(value[k], `${where}.${k}`);
  }
}

function sha256HexUtf8(s) {
  return sha256_hex(Buffer.from(String(s ?? ""), "utf8"));
}

function normalizeText(s) {
  const raw = typeof s === "string" ? s : "";
  const lf = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const trimmed = lf
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, ""))
    .join("\n");
  return trimmed;
}

function normalizeEnvelopeArgs({ repoRoot, tool_name, args }) {
  const out = args && typeof args === "object" && !Array.isArray(args) ? { ...args } : {};

  // Normalize file paths to repo-relative or OUTSIDE_REPO, never absolute.
  if (tool_name === "fs.read" || tool_name === "fs.write" || tool_name === "fs.delete") {
    const rawPath = String(out.path ?? "");
    const rel = safeRelPath(repoRoot, rawPath);
    out.path = rel ?? "OUTSIDE_REPO";
  }

  // Enforce "no absolute Windows paths" for all remaining string fields.
  assertNoAbsWindowsPaths(out, "envelope.args");
  return out;
}

export function buildEnvelopeFromToolCall({ repoRoot, fixture_id, tool_call }) {
  const tool_name = String(tool_call?.tool ?? tool_call?.name ?? "");
  const tool_call_id = String(tool_call?.id ?? tool_call?.call_id ?? fixture_id ?? "CALL");
  const lane_id = typeof tool_call?.lane_id === "string" ? tool_call.lane_id : "proxy";
  const binding = tool_call?.binding && typeof tool_call.binding === "object" ? tool_call.binding : null;

  const args = {};
  for (const [k, v] of Object.entries(tool_call ?? {})) {
    if (
      k === "tool" ||
      k === "name" ||
      k === "id" ||
      k === "call_id" ||
      k === "lane_id" ||
      k === "binding"
    )
      continue;
    args[k] = v;
  }

  let normalizedArgs = normalizeEnvelopeArgs({ repoRoot, tool_name, args });
  if (tool_name === "skill.install") {
    normalizedArgs = {
      skill_install_request: {
        skill_id: typeof args.skill_id === "string" ? args.skill_id : "",
        artifact: args.artifact ?? null,
        capability_diff: args.capability_diff ?? null,
        requested_authority_profile:
          typeof args.requested_authority_profile === "string" ? args.requested_authority_profile : "",
        version_lock: typeof args.version_lock === "string" ? args.version_lock : "",
        ratification_token: args.ratification_token ?? null,
        ratification_tokens: args.ratification_tokens ?? null,
      },
      ...(typeof args.force_nonce === "string" ? { force_nonce: args.force_nonce } : {}),
      ...(typeof args.expiry_ts === "string" ? { expiry_ts: args.expiry_ts } : {}),
      ...(typeof args.bind_lane_id === "string" ? { bind_lane_id: args.bind_lane_id } : {}),
    };
    assertNoAbsWindowsPaths(normalizedArgs, "envelope.args.skill_install_request");
  }

  if (
    tool_name === "publish.draft.create" ||
    tool_name === "publish.draft.bundle" ||
    tool_name === "publish.draft.commit"
  ) {
    const draft_kind = typeof args.draft_kind === "string" ? args.draft_kind : "x_post";
    const title = typeof args.title === "string" ? args.title : "";
    const content = normalizeText(args.content);
    const tags = Array.isArray(args.tags) ? args.tags.map((t) => String(t)) : [];
    const content_sha256 = `sha256:${sha256HexUtf8(content)}`;
    const slug = sha256HexUtf8(content).slice(0, 12);

    const defaultPath = `sandbox/_publish_drafts/${draft_kind}_${slug}.md`;
    const rawTarget = typeof args.target_path === "string" ? args.target_path : "";
    const relTarget = rawTarget ? safeRelPath(repoRoot, rawTarget) : null;
    const target_path =
      relTarget && toPosix(relTarget).startsWith("sandbox/_publish_drafts/")
        ? toPosix(relTarget)
        : defaultPath;

    normalizedArgs = {
      draft_kind,
      ...(title ? { title } : {}),
      content,
      ...(tags.length > 0 ? { tags } : {}),
      target_path,
      content_sha256,
      ...(typeof args.git_branch === "string" ? { git_branch: args.git_branch } : {}),
      ...(typeof args.base_branch === "string" ? { base_branch: args.base_branch } : {}),
      ...(typeof args.commit_message === "string" ? { commit_message: args.commit_message } : {}),
      ...(Object.prototype.hasOwnProperty.call(args, "ratification_token") ? { ratification_token: args.ratification_token } : {}),
      ...(Object.prototype.hasOwnProperty.call(args, "execution_permit") ? { execution_permit: args.execution_permit } : {}),
      ...(typeof args.force_nonce === "string" ? { force_nonce: args.force_nonce } : {}),
      ...(typeof args.expiry_ts === "string" ? { expiry_ts: args.expiry_ts } : {}),
      ...(typeof args.bind_lane_id === "string" ? { bind_lane_id: args.bind_lane_id } : {}),
    };
    assertNoAbsWindowsPaths(normalizedArgs, "envelope.args.publish_draft");
  }

  if (tool_name === "publish.post.x" || tool_name === "publish.post.x_thread") {
    const post_kind = tool_name === "publish.post.x_thread" ? "x_thread" : "x_post";
    const payload_text = normalizeText(args.payload_text);
    const payload_norm = payload_text.endsWith("\n") ? payload_text : `${payload_text}\n`;
    const payload_sha256 = `sha256:${sha256HexUtf8(payload_norm)}`;

    const source_commit_hash =
      typeof args.source_commit_hash === "string" ? String(args.source_commit_hash) : "";
    const source_receipt_hash_sha256 =
      typeof args.source_receipt_hash_sha256 === "string" ? String(args.source_receipt_hash_sha256) : "";

    normalizedArgs = {
      post_kind,
      payload_text: payload_norm,
      payload_sha256,
      ...(source_commit_hash ? { source_commit_hash } : {}),
      ...(source_receipt_hash_sha256 ? { source_receipt_hash_sha256 } : {}),
      ...(Object.prototype.hasOwnProperty.call(args, "execution_permit") ? { execution_permit: args.execution_permit } : {}),
      ...(Object.prototype.hasOwnProperty.call(args, "ratification_token") ? { ratification_token: args.ratification_token } : {}),
      ...(typeof args.force_nonce === "string" ? { force_nonce: args.force_nonce } : {}),
      ...(typeof args.expiry_ts === "string" ? { expiry_ts: args.expiry_ts } : {}),
      ...(typeof args.bind_lane_id === "string" ? { bind_lane_id: args.bind_lane_id } : {}),
    };
    assertNoAbsWindowsPaths(normalizedArgs, "envelope.args.publish_post");
  }

  if (tool_name === "code.patch.apply") {
    const rawPath = typeof args.path === "string" ? args.path : "";
    const relTarget = rawPath ? safeRelPath(repoRoot, rawPath) : null;
    const pathRel = relTarget && toPosix(relTarget).length > 0 ? toPosix(relTarget) : "OUTSIDE_REPO";
    const after_text = normalizeText(args.after_text);
    const after_norm = after_text.endsWith("\n") ? after_text : `${after_text}\n`;
    const after_text_sha256 = `sha256:${sha256HexUtf8(after_norm)}`;

    normalizedArgs = {
      repo_root: ".",
      path: pathRel,
      after_text: after_norm,
      after_text_sha256,
      ...(Object.prototype.hasOwnProperty.call(args, "execution_permit") ? { execution_permit: args.execution_permit } : {}),
      ...(typeof args.force_nonce === "string" ? { force_nonce: args.force_nonce } : {}),
      ...(typeof args.expiry_ts === "string" ? { expiry_ts: args.expiry_ts } : {}),
      ...(typeof args.bind_lane_id === "string" ? { bind_lane_id: args.bind_lane_id } : {}),
    };
    assertNoAbsWindowsPaths(normalizedArgs, "envelope.args.code_patch_apply");
  }

  if (tool_name === "code.test.run") {
    const rawCwd = typeof args.cwd === "string" ? args.cwd : ".";
    const relCwd = rawCwd ? safeRelPath(repoRoot, rawCwd) : null;
    const cwdRel = relCwd && toPosix(relCwd).length > 0 ? toPosix(relCwd) : ".";

    const cmd = typeof args.cmd === "string" ? normalizeText(args.cmd) : "";
    const env_profile = typeof args.env_profile === "string" ? normalizeText(args.env_profile) : "";

    normalizedArgs = {
      cwd: cwdRel,
      cmd,
      env_profile,
      ...(Object.prototype.hasOwnProperty.call(args, "execution_permit") ? { execution_permit: args.execution_permit } : {}),
      ...(typeof args.force_nonce === "string" ? { force_nonce: args.force_nonce } : {}),
      ...(typeof args.expiry_ts === "string" ? { expiry_ts: args.expiry_ts } : {}),
      ...(typeof args.bind_lane_id === "string" ? { bind_lane_id: args.bind_lane_id } : {}),
    };
    assertNoAbsWindowsPaths(normalizedArgs, "envelope.args.code_test_run");
  }

  if (tool_name === "code.deps.fetch") {
    const rawCwd = typeof args.cwd === "string" ? args.cwd : ".";
    const relCwd = rawCwd ? safeRelPath(repoRoot, rawCwd) : null;
    const cwdRel = relCwd && toPosix(relCwd).length > 0 ? toPosix(relCwd) : ".";

    const cmd = typeof args.cmd === "string" ? normalizeText(args.cmd) : "";
    const env_profile = typeof args.env_profile === "string" ? normalizeText(args.env_profile) : "";

    const rawLockfile = typeof args.lockfile_path === "string" ? args.lockfile_path : "";
    const relLock = rawLockfile ? safeRelPath(repoRoot, rawLockfile) : null;
    const lockfile_path = relLock && toPosix(relLock).length > 0 ? toPosix(relLock) : "OUTSIDE_REPO";

    normalizedArgs = {
      cwd: cwdRel,
      cmd,
      env_profile,
      lockfile_path,
      ...(Object.prototype.hasOwnProperty.call(args, "execution_permit") ? { execution_permit: args.execution_permit } : {}),
      ...(typeof args.force_nonce === "string" ? { force_nonce: args.force_nonce } : {}),
      ...(typeof args.expiry_ts === "string" ? { expiry_ts: args.expiry_ts } : {}),
      ...(typeof args.bind_lane_id === "string" ? { bind_lane_id: args.bind_lane_id } : {}),
    };
    assertNoAbsWindowsPaths(normalizedArgs, "envelope.args.code_deps_fetch");
  }

  const envelope = {
    session_id: "proxy",
    lane_id,
    tool_call_id,
    tool_name,
    args: normalizedArgs,
    ...(binding ? { binding } : {}),
    agent_id: "proxy",
    channel: "cli",
    origin: "proxy",
  };

  assertNoAbsWindowsPaths(envelope, "envelope");
  return envelope;
}

export function buildEnvelopeFromFixtureFile({ repoRoot, fixturePath, fixture_id }) {
  const raw = fs.readFileSync(path.resolve(repoRoot, fixturePath), "utf8");
  const tool_call = JSON.parse(raw);
  return buildEnvelopeFromToolCall({ repoRoot, fixture_id, tool_call });
}

function isOutsideRepoPath(p) {
  if (typeof p !== "string") return true;
  if (p === "OUTSIDE_REPO") return true;
  if (hasAbsWindowsPathString(p)) return true;
  return false;
}

function isNonEmptyCapabilityDiff(diffObj) {
  if (!diffObj || typeof diffObj !== "object") return false;
  const keys = Object.keys(diffObj);
  if (keys.length === 0) return false;
  for (const k of keys) {
    const v = diffObj[k];
    if (Array.isArray(v) && v.length > 0) return true;
    if (typeof v === "string" && v.trim().length > 0) return true;
    if (v && typeof v === "object" && Object.keys(v).length > 0) return true;
  }
  return false;
}

export function normalizeEnvelopeToIntent({ repoRoot, envelope }) {
  const tool = String(envelope?.tool_name ?? "");
  const id = String(envelope?.tool_call_id ?? "CALL");
  const args = envelope?.args ?? {};

  if (tool === "fs.read") {
    const rel = isOutsideRepoPath(args.path) ? null : safeRelPath(repoRoot, String(args.path));
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "file",
          tool_surface_id: "file.read",
          file: {
            op: "read",
            zone: rel ? "repo" : "UNKNOWN",
            path: rel ?? "OUTSIDE_REPO",
          },
        },
      ],
    };
  }

  if (tool === "fs.write") {
    const rel = isOutsideRepoPath(args.path) ? null : safeRelPath(repoRoot, String(args.path));
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "file",
          tool_surface_id: "file.write",
          file: {
            op: "write",
            zone: rel ? "repo" : "UNKNOWN",
            path: rel ?? "OUTSIDE_REPO",
          },
        },
      ],
    };
  }

  if (tool === "fs.delete") {
    const rel = isOutsideRepoPath(args.path) ? null : safeRelPath(repoRoot, String(args.path));
    const zone = String(args.zone ?? (rel ? "repo" : "UNKNOWN"));
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "file",
          tool_surface_id: "file.delete",
          file: {
            op: "delete",
            zone,
            path: rel ?? "OUTSIDE_REPO",
          },
        },
      ],
    };
  }

  if (tool === "exec") {
    const target = String(args.target ?? "sandbox");
    const surface = target === "host" ? "exec.host" : "exec.sandbox";
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "process",
          tool_surface_id: surface,
          process: {
            command: String(args.command ?? ""),
            args: Array.isArray(args.args) ? args.args.map(String) : [],
          },
        },
      ],
    };
  }

  if (tool === "browser.navigate") {
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "net",
          tool_surface_id: "browser.navigate",
          net: {
            url: String(args.url ?? ""),
          },
        },
      ],
    };
  }

  if (tool === "git.pipeline_commit_from_diff") {
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "process",
          tool_surface_id: "git.pipeline_commit_from_diff",
          process: {
            command: "git.pipeline_commit_from_diff",
            args: [],
          },
        },
      ],
    };
  }

  if (tool === "publish.draft.create") {
    const rel = isOutsideRepoPath(args.target_path) ? null : safeRelPath(repoRoot, String(args.target_path));
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "file",
          tool_surface_id: "publish.draft.create",
          file: {
            op: "write",
            zone: rel ? "repo" : "UNKNOWN",
            path: rel ?? "OUTSIDE_REPO",
          },
        },
      ],
    };
  }

  if (tool === "publish.draft.bundle") {
    const rel = isOutsideRepoPath(args.target_path) ? null : safeRelPath(repoRoot, String(args.target_path));
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "file",
          tool_surface_id: "publish.draft.bundle",
          file: {
            op: "write",
            zone: rel ? "repo" : "UNKNOWN",
            path: rel ?? "OUTSIDE_REPO",
          },
        },
      ],
    };
  }

  if (tool === "publish.draft.commit") {
    const rel = isOutsideRepoPath(args.target_path) ? null : safeRelPath(repoRoot, String(args.target_path));
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "file",
          tool_surface_id: "publish.draft.commit",
          file: {
            op: "write",
            zone: rel ? "repo" : "UNKNOWN",
            path: rel ?? "OUTSIDE_REPO",
          },
        },
      ],
    };
  }

  if (tool === "publish.post.x" || tool === "publish.post.x_thread") {
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "process",
          tool_surface_id: tool,
          process: {
            command: tool,
            args: [],
          },
        },
      ],
    };
  }

  if (tool === "code.patch.apply") {
    const rel = isOutsideRepoPath(args.path) ? null : safeRelPath(repoRoot, String(args.path));
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "file",
          tool_surface_id: "code.patch.apply",
          file: {
            op: "write",
            zone: rel ? "repo" : "UNKNOWN",
            path: rel ?? "OUTSIDE_REPO",
          },
        },
      ],
    };
  }

  if (tool === "code.test.run") {
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "process",
          tool_surface_id: "code.test.run",
          process: {
            command: "code.test.run",
            args: [],
          },
        },
      ],
    };
  }

  if (tool === "code.deps.fetch") {
    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      actions: [
        {
          action_id: "A1",
          kind: "process",
          tool_surface_id: "code.deps.fetch",
          process: {
            command: "code.deps.fetch",
            args: [],
          },
        },
      ],
    };
  }

  if (tool === "skill.install") {
    const req = args.skill_install_request ?? {};
    const artifact = req?.artifact ?? null;
    const capability_diff = req?.capability_diff ?? null;
    const declared_sha256 =
      typeof artifact?.declared_sha256 === "string" ? artifact.declared_sha256 : null;
    const bytes_b64 = typeof artifact?.bytes_b64 === "string" ? artifact.bytes_b64 : null;

    let observed_sha256 = null;
    let artifact_size_bytes = null;
    if (bytes_b64) {
      try {
        const bytes = decode_b64_to_bytes(bytes_b64);
        observed_sha256 = sha256_hex(bytes);
        artifact_size_bytes = bytes.byteLength;
      } catch {
        observed_sha256 = null;
        artifact_size_bytes = null;
      }
    }

    const capability_diff_present = isNonEmptyCapabilityDiff(capability_diff);
    const capability_diff_digest = capability_diff_present
      ? capability_diff_sha256(capability_diff).sha256
      : null;
    const authority_diff_digest = capability_diff_present
      ? authority_diff_sha256(capability_diff).sha256
      : null;

    return {
      schema_id: "EGL.INTENT",
      version: "0.1.0",
      intent_id: id,
      skill_install: {
        skill_id: typeof req?.skill_id === "string" ? req.skill_id : "",
        requested_authority_profile:
          typeof req?.requested_authority_profile === "string" ? req.requested_authority_profile : "",
        version_lock: typeof req?.version_lock === "string" ? req.version_lock : "",
        declared_sha256,
        observed_sha256,
        artifact_size_bytes,
        capability_diff_present,
        capability_diff_digest,
        authority_diff_sha256: authority_diff_digest,
      },
      actions: [
        {
          action_id: "A1",
          kind: "process",
          tool_surface_id: "skill.install",
          process: {
            command: "skill.install",
            args: [],
          },
        },
      ],
    };
  }

  // Unrecognized tool => goes through mapping and refuses as unmapped.
  return {
    schema_id: "EGL.INTENT",
    version: "0.1.0",
    intent_id: id,
    actions: [
      {
        action_id: "A1",
        kind: "process",
        tool_surface_id: `unknown.${tool}`,
        process: { command: "", args: [] },
      },
    ],
  };
}
