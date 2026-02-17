import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { pathWithinRoots } from "../provenance/execution_permit.mjs";

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function toPosix(p) {
  return String(p ?? "").replace(/\\/g, "/");
}

function resolveRepoRelative({ repoRoot, relPath }) {
  const clean = toPosix(relPath);
  const abs = path.resolve(repoRoot, clean);
  const repo = path.resolve(repoRoot);
  const repoLower = repo.toLowerCase();
  const absLower = abs.toLowerCase();
  if (absLower === repoLower || absLower.startsWith(repoLower + path.sep.toLowerCase())) {
    return abs;
  }
  throw new Error("path escapes repoRoot");
}

function readFileHashOrNull({ repoRoot, relPath }) {
  try {
    const abs = resolveRepoRelative({ repoRoot, relPath });
    if (!fs.existsSync(abs)) return null;
    const bytes = fs.readFileSync(abs);
    return `sha256:${sha256Hex(bytes)}`;
  } catch {
    return null;
  }
}

export function execute_real_sandbox({ repoRoot, plan, permit, envelope }) {
  const action = Array.isArray(plan?.actions) ? plan.actions[0] : null;
  if (!action || action.kind !== "file") {
    return {
      ok: false,
      code: "UNSUPPORTED_ACTION",
      result: { kind: "exec_error", note: "Only file actions are supported" },
    };
  }

  const tool_surface_id = String(action.tool_surface_id ?? "");
  const file = action.file && typeof action.file === "object" ? action.file : {};
  const op = String(file.op ?? "");
  const relPath = String(file.path ?? "");

  const fsScope =
    permit?.scope?.filesystem && typeof permit.scope.filesystem === "object"
      ? permit.scope.filesystem
      : { read_roots: [], write_roots: [], deny_paths: [] };
  const read_roots = Array.isArray(fsScope.read_roots) ? fsScope.read_roots : [];
  const write_roots = Array.isArray(fsScope.write_roots) ? fsScope.write_roots : [];
  const deny_paths = Array.isArray(fsScope.deny_paths) ? fsScope.deny_paths : [];

  if (pathWithinRoots({ relPath, roots: deny_paths })) {
    return { ok: false, code: "PERMIT_SCOPE_VIOLATION", result: { kind: "exec_error", note: "deny_path" } };
  }

  const before_hash_sha256 = readFileHashOrNull({ repoRoot, relPath });

  if (tool_surface_id === "file.read" && op === "read") {
    if (!pathWithinRoots({ relPath, roots: read_roots })) {
      return {
        ok: false,
        code: "PERMIT_SCOPE_VIOLATION",
        result: { kind: "exec_error", note: "path not within read_roots" },
      };
    }
    const abs = resolveRepoRelative({ repoRoot, relPath });
    const bytes = fs.readFileSync(abs);
    const content_sha256 = `sha256:${sha256Hex(bytes)}`;
    return {
      ok: true,
      tool_surface_id,
      result: {
        kind: "file_result",
        op: "read",
        path: toPosix(relPath),
        bytes: bytes.byteLength,
        content_sha256,
        before_hash_sha256,
        after_hash_sha256: before_hash_sha256,
      },
      file_receipt: {
        schema_id: "EGL.FILE_RECEIPT",
        version: "0.1.0",
        op: "read",
        path: toPosix(relPath),
        bytes: bytes.byteLength,
        before_hash_sha256,
        after_hash_sha256: before_hash_sha256,
        diff_sha256: null,
        diff_stats: null,
        diff_preview_hash_sha256: null,
        permit_sha256: typeof permit?.permit_sha256 === "string" ? permit.permit_sha256 : null,
        law_bundle_sha256: envelope?.binding?.law_bundle_sha256 ?? null,
        plan_hash: null,
      },
    };
  }

  if (
    (tool_surface_id === "file.write" ||
      tool_surface_id === "code.patch.apply" ||
      tool_surface_id === "publish.draft.create" ||
      tool_surface_id === "publish.draft.bundle" ||
      tool_surface_id === "publish.draft.commit") &&
    op === "write"
  ) {
    const after_text = typeof envelope?.args?.after_text === "string" ? envelope.args.after_text : null;
    const diff_sha256 = typeof envelope?.args?.diff_sha256 === "string" ? envelope.args.diff_sha256 : null;
    const diff_stats = envelope?.args?.diff_stats ?? null;
    const diff_preview_hash_sha256 =
      typeof envelope?.args?.diff_preview_hash_sha256 === "string"
        ? envelope.args.diff_preview_hash_sha256
        : null;
    const draft_kind = typeof envelope?.args?.draft_kind === "string" ? envelope.args.draft_kind : null;
    const content_sha256 = typeof envelope?.args?.content_sha256 === "string" ? envelope.args.content_sha256 : null;

    if (typeof after_text !== "string") {
      return {
        ok: false,
        code: "UNSUPPORTED_ACTION",
        result: { kind: "exec_error", note: "write requires after_text" },
      };
    }
    if (!pathWithinRoots({ relPath, roots: write_roots })) {
      return {
        ok: false,
        code: "PERMIT_SCOPE_VIOLATION",
        result: { kind: "exec_error", note: "path not within write_roots" },
      };
    }
    const abs = resolveRepoRelative({ repoRoot, relPath });
    fs.mkdirSync(path.dirname(abs), { recursive: true });

    const normalized = String(after_text).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const bytes = Buffer.from(normalized, "utf8");
    fs.writeFileSync(abs, bytes);
    const after_hash_sha256 = `sha256:${sha256Hex(bytes)}`;

    return {
      ok: true,
      tool_surface_id,
      result: {
        kind: "file_result",
        op: "write",
        path: toPosix(relPath),
        bytes: bytes.byteLength,
        before_hash_sha256,
        after_hash_sha256,
        content_sha256: after_hash_sha256,
        note: "APPLIED_PERMIT_SCOPED_PATCH",
      },
      file_receipt: {
        schema_id: "EGL.FILE_RECEIPT",
        version: "0.1.0",
        op: "write",
        path: toPosix(relPath),
        bytes: bytes.byteLength,
        before_hash_sha256,
        after_hash_sha256,
        diff_sha256,
        diff_stats,
        diff_preview_hash_sha256,
        ...(draft_kind ? { draft_kind } : {}),
        ...(content_sha256 ? { content_sha256 } : {}),
        permit_sha256: typeof permit?.permit_sha256 === "string" ? permit.permit_sha256 : null,
        law_bundle_sha256: envelope?.binding?.law_bundle_sha256 ?? null,
        plan_hash: null,
      },
    };
  }

  return {
    ok: false,
    code: "UNSUPPORTED_ACTION",
    result: { kind: "exec_error", note: `unsupported tool/op: ${tool_surface_id}/${op}` },
  };
}

export function file_state_sha256({ repoRoot, relPath }) {
  return readFileHashOrNull({ repoRoot, relPath });
}
