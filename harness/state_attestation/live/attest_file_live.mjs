import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

function toPosix(p) {
  return p.replace(/\\/g, "/");
}

function safeRelPath(repoRoot, targetPathAbs) {
  const repo = path.resolve(repoRoot);
  const target = path.resolve(targetPathAbs);

  const repoLower = repo.toLowerCase();
  const targetLower = target.toLowerCase();

  if (targetLower === repoLower || targetLower.startsWith(repoLower + path.sep.toLowerCase())) {
    const rel = path.relative(repo, target);
    return toPosix(rel);
  }
  return null;
}

function hasAbsWindowsPathString(s) {
  if (typeof s !== "string") return false;
  return /^[a-zA-Z]:\\/.test(s) || /^\\\\/.test(s) || /[a-zA-Z]:\\/.test(s);
}

function hasAbsUnixPathString(s) {
  return typeof s === "string" && s.startsWith("/");
}

function redactIfAbsolute(inputPath) {
  const s = String(inputPath ?? "");
  if (hasAbsWindowsPathString(s) || hasAbsUnixPathString(s)) return "[ABSOLUTE_REDACTED]";
  return toPosix(s);
}

function sha256HexFromBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function attest_file_live({ repoRoot, op, input_path }) {
  const requested = redactIfAbsolute(input_path);
  const resolved = path.resolve(repoRoot, String(input_path ?? ""));
  const rel = safeRelPath(repoRoot, resolved);
  const normalizedPath = rel ?? "[OUTSIDE_REPO]";
  const zone = rel ? "WORKSPACE" : "UNKNOWN";

  let exists = false;
  let size_bytes = null;
  let is_symlink = false;
  let content_hash = null;
  try {
    const st = fs.lstatSync(resolved);
    is_symlink = st.isSymbolicLink();
    exists = st.isFile() || st.isDirectory() || is_symlink;

    // Fail-closed on symlinks: do not follow/measure contents.
    if (is_symlink) {
      return {
        schema_id: "MVM.FILE",
        version: "0.1.0",
        op,
        zone: "UNKNOWN",
        path: normalizedPath,
        exists,
        identity: { absolute_path: normalizedPath, requested_path: requested },
        classification: { zone: "UNKNOWN", is_symlink: true },
        integrity: { content_hash: null, size_bytes: null },
      };
    }

    if (st.isFile()) {
      const bytes = fs.readFileSync(resolved);
      size_bytes = st.size;
      content_hash = sha256HexFromBytes(bytes);
    }
  } catch {
    exists = false;
    size_bytes = null;
    is_symlink = false;
    content_hash = null;
  }

  return {
    schema_id: "MVM.FILE",
    version: "0.1.0",
    op,
    zone,
    path: normalizedPath,
    exists,
    identity: { absolute_path: normalizedPath, requested_path: requested },
    classification: { zone, is_symlink },
    integrity: { content_hash, size_bytes },
  };
}
