import { createHash } from "node:crypto";

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function normalizeText(t) {
  const s = String(t ?? "");
  return s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

function splitLinesPreserveLastEmpty(text) {
  // Keep stable line accounting: if text ends with \n, we include the trailing empty line.
  return normalizeText(text).split("\n");
}

export function unifiedDiff({ relPath, before_text, after_text }) {
  const before = normalizeText(before_text);
  const after = normalizeText(after_text);

  const beforeLines = splitLinesPreserveLastEmpty(before);
  const afterLines = splitLinesPreserveLastEmpty(after);

  const beforeCount = beforeLines.length;
  const afterCount = afterLines.length;

  const header = [
    `--- a/${relPath}`,
    `+++ b/${relPath}`,
  ];

  // Minimal deterministic diff: replace the whole file as a single hunk.
  // (Good enough for governance: digest + stats, no timestamps, stable headers.)
  const hunkHeader = `@@ -1,${beforeCount} +1,${afterCount} @@`;

  const body = [];
  for (const l of beforeLines) body.push(`-${l}`);
  for (const l of afterLines) body.push(`+${l}`);

  const diff_unified = [...header, hunkHeader, ...body, ""].join("\n");
  const diff_sha256 = `sha256:${sha256Hex(Buffer.from(diff_unified, "utf8"))}`;

  const bytes_before = Buffer.from(before, "utf8").byteLength;
  const bytes_after = Buffer.from(after, "utf8").byteLength;

  const diff_stats = {
    added_lines: afterCount,
    removed_lines: beforeCount,
    changed_lines: null,
    bytes_after,
    bytes_before,
    bytes_delta: bytes_after - bytes_before,
  };

  return { diff_unified, diff_sha256, diff_stats };
}

