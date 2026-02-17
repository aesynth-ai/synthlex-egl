import { createHash } from "node:crypto";

function sha256HexFromUtf8(text) {
  return createHash("sha256").update(Buffer.from(String(text), "utf8")).digest("hex");
}

function firstAction(plan) {
  const actions = Array.isArray(plan?.actions) ? plan.actions : [];
  return actions[0] ?? null;
}

export function execute_stub({ plan, io, envelope }) {
  const action = firstAction(plan);
  const tool_surface_id = String(action?.tool_surface_id ?? "");

  if (tool_surface_id === "file.read") {
    const path = String(action?.file?.path ?? "");
    const result = {
      kind: "stub_result",
      op: "read",
      path,
      content_sha256: sha256HexFromUtf8(`STUB_READ:${path}`),
      bytes: 17,
    };
    return { ok: true, tool_surface_id, result };
  }

  const result = {
    kind: "stub_result",
    op: tool_surface_id,
    note: "STUB_ONLY_NOT_IMPLEMENTED",
    content_sha256: sha256HexFromUtf8(`STUB:${tool_surface_id}`),
  };
  return { ok: true, tool_surface_id, result };
}

