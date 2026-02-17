import fs from "node:fs";
import path from "node:path";

function stripComments(line) {
  const idx = line.indexOf("#");
  if (idx === -1) return line;
  return line.slice(0, idx);
}

function parseScalar(raw) {
  const v = raw.trim();
  if (v.startsWith('"') && v.endsWith('"')) return v.slice(1, -1);
  return v;
}

export function parseToolSurfaceMapYAML(yamlText) {
  const lines = yamlText
    .split(/\r?\n/)
    .map((l) => stripComments(l).trimEnd())
    .filter((l) => l.trim().length > 0);

  const out = { surfaces: [] };
  let mode = "top";
  let current = null;

  for (const line of lines) {
    if (line.trim() === "---") continue;

    if (mode === "top") {
      if (line.trim().startsWith("surfaces:")) {
        mode = "surfaces";
        continue;
      }
      const m = line.trim().match(/^([A-Za-z0-9_]+):\s*(.*)$/);
      if (m) {
        out[m[1]] = parseScalar(m[2]);
        continue;
      }
      throw new Error(`Invalid YAML line: ${line}`);
    }

    if (mode === "surfaces") {
      const item = line.match(/^\s*-\s*surface_id:\s*(.+)$/);
      if (item) {
        current = { surface_id: parseScalar(item[1]) };
        out.surfaces.push(current);
        continue;
      }
      const prop = line.trim().match(/^([A-Za-z0-9_]+):\s*(.+)$/);
      if (prop && current) {
        current[prop[1]] = parseScalar(prop[2]);
        continue;
      }
      throw new Error(`Invalid surfaces YAML line: ${line}`);
    }
  }

  if (out.schema_id !== "EGL.TOOL_SURFACE_MAP") {
    throw new Error("tool surface map schema_id mismatch");
  }
  if (!out.version) {
    throw new Error("tool surface map missing version");
  }
  if (!Array.isArray(out.surfaces) || out.surfaces.length === 0) {
    throw new Error("tool surface map must declare at least one surface");
  }
  for (const s of out.surfaces) {
    if (!s.surface_id || !s.kind || !s.schema_ref) {
      throw new Error("tool surface entries require surface_id, kind, schema_ref");
    }
  }
  out.surfaces.sort((a, b) => String(a.surface_id).localeCompare(String(b.surface_id)));
  return out;
}

export function loadToolSurfaceMap(repoRoot) {
  const mapPath = path.resolve(
    repoRoot,
    "harness/intent_compiler/tool_surface_map.v1.1.1.yaml",
  );
  const text = fs.readFileSync(mapPath, "utf8");
  return parseToolSurfaceMapYAML(text);
}