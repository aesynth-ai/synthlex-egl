import { createHash } from "node:crypto";
import { stableStringify } from "../intent_compiler/hash.mjs";

function normalizeString(s) {
  return String(s).trim();
}

function shouldSortStringArray(arr) {
  return Array.isArray(arr) && arr.every((x) => typeof x === "string");
}

function normalizeValue(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") return normalizeString(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    const normalized = value.map(normalizeValue);
    if (shouldSortStringArray(normalized)) {
      return [...normalized].sort((a, b) => String(a).localeCompare(String(b)));
    }
    return normalized;
  }
  if (typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) {
      out[k] = normalizeValue(value[k]);
    }
    return out;
  }
  // Non-JSON values are not allowed.
  throw new Error("capability diff contains non-JSON value");
}

export function canonicalize_capability_diff(diffObj) {
  const normalized = normalizeValue(diffObj);
  return stableStringify(normalized);
}

export function capability_diff_sha256(diffObj) {
  const canonical_json = canonicalize_capability_diff(diffObj);
  const sha256 = createHash("sha256").update(Buffer.from(canonical_json, "utf8")).digest("hex");
  return { canonical_json, sha256 };
}

function uniqueSortedStrings(arr) {
  if (!Array.isArray(arr)) return [];
  const set = new Set(arr.map((x) => (x === null || x === undefined ? "" : String(x).trim())).filter(Boolean));
  return Array.from(set).sort((a, b) => a.localeCompare(b));
}

function normalizeEgressEntry(raw) {
  const s = raw === null || raw === undefined ? "" : String(raw).trim();
  if (!s) return "";

  function explicitPortFromUrlString(urlString) {
    const lower = urlString.toLowerCase();
    const schemeIdx = lower.indexOf("://");
    if (schemeIdx <= 0) return null;

    const rest = urlString.slice(schemeIdx + 3);
    const end = rest.search(/[/?#]/);
    const authority = (end === -1 ? rest : rest.slice(0, end)).trim();
    if (!authority) return null;

    const hostPortPart = authority.includes("@") ? authority.slice(authority.lastIndexOf("@") + 1) : authority;
    const hp = hostPortPart.trim();
    if (!hp) return null;

    // Basic IPv6 support: [::1]:443
    if (hp.startsWith("[")) {
      const close = hp.indexOf("]");
      if (close === -1) return null;
      const after = hp.slice(close + 1);
      if (after.startsWith(":")) {
        const portPart = after.slice(1).trim();
        if (/^\d+$/.test(portPart)) return Number(portPart);
      }
      return null;
    }

    const lastColon = hp.lastIndexOf(":");
    if (lastColon > 0 && lastColon < hp.length - 1) {
      const portPart = hp.slice(lastColon + 1).trim();
      if (/^\d+$/.test(portPart)) return Number(portPart);
    }
    return null;
  }

  // URL form: https://example.com[:port]/...
  if (s.startsWith("http://") || s.startsWith("https://")) {
    try {
      const explicitPort = explicitPortFromUrlString(s);
      const u = new URL(s);
      const host = String(u.hostname ?? "").toLowerCase();
      if (!host) return "";
      // Preserve an explicitly specified port even if it is the scheme default (e.g. :443 for https),
      // since the authority-diff digest treats host-only and host:port as distinct grants.
      if (explicitPort !== null) {
        return `${host}:${explicitPort}`;
      }
      return host;
    } catch {
      // fall through
    }
  }

  // host:port form (including "example.com:443").
  const lastColon = s.lastIndexOf(":");
  if (lastColon > 0 && lastColon < s.length - 1) {
    const hostPart = s.slice(0, lastColon).trim();
    const portPart = s.slice(lastColon + 1).trim();
    if (/^\d+$/.test(portPart)) {
      const host = hostPart.toLowerCase();
      return host ? `${host}:${Number(portPart)}` : "";
    }
  }

  // host-only form: canonicalize to lowercase host (no implicit port).
  // NOTE: `example.com` and `example.com:443` are intentionally distinct authority grants.
  return s.toLowerCase();
}

function uniqueSortedEgress(arr) {
  if (!Array.isArray(arr)) return [];
  const set = new Set(arr.map(normalizeEgressEntry).filter(Boolean));
  return Array.from(set).sort((a, b) => a.localeCompare(b));
}

export function derive_authority_diff(capabilityDiff) {
  const d = capabilityDiff && typeof capabilityDiff === "object" ? capabilityDiff : {};
  return {
    adds_tools: uniqueSortedStrings(d.adds_tools),
    adds_egress: uniqueSortedEgress(d.adds_egress),
    adds_write_roots: uniqueSortedStrings(d.adds_filesystem_write_roots),
  };
}

export function authority_diff_sha256(capabilityDiff) {
  const authority = derive_authority_diff(capabilityDiff);
  const canonical_json = stableStringify(authority);
  const sha256 = createHash("sha256").update(Buffer.from(canonical_json, "utf8")).digest("hex");
  return { canonical_json, sha256 };
}
