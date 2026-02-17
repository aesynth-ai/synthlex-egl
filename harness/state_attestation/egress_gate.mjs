function toPosix(s) {
  return String(s ?? "").replace(/\\/g, "/");
}

function normalizeHost(hostRaw) {
  const h = String(hostRaw ?? "").trim().toLowerCase();
  return h;
}

function parseTargetFromUrlOrHost(input) {
  const raw = String(input ?? "").trim();
  if (!raw) return { ok: false, target_input: raw, protocol: null, host: null, port: null, port_explicit: false };

  // URL form
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) {
    try {
      const u = new URL(raw);
      const protocol = String(u.protocol ?? "").replace(":", "").toUpperCase();
      const host = normalizeHost(u.hostname ?? "");
      const portStr = String(u.port ?? "");

      // URL() omits default ports (e.g. https://host:443 => u.port === "").
      // We must preserve whether a port was explicitly present in the input.
      const authorityRaw = (() => {
        const tail = raw.split("://", 2)[1] ?? "";
        const end = tail.search(/[/?#]/);
        const authority = end === -1 ? tail : tail.slice(0, end);
        const at = authority.lastIndexOf("@");
        return at >= 0 ? authority.slice(at + 1) : authority;
      })();

      const explicitPort = (() => {
        const s = authorityRaw.trim();
        if (!s) return null;
        if (s.startsWith("[")) {
          const idx = s.indexOf("]");
          if (idx >= 0) {
            const rest = s.slice(idx + 1);
            const m = rest.match(/^:([0-9]{1,5})$/);
            return m ? m[1] : null;
          }
          return null;
        }
        const m = s.match(/:([0-9]{1,5})$/);
        return m ? m[1] : null;
      })();

      const portEffectiveStr = portStr || explicitPort || "";
      const port = portEffectiveStr ? Number(portEffectiveStr) : null;
      const port_explicit = Boolean(explicitPort);
      return { ok: Boolean(host), target_input: raw, protocol, host, port, port_explicit };
    } catch {
      return { ok: false, target_input: raw, protocol: null, host: null, port: null, port_explicit: false };
    }
  }

  // Host or host:port (no protocol)
  // Note: for IPv6 literals, require URL form for determinism (e.g., http://[::1]:3000).
  const m = raw.match(/^([^:\s]+)(?::([0-9]{1,5}))?$/);
  if (!m) return { ok: false, target_input: raw, protocol: null, host: null, port: null, port_explicit: false };
  const host = normalizeHost(m[1]);
  const portStr = m[2] ? String(m[2]) : "";
  const port = portStr ? Number(portStr) : null;
  const port_explicit = Boolean(portStr);
  return { ok: Boolean(host), target_input: raw, protocol: null, host, port, port_explicit };
}

function canonicalTarget({ host, port, port_explicit }) {
  if (!host) return null;
  if (port_explicit && Number.isFinite(port) && port !== null) return `${host}:${port}`;
  return host;
}

function isLocalhostHost(host) {
  const h = normalizeHost(host);
  return h === "localhost" || h === "127.0.0.1" || h === "::1";
}

function isPrivateIpv4(host) {
  const h = normalizeHost(host);
  const parts = h.split(".");
  if (parts.length !== 4) return false;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = nums;
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

function isPrivateIpv6(host) {
  const h = normalizeHost(host);
  // Minimal deterministic check for fc00::/7 and fe80::/10 link-local.
  return h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80:");
}

function zoneFromHost(host) {
  if (!host) return "UNKNOWN";
  if (isLocalhostHost(host)) return "LOCALHOST";
  if (isPrivateIpv4(host) || isPrivateIpv6(host)) return "LAN";
  return "PUBLIC_INTERNET";
}

function canonicalizeAllowlistEntry(entry) {
  const s = String(entry ?? "").trim();
  if (!s) return null;
  const p = parseTargetFromUrlOrHost(s);
  if (!p.ok) return null;
  return canonicalTarget(p);
}

function canonicalizeAllowlist(list) {
  const raw = Array.isArray(list) ? list : [];
  const out = raw
    .map((e) => canonicalizeAllowlistEntry(e))
    .filter((e) => typeof e === "string" && e.length > 0);
  out.sort((a, b) => a.localeCompare(b));
  return out;
}

function splitCanonicalTarget(t) {
  const s = String(t ?? "").trim().toLowerCase();
  if (!s) return { host: null, port: null, port_explicit: false };
  const m = s.match(/^([^:\s]+):([0-9]{1,5})$/);
  if (!m) return { host: s, port: null, port_explicit: false };
  return { host: m[1], port: Number(m[2]), port_explicit: true };
}

export function evaluate_egress({ target, protocol, permit_scope }) {
  const parsed = parseTargetFromUrlOrHost(target);
  const proto = (protocol ? String(protocol) : parsed.protocol ? String(parsed.protocol) : "").toUpperCase();
  const canonical_target = canonicalTarget(parsed);
  const host = parsed.host;
  const zone = zoneFromHost(host);

  const scope = permit_scope && typeof permit_scope === "object" ? permit_scope : null;
  if (!scope || scope.allow !== true) {
    return { status: "refused", reason_code: "EGRESS_SCOPE_VIOLATION", canonical_target, protocol: proto || null, zone };
  }

  const allow_http = scope.allow_http === true;
  const allow_localhost = scope.allow_localhost === true;
  const allow_lan = scope.allow_lan === true;
  const allowlist = canonicalizeAllowlist(scope.allowlist);

  // Zone policy (deny-first, deterministic precedence).
  if (zone === "LOCALHOST" && !allow_localhost) {
    return { status: "refused", reason_code: "LOCALHOST_DENIED", canonical_target, protocol: proto || null, zone, allowlist };
  }
  if (zone === "LAN" && !allow_lan) {
    return { status: "refused", reason_code: "LAN_DENIED", canonical_target, protocol: proto || null, zone, allowlist };
  }

  // Protocol policy.
  if (proto === "HTTP" && !allow_http) {
    return { status: "refused", reason_code: "INSECURE_PROTOCOL", canonical_target, protocol: proto, zone, allowlist };
  }

  // Allowlist exact-match semantics (host-only != host:port).
  if (!canonical_target || !allowlist.includes(canonical_target)) {
    // Detect same-host port-shape/port-value drift explicitly.
    const req = splitCanonicalTarget(canonical_target);
    if (req.host) {
      const sameHostDifferentPortShape = allowlist.some((entry) => {
        const grant = splitCanonicalTarget(entry);
        if (!grant.host || grant.host !== req.host) return false;
        if (grant.port_explicit !== req.port_explicit) return true;
        if (grant.port_explicit && req.port_explicit && grant.port !== req.port) return true;
        return false;
      });
      if (sameHostDifferentPortShape) {
        return { status: "refused", reason_code: "EGRESS_DRIFT", canonical_target, protocol: proto || null, zone, allowlist };
      }
    }
    return { status: "refused", reason_code: "EGRESS_DENIED", canonical_target, protocol: proto || null, zone, allowlist };
  }

  return { status: "ok", reason_code: null, canonical_target, protocol: proto || null, zone, allowlist };
}
