function normalizeHost(host) {
  return String(host ?? "").trim().toLowerCase();
}

function stripDefaultPort({ protocol, host, port }) {
  const p = String(port ?? "");
  if (!p) return host;
  if ((protocol === "https:" && p === "443") || (protocol === "http:" && p === "80")) return host;
  return `${host}:${p}`;
}

function isLocalhost(host) {
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

function isRfc1918(host) {
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

export function attest_network_live({ url_or_host }) {
  // Deterministic/minimal: do not DNS-resolve.
  const raw = String(url_or_host ?? "");

  let protocol = null;
  let host = null;
  let target = null;
  let zone = "UNKNOWN";

  try {
    const u = new URL(raw);
    protocol = u.protocol;
    host = normalizeHost(u.hostname);
    target = `${protocol}//${stripDefaultPort({ protocol, host, port: u.port })}${u.pathname || "/"}${
      u.search || ""
    }`;
  } catch {
    host = normalizeHost(raw);
    target = host;
  }

  if (isLocalhost(host)) zone = "LOCALHOST";
  else if (isRfc1918(host)) zone = "LAN";
  else if (protocol === "https:") zone = "PUBLIC_INTERNET";

  return {
    schema_id: "MVM.NETWORK",
    version: "0.1.0",
    zone,
    target,
    host,
    ip: null,
  };
}
