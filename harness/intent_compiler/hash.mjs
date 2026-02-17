import { createHash } from "node:crypto";

export function sha3_512_hex(inputBytes) {
  return createHash("sha3-512").update(inputBytes).digest("hex");
}

export function sha256_hex(inputBytes) {
  return createHash("sha256").update(inputBytes).digest("hex");
}

export function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(",")}]`;
  }
  const obj = value;
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`);
  return `{${parts.join(",")}}`;
}

export function hashCanonical(value) {
  const canonical = stableStringify(value);
  const hash = `sha3-512:${sha3_512_hex(Buffer.from(canonical, "utf8"))}`;
  return { canonical, hash };
}

export function hashCanonicalSha256(value) {
  const canonical = stableStringify(value);
  const hash = sha256_hex(Buffer.from(canonical, "utf8"));
  return { canonical, hash };
}