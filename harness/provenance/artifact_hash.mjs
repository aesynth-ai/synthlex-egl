import { createHash } from "node:crypto";

export function sha256_hex(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return createHash("sha256").update(b).digest("hex");
}

export function decode_b64_to_bytes(b64) {
  if (typeof b64 !== "string" || b64.length === 0) {
    throw new Error("bytes_b64 must be a non-empty string");
  }
  return new Uint8Array(Buffer.from(b64, "base64"));
}

