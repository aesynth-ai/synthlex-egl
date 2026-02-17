import { stableStringify } from "./hash.mjs";

export function canonicalBytes(value) {
  return Buffer.from(stableStringify(value), "utf8");
}

export function canonicalString(value) {
  return stableStringify(value);
}