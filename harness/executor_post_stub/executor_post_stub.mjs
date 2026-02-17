import { stableStringify, sha256_hex } from "../intent_compiler/hash.mjs";

export function post_stub_receipt({
  surface,
  payload_sha256,
  source_commit_hash,
  source_receipt_hash_sha256,
  permit_sha256,
  ratification_token_hash_sha256,
  law_bundle_sha256,
  plan_hash,
  intent_hash,
}) {
  const receipt = {
    schema_id: "EGL.POST_STUB_RECEIPT",
    version: "0.1.0",
    surface: String(surface ?? ""),
    payload_sha256: String(payload_sha256 ?? ""),
    source_commit_hash: typeof source_commit_hash === "string" ? source_commit_hash : null,
    source_receipt_hash_sha256:
      typeof source_receipt_hash_sha256 === "string" ? source_receipt_hash_sha256 : null,
    permit_sha256: typeof permit_sha256 === "string" ? permit_sha256 : null,
    ratification_token_hash_sha256:
      typeof ratification_token_hash_sha256 === "string" ? ratification_token_hash_sha256 : null,
    law_bundle_sha256: typeof law_bundle_sha256 === "string" ? law_bundle_sha256 : null,
    plan_hash: typeof plan_hash === "string" ? plan_hash : null,
    intent_hash: typeof intent_hash === "string" ? intent_hash : null,
  };

  const canonical = stableStringify(receipt);
  const hash = `sha256:${sha256_hex(Buffer.from(canonical, "utf8"))}`;
  return { receipt, canonical, hash };
}

