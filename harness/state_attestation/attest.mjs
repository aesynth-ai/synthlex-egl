import { hashCanonical } from "../intent_compiler/hash.mjs";

export function attest({ aar }) {
  if (!aar || aar.status !== "ok") {
    throw new Error("attestation requires aar.status=ok");
  }

  const payload = {
    schema_id: "EGL.ATTESTATION",
    version: "0.1.0",
    plan_hash: aar.plan_freeze?.plan_hash,
    ledger_hash: aar.ledger?.hashes?.ledger,
    aar_hash: aar.hashes?.aar,
  };

  const hash = hashCanonical(payload).hash;
  return {
    ...payload,
    hashes: {
      attestation: hash,
    },
  };
}