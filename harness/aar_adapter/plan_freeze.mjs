import { hashCanonical, stableStringify } from "../intent_compiler/hash.mjs";

export function freezePlan(plan) {
  const { canonical, hash } = hashCanonical(plan);
  return {
    schema_id: "EGL.PLAN_FREEZE",
    version: "0.1.0",
    plan_hash: hash,
    plan_canonical: canonical,
    plan,
  };
}

export function freezeCompilation(compilation) {
  if (!compilation || compilation.status !== "OK") {
    throw new Error("cannot freeze: compilation not OK");
  }
  const freeze = freezePlan(compilation.plan);
  return {
    ...freeze,
    hashes: {
      plan: freeze.plan_hash,
      freeze: hashCanonical({
        schema_id: freeze.schema_id,
        version: freeze.version,
        plan_hash: freeze.plan_hash,
      }).hash,
    },
  };
}

export function stableJSON(value) {
  return stableStringify(value);
}