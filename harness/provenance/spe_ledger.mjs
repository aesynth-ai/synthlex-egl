import { hashCanonical } from "../intent_compiler/hash.mjs";

export function buildLedger({ planFreeze, refusal }) {
  const entries = [];

  if (refusal) {
    entries.push({
      entry_id: "SPE/REFUSAL/0001",
      kind: "refusal",
      code: refusal.code,
      tool_surface_id: refusal.tool_surface_id,
      hashes: {
        refusal: refusal.hashes?.refusal ?? hashCanonical(refusal).hash,
      },
    });
  }

  if (planFreeze) {
    entries.push({
      entry_id: "SPE/PLAN_FREEZE/0001",
      kind: "plan_freeze",
      plan_hash: planFreeze.plan_hash,
      hashes: {
        freeze: planFreeze.hashes?.freeze ?? hashCanonical(planFreeze).hash,
      },
    });
  }

  entries.sort((a, b) => a.entry_id.localeCompare(b.entry_id));

  const ledger = {
    schema_id: "EGL.SPE_LEDGER",
    version: "0.1.0",
    entries,
  };

  return {
    ...ledger,
    hashes: {
      ledger: hashCanonical(ledger).hash,
    },
  };
}