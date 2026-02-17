import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

function readJSON(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function run(packPath, runId) {
  const r = spawnSync(process.execPath, ["runner.mjs", "--pack", packPath, "--run-id", runId], {
    stdio: "inherit",
  });
  if (r.status !== 0) {
    throw new Error(`runner failed for run ${runId} with status ${r.status}`);
  }
}

function main() {
  const packPath = process.argv.includes("--pack")
    ? process.argv[process.argv.indexOf("--pack") + 1]
    : "tests/packs/TH-001B.pack.json";

  const runA = process.argv.includes("--runA")
    ? process.argv[process.argv.indexOf("--runA") + 1]
    : "A";

  const runB = process.argv.includes("--runB")
    ? process.argv[process.argv.indexOf("--runB") + 1]
    : "B";

  const pack = readJSON(path.resolve(packPath));
  const packId = pack.pack_id;

  run(packPath, runA);
  run(packPath, runB);

  const a = readJSON(path.resolve("out", packId, runA, "artifact.hashes.json"));
  const b = readJSON(path.resolve("out", packId, runB, "artifact.hashes.json"));

  const diffs = [];
  if (a.hashes.plan_freeze !== b.hashes.plan_freeze) diffs.push("plan_freeze");
  if (a.hashes.ledger_canonical !== b.hashes.ledger_canonical) diffs.push("ledger_canonical");

  const goldenPath = path.resolve("tests", "packs", `${packId}.golden`, "hashes.json");
  if (fs.existsSync(goldenPath)) {
    const golden = readJSON(goldenPath);
    if (a.hashes.plan_freeze !== golden.expected.plan_freeze) diffs.push("golden.plan_freeze");
    if (a.hashes.ledger_canonical !== golden.expected.ledger_canonical) diffs.push("golden.ledger_canonical");
  }

  const expectedRefusals = {
    hash_mismatch: "HASH_MISMATCH",
    lane_mismatch: "LANE_MISMATCH",
    memory_md_write: "MEMORY_MD_WRITE",
    plan_replay: "PLAN_REPLAY",
    system_core_delete: "SYSTEM_CORE_DELETE",
    unmapped_intent: "UNMAPPED_TOOL_SURFACE",
    zone_unknown_file_op: "ZONE_UNKNOWN",
  };

  // Ensure each expected refusal fixture has per_test evidence.
  for (const key of Object.keys(expectedRefusals)) {
    if (!a.per_test[key]) {
      diffs.push(`per_test_missing:${key}`);
    }
  }

  const planFreezeA = readJSON(path.resolve("out", packId, runA, "plan.freeze.json"));
  const byFixture = new Map(planFreezeA.plans.map((p) => [p.fixture_id, p]));

  for (const [fixtureId, code] of Object.entries(expectedRefusals)) {
    const entry = byFixture.get(fixtureId);
    if (!entry) {
      diffs.push(`freeze_missing:${fixtureId}`);
      continue;
    }
    if (entry.reason_code !== code) {
      diffs.push(`freeze_code:${fixtureId}`);
    }
    if (entry.plan !== null) {
      diffs.push(`freeze_plan_not_null:${fixtureId}`);
    }
  }

  const ledgerAPath = path.resolve("out", packId, runA, "spe.ledger.jsonl");
  const ledgerLines = fs
    .readFileSync(ledgerAPath, "utf8")
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));

  for (const [fixtureId, code] of Object.entries(expectedRefusals)) {
    const ok = ledgerLines.some(
      (r) => r.fixture_id === fixtureId && r.kind === "refusal" && r.reason_code === code,
    );
    if (!ok) {
      diffs.push(`ledger_missing:${fixtureId}`);
    }
  }

  if (diffs.length > 0) {
    console.error("Golden replay mismatch:");
    for (const d of diffs) console.error(`- ${d}`);
    process.exit(1);
  }

  console.log("Golden replay: OK");
}

main();