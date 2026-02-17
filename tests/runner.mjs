import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compileIntent } from "../harness/intent_compiler/compile_intent.mjs";
import { loadToolSurfaceMap } from "../harness/intent_compiler/tool_surface_map.mjs";
import { stableStringify, hashCanonical } from "../harness/intent_compiler/hash.mjs";
import { adaptCompilationToAAR } from "../harness/aar_adapter/aar_adapter.mjs";
import { attest } from "../harness/state_attestation/attest.mjs";

function repoRoot() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..");
}

function readJSON(repo, rel) {
  return JSON.parse(fs.readFileSync(path.resolve(repo, rel), "utf8"));
}

function metric(ok) {
  return ok ? 1.0 : 0.0;
}

function writeCanonicalJSON(filePath, value) {
  const canonical = stableStringify(value);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, canonical, { encoding: "utf8" });
  return { canonical, hash: hashCanonical(value).hash };
}

function appendJSONL(filePath, value) {
  const line = stableStringify(value) + "\n";
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, line, { encoding: "utf8" });
}

function fixtureOutDir(repo, fixtureId, runId) {
  return path.resolve(repo, "tests", "out", runId, fixtureId);
}

function runOne({ repo, runId, fixtureId, intentRelPath, map }) {
  const intent = readJSON(repo, intentRelPath);
  const compilation = compileIntent({ intent, toolSurfaceMap: map });
  const aar = adaptCompilationToAAR(compilation);

  const outDir = fixtureOutDir(repo, fixtureId, runId);
  fs.mkdirSync(outDir, { recursive: true });

  const io = {
    schema_id: "EGL.IO",
    version: "0.1.0",
    fixture_id: fixtureId,
    intent,
    compilation,
    aar,
  };

  const ioRes = writeCanonicalJSON(path.join(outDir, "io.json"), io);

  let planRes = null;
  if (compilation.status === "OK") {
    planRes = writeCanonicalJSON(path.join(outDir, "plan.json"), compilation.plan);
  }

  let attestationRes = null;
  if (aar.status === "ok") {
    const a = attest({ aar });
    attestationRes = writeCanonicalJSON(path.join(outDir, "attestation.json"), a);
  }

  const decision = {
    schema_id: "EGL.DECISION",
    version: "0.1.0",
    fixture_id: fixtureId,
    status: compilation.status === "OK" ? "admitted" : "rejected",
    refusal:
      compilation.status !== "OK"
        ? {
            status: compilation.status,
            code: compilation.code,
            tool_surface_id: compilation.tool_surface_id,
            violated_ref: compilation.violated_ref,
            reason: compilation.reason,
          }
        : null,
    hashes: {
      intent: compilation.hashes?.intent,
      plan: compilation.hashes?.plan ?? null,
      io: ioRes.hash,
      plan_canonical: planRes?.hash ?? null,
      attestation: attestationRes?.hash ?? null,
      aar: aar.hashes?.aar,
      ledger: aar.ledger?.hashes?.ledger,
    },
  };

  const decisionRes = writeCanonicalJSON(path.join(outDir, "decision.json"), decision);

  const speRecord = {
    schema_id: "EGL.SPE_RECORD",
    version: "0.1.0",
    fixture_id: fixtureId,
    decision_hash: decisionRes.hash,
    ledger_hash: aar.ledger?.hashes?.ledger ?? null,
  };

  appendJSONL(path.resolve(repo, "tests", "out", runId, "spe_record.jsonl"), speRecord);

  return {
    fixtureId,
    outDir,
    compilation,
    aar,
    decision,
  };
}

function main() {
  const repo = repoRoot();
  const runId = process.argv.includes("--run-id")
    ? process.argv[process.argv.indexOf("--run-id") + 1]
    : "run";

  const pack = readJSON(repo, "tests/packs/TH-001B.pack.json");
  const map = loadToolSurfaceMap(repo);

  const mapped = runOne({
    repo,
    runId,
    fixtureId: "TH-001B",
    intentRelPath: pack.fixtures.mapped_intent,
    map,
  });

  const unmapped = runOne({
    repo,
    runId,
    fixtureId: "TH-001B-UNMAPPED",
    intentRelPath: pack.fixtures.unmapped_intent,
    map,
  });

  const mappedIntent = readJSON(repo, pack.fixtures.mapped_intent);
  const a1 = compileIntent({ intent: mappedIntent, toolSurfaceMap: map });
  const a2 = compileIntent({ intent: mappedIntent, toolSurfaceMap: map });

  const detCompilation = stableStringify(a1) === stableStringify(a2);
  const detIntentHash = (a1.hashes?.intent ?? null) === (a2.hashes?.intent ?? null);
  const detPlanHash = (a1.hashes?.plan ?? null) === (a2.hashes?.plan ?? null);

  const okMapped =
    mapped.compilation.status === "OK" &&
    Boolean(mapped.compilation.plan) &&
    Boolean(mapped.compilation.hashes?.plan);

  const okRefuse =
    unmapped.compilation.status === "REFUSE_HARD" &&
    unmapped.compilation.code === "UNMAPPED_TOOL_SURFACE" &&
    unmapped.compilation.tool_surface_id === "process.python" &&
    !("plan" in unmapped.compilation) &&
    unmapped.compilation.reason === "No mapping → no execution";

  const detAAR = stableStringify(mapped.aar) === stableStringify(adaptCompilationToAAR(a2));

  const hasArtifactsMapped =
    fs.existsSync(path.join(mapped.outDir, "io.json")) &&
    fs.existsSync(path.join(mapped.outDir, "plan.json")) &&
    fs.existsSync(path.join(mapped.outDir, "decision.json")) &&
    fs.existsSync(path.join(mapped.outDir, "attestation.json"));

  const hasArtifactsUnmapped =
    fs.existsSync(path.join(unmapped.outDir, "io.json")) &&
    fs.existsSync(path.join(unmapped.outDir, "decision.json")) &&
    !fs.existsSync(path.join(unmapped.outDir, "plan.json")) &&
    !fs.existsSync(path.join(unmapped.outDir, "attestation.json"));

  const metrics = {
    mapped_intent_ok: metric(okMapped),
    unmapped_refuse_hard: metric(okRefuse),
    deterministic_compilation: metric(detCompilation),
    deterministic_intent_hash: metric(detIntentHash),
    deterministic_plan_hash: metric(detPlanHash),
    deterministic_aar: metric(detAAR),
    artifacts_mapped: metric(hasArtifactsMapped),
    artifacts_unmapped: metric(hasArtifactsUnmapped),
  };

  const allOne = Object.values(metrics).every((v) => v === 1.0);
  console.log(JSON.stringify({ pack_id: pack.pack_id, run_id: runId, metrics }, null, 2));

  if (!allOne) {
    process.exitCode = 1;
  }
}

main();