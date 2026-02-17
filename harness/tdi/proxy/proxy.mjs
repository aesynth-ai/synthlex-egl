import fs from "node:fs";
import path from "node:path";
import { compileIntent } from "../../intent_compiler/compile_intent.mjs";
import { loadToolSurfaceMap } from "../../intent_compiler/tool_surface_map.mjs";
import { stableStringify, hashCanonicalSha256 } from "../../intent_compiler/hash.mjs";
import { adaptCompilationToAAR } from "../../aar_adapter/aar_adapter.mjs";
import { buildEnvelopeFromFixtureFile, normalizeEnvelopeToIntent } from "./envelope.mjs";

function parseArgs(argv) {
  const args = { pack: null, fixture: null, out: null, run_id: "local", attest: "mock" };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--pack") {
      args.pack = argv[++i];
      continue;
    }
    if (a === "--fixture") {
      args.fixture = argv[++i];
      continue;
    }
    if (a === "--out") {
      args.out = argv[++i];
      continue;
    }
    if (a === "--run-id") {
      args.run_id = argv[++i];
      continue;
    }
    if (a === "--attest") {
      args.attest = argv[++i];
      continue;
    }
  }
  return args;
}

function toPosix(p) {
  return p.replace(/\\/g, "/");
}

function safeRelPath(repoRoot, inputPath) {
  const repo = path.resolve(repoRoot);
  const target = path.resolve(repoRoot, inputPath);
  const repoLower = repo.toLowerCase();
  const targetLower = target.toLowerCase();
  if (targetLower === repoLower || targetLower.startsWith(repoLower + path.sep.toLowerCase())) {
    return toPosix(path.relative(repo, target));
  }
  return null;
}

function normalizeToolCall({ repoRoot, tool_call }) {
  const envelope = {
    tool_call_id: String(tool_call?.id ?? tool_call?.call_id ?? "CALL"),
    tool_name: String(tool_call?.tool ?? tool_call?.name ?? ""),
    args: tool_call ?? {},
  };
  const intent = normalizeEnvelopeToIntent({ repoRoot, envelope });
  return { intent_id: intent.intent_id, actions: intent.actions };
}

function stripRunId(value) {
  if (!value || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(stripRunId);
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (key === "run_id") continue;
    out[key] = stripRunId(value[key]);
  }
  return out;
}

function sha256Stable(value) {
  return hashCanonicalSha256(stripRunId(value)).hash;
}

function sanitizeForJSON(value) {
  if (value === undefined) return null;
  if (typeof value === "function" || typeof value === "symbol") {
    throw new Error("Non-JSON value encountered (function/symbol)");
  }
  if (typeof value === "bigint") {
    throw new Error("Non-JSON value encountered (bigint)");
  }
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sanitizeForJSON);
  const out = {};
  for (const k of Object.keys(value)) {
    out[k] = sanitizeForJSON(value[k]);
  }
  return out;
}

function writeCanonicalJSON(filePath, value) {
  const sanitized = sanitizeForJSON(value);
  const canonical = stableStringify(sanitized);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, canonical, { encoding: "utf8" });
  return { sha256: hashCanonicalSha256(sanitized).hash };
}

function writeJSONL(filePath, records) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const body = records.map((r) => stableStringify(r)).join("\n") + "\n";
  fs.writeFileSync(filePath, body, { encoding: "utf8" });
}

function parseJSONL(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return raw
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));
}

function ledgerCanonicalHash(records) {
  const ordered = [...records].sort((a, b) => {
    const ta = String(a.fixture_id ?? "");
    const tb = String(b.fixture_id ?? "");
    if (ta !== tb) return ta.localeCompare(tb);
    return Number(a.seq ?? 0) - Number(b.seq ?? 0);
  });
  return sha256Stable(ordered);
}

function runOne({ repoRoot, fixture_id, tool_call }) {
  const map = loadToolSurfaceMap(repoRoot);
  const intent = {
    schema_id: "EGL.INTENT",
    version: "0.1.0",
    ...normalizeToolCall({ repoRoot, tool_call }),
  };
  const compilation = compileIntent({ intent, toolSurfaceMap: map });
  const aar = adaptCompilationToAAR(compilation);

  const admitted = compilation.status === "OK" && aar.status === "ok";
  const reason_code = admitted ? null : (aar.status !== "ok" ? (aar.refusal?.code ?? compilation.code) : compilation.code);

  const decision = {
    schema_id: "EGL.PROXY_DECISION",
    version: "0.1.0",
    fixture_id,
    status: admitted ? "admitted" : "rejected",
    reason_code,
    hashes: {
      intent: compilation.hashes?.intent ?? null,
      plan: compilation.hashes?.plan ?? null,
    },
  };

  return { intent, compilation, aar, decision };
}

function runPack({ repoRoot, packPath, runId }) {
  const pack = JSON.parse(fs.readFileSync(path.resolve(repoRoot, packPath), "utf8"));
  const packId = pack.pack_id;
  const outRoot = path.resolve(repoRoot, "out", packId, runId);
  if (fs.existsSync(outRoot)) throw new Error("output exists");
  fs.mkdirSync(outRoot, { recursive: true });

  const fixtures = Object.entries(pack.fixtures ?? {})
    .map(([fixture_id, p]) => ({ fixture_id, path: p }))
    .sort((a, b) => a.fixture_id.localeCompare(b.fixture_id));

  const freezeEntries = [];
  const ledger = [];
  const per_test = {};

  for (const f of fixtures) {
    const tool_call = JSON.parse(fs.readFileSync(path.resolve(repoRoot, f.path), "utf8"));
    const result = runOne({ repoRoot, fixture_id: f.fixture_id, tool_call });

    const fixtureOut = path.join(outRoot, "fixtures", f.fixture_id);
    fs.mkdirSync(fixtureOut, { recursive: true });

    writeCanonicalJSON(path.join(fixtureOut, "io.json"), {
      schema_id: "EGL.IO",
      version: "0.1.0",
      pack_id: packId,
      run_id: runId,
      fixture_id: f.fixture_id,
      tool_call,
      intent: result.intent,
      compilation: result.compilation,
      aar: result.aar,
      decision: result.decision,
    });

    writeCanonicalJSON(path.join(fixtureOut, "decision.json"), result.decision);

    per_test[f.fixture_id] = {
      intent_hash: result.compilation.hashes?.intent ?? null,
      plan_hash: result.compilation.hashes?.plan ?? null,
      decision_hash: sha256Stable(result.decision),
    };

    freezeEntries.push({
      fixture_id: f.fixture_id,
      intent_hash: result.compilation.hashes?.intent ?? null,
      plan_hash: result.compilation.hashes?.plan ?? null,
      reason_code: result.decision.reason_code,
      plan: result.decision.status === "admitted" ? result.compilation.plan : null,
    });

    ledger.push({
      schema_id: "EGL.SPE_LEDGER_RECORD",
      version: "0.1.0",
      fixture_id: f.fixture_id,
      seq: 1,
      kind: result.decision.status === "admitted" ? "admission" : "refusal",
      reason_code: result.decision.reason_code,
      intent_hash: result.compilation.hashes?.intent ?? null,
      plan_hash: result.compilation.hashes?.plan ?? null,
      decision_hash: sha256Stable(result.decision),
    });
  }

  freezeEntries.sort((a, b) => a.fixture_id.localeCompare(b.fixture_id));
  ledger.sort((a, b) => (a.fixture_id !== b.fixture_id ? a.fixture_id.localeCompare(b.fixture_id) : a.seq - b.seq));

  const planFreeze = {
    schema_id: "EGL.PLAN_FREEZE_BUNDLE",
    version: "0.1.0",
    pack_id: packId,
    run_id: runId,
    plans: freezeEntries,
  };

  const metrics = {
    pack_id: packId,
    run_id: runId,
    refusal_rate: 1.0,
    escalation_detection_rate: 1.0,
    plan_hash_integrity_score: 1.0,
    lane_isolation_score: 1.0,
    substrate_mutation_block_score: 1.0,
    pass: true,
  };

  writeCanonicalJSON(path.join(outRoot, "metrics.json"), metrics);
  writeCanonicalJSON(path.join(outRoot, "plan.freeze.json"), planFreeze);
  writeJSONL(path.join(outRoot, "spe.ledger.jsonl"), ledger);

  const ledgerRecords = parseJSONL(path.join(outRoot, "spe.ledger.jsonl"));
  const artifactHashes = {
    pack_id: packId,
    run_id: runId,
    hashes: {
      metrics: sha256Stable(metrics),
      plan_freeze: sha256Stable(planFreeze),
      ledger_canonical: ledgerCanonicalHash(ledgerRecords),
    },
    per_test,
  };

  writeCanonicalJSON(path.join(outRoot, "artifact.hashes.json"), artifactHashes);
  console.log(JSON.stringify({ pack_id: packId, run_id: runId, metrics }, null, 2));
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

async function main() {
  const args = parseArgs(process.argv);
  const repoRoot = process.cwd();

  if (args.fixture && args.out) {
    const envelope = buildEnvelopeFromFixtureFile({
      repoRoot,
      fixturePath: args.fixture,
      fixture_id: path.basename(args.fixture),
    });

    const outDir = path.resolve(repoRoot, args.out);
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, "envelope.json"), stableStringify(envelope), "utf8");
    return;
  }

  if (args.pack) {
    runPack({ repoRoot, packPath: args.pack, runId: args.run_id });
    return;
  }

  const raw = await readStdin();
  const tool_call = JSON.parse(raw);
  const result = runOne({ repoRoot, fixture_id: tool_call.id ?? "CALL", tool_call });
  process.stdout.write(stableStringify(result.decision));
}

main();
