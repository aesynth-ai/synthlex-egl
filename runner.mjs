import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { compileIntentFromFile } from "./harness/intent_compiler/compile_intent.mjs";
import { compileIntent, loadToolSurfaceMap } from "./harness/intent_compiler/index.mjs";
import { adaptCompilationToAAR } from "./harness/aar_adapter/aar_adapter.mjs";
import { attest } from "./harness/state_attestation/attest.mjs";
import { live } from "./harness/state_attestation/index.mjs";
import { stableStringify, hashCanonicalSha256 } from "./harness/intent_compiler/hash.mjs";
import { buildEnvelopeFromToolCall, normalizeEnvelopeToIntent } from "./harness/tdi/proxy/envelope.mjs";
import { capability_diff_sha256, authority_diff_sha256 } from "./harness/provenance/capability_diff.mjs";
import { build_sce } from "./harness/provenance/sce.mjs";
import { computeLawBundle } from "./harness/provenance/law_bundle.mjs";
import {
  validate_execution_permit,
  compute_permit_sha256,
  pathWithinRoots,
  validate_git_scope,
  validate_publish_scope,
  validate_egress_scope,
  validate_exec_scope,
  validate_deps_scope,
} from "./harness/provenance/execution_permit.mjs";
import { execute_real_sandbox, file_state_sha256 } from "./harness/executor_real/executor_real.mjs";
import { unifiedDiff } from "./harness/executor_real/diff_engine.mjs";
import {
  validate_git_ratification_token,
  git_ratification_token_sha256,
  validate_publish_post_ratification_token,
  publish_post_ratification_token_sha256,
} from "./harness/provenance/ratification_token.mjs";
import {
  git_pipeline_commit_from_diff,
  git_execution_evidence,
  stableGitReceipt,
} from "./harness/executor_git/executor_git.mjs";
import { post_stub_receipt } from "./harness/executor_post_stub/executor_post_stub.mjs";
import { evaluate_egress } from "./harness/state_attestation/egress_gate.mjs";

function parseArgs(argv) {
  const args = {
    pack: "tests/packs/TH-001B.pack.json",
    run_id: "local",
    attest: "mock",
    source: "fixture",
    git: "mock",
    exec: "mock",
    deps: "mock",
    now: null,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--pack") {
      args.pack = argv[++i];
      continue;
    }
    if (a === "--run-id") {
      args.run_id = argv[++i];
      continue;
    }
    // Back-compat alias
    if (a === "--run") {
      args.run_id = argv[++i];
      continue;
    }
    if (a === "--attest") {
      args.attest = argv[++i];
      continue;
    }
    if (a === "--source") {
      args.source = argv[++i];
      continue;
    }
    if (a === "--git") {
      args.git = argv[++i];
      continue;
    }
    if (a === "--exec") {
      args.exec = argv[++i];
      continue;
    }
    if (a === "--deps") {
      args.deps = argv[++i];
      continue;
    }
    if (a === "--now") {
      args.now = argv[++i];
      continue;
    }
    if (a === "--help") {
      args.help = true;
      continue;
    }
  }
  return args;
}

function readJSON(relPath) {
  const raw = fs.readFileSync(path.resolve(process.cwd(), relPath), "utf8");
  return JSON.parse(raw);
}

function ensureNewDir(dirPath) {
  if (fs.existsSync(dirPath)) {
    throw new Error(
      `Output directory already exists: ${path.relative(process.cwd(), dirPath)}`,
    );
  }
  fs.mkdirSync(dirPath, { recursive: true });
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
  return { canonical, sha256: hashCanonicalSha256(sanitized).hash };
}

function writeJSONL(filePath, records) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const body = records.map((r) => stableStringify(r)).join("\n") + "\n";
  fs.writeFileSync(filePath, body, { encoding: "utf8" });
}

function gitBranchRefExists({ repoRoot, branch }) {
  if (typeof branch !== "string" || branch.length === 0) return null;
  const gitDir = path.resolve(repoRoot, ".git");
  if (!fs.existsSync(gitDir) || !fs.statSync(gitDir).isDirectory()) return null;

  const refPath = path.resolve(gitDir, "refs", "heads", ...branch.split("/"));
  if (fs.existsSync(refPath)) return true;

  const packedRefs = path.resolve(gitDir, "packed-refs");
  if (!fs.existsSync(packedRefs)) return false;
  const raw = fs.readFileSync(packedRefs, "utf8");
  const needle = `refs/heads/${branch}`;
  return raw.split(/\r?\n/).some((l) => l && !l.startsWith("#") && !l.startsWith("^") && l.endsWith(needle));
}

function sha256HexFromUtf8Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha256HexFromUtf8(text) {
  return createHash("sha256").update(Buffer.from(String(text), "utf8")).digest("hex");
}

function readFileSha256Hex({ repoRoot, relPath }) {
  if (typeof relPath !== "string" || relPath.length === 0 || relPath === "OUTSIDE_REPO") return null;
  const abs = path.resolve(repoRoot, relPath);
  const root = path.resolve(repoRoot);
  if (!abs.startsWith(root)) return null;
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) return null;
  const bytes = fs.readFileSync(abs);
  return createHash("sha256").update(bytes).digest("hex");
}

function deriveWriteAfterText({ relPath, envelopeArgs }) {
  const args = envelopeArgs && typeof envelopeArgs === "object" ? envelopeArgs : {};
  const spec = args.write_spec && typeof args.write_spec === "object" ? args.write_spec : null;

  if (typeof args.after_text === "string") {
    return args.after_text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  }

  if (typeof args.draft_kind === "string" && typeof args.content === "string") {
    const kind = String(args.draft_kind ?? "x_post");
    const contentRaw = String(args.content ?? "");
    const contentLf = contentRaw.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const contentTrimmed = contentLf
      .split("\n")
      .map((line) => line.replace(/[ \t]+$/g, ""))
      .join("\n");
    const contentNorm = contentTrimmed.endsWith("\n") ? contentTrimmed : `${contentTrimmed}\n`;
    const contentSha = sha256HexFromUtf8(contentTrimmed);

    const header =
      `---\n` +
      `schema_id: EGL.PUBLISH_DRAFT\n` +
      `version: 0.1.0\n` +
      `draft_kind: ${kind}\n` +
      `content_sha256: sha256:${contentSha}\n` +
      `---\n`;
    return `${header}${contentNorm}`;
  }

  if (spec && String(spec.kind ?? "") === "literal") {
    const t = typeof spec.text === "string" ? spec.text : "";
    return t.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  }

  if (spec && String(spec.kind ?? "") === "repeat") {
    const chRaw = typeof spec.char === "string" ? spec.char : "A";
    const ch = chRaw.length > 0 ? chRaw.slice(0, 1) : "A";
    const count = Number(spec.count ?? 0);
    const n = Number.isFinite(count) && count > 0 ? Math.floor(count) : 0;
    const prefix = `EGL_DIFF_WRITE:${String(relPath ?? "")}\n`;
    return prefix + ch.repeat(n);
  }

  // Default deterministic payload.
  return `EGL_DIFF_WRITE:${String(relPath ?? "")}`;
}

function deterministicNonce({ intent_hash }) {
  return sha256HexFromUtf8(`nonce:${String(intent_hash ?? "")}`);
}

function bindingNonce({ attestMode, intent_hash, force_nonce, last_nonce }) {
  if (attestMode === "live") {
    if (typeof force_nonce === "string" && force_nonce.length > 0) {
      if (force_nonce === "REUSE_LAST_NONCE") return last_nonce ?? null;
      return force_nonce;
    }
    return randomUUID();
  }
  if (typeof force_nonce === "string" && force_nonce.startsWith("FIXTURE:")) {
    return force_nonce;
  }
  return deterministicNonce({ intent_hash });
}

function listFilesRecursive(rootDir) {
  const out = [];
  const stack = [rootDir];
  while (stack.length > 0) {
    const dir = stack.pop();
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) stack.push(p);
      else if (e.isFile()) out.push(p);
    }
  }
  out.sort((a, b) => a.localeCompare(b));
  return out;
}

function containsAbsolutePathLeak(text) {
  if (typeof text !== "string") return false;
  // Windows drive paths, extended-length, UNC, and common Unix absolute roots.
  if (/[A-Za-z]:\\/.test(text)) return true;
  if (/\\\\\?\\/.test(text)) return true;
  if (/\\\\[A-Za-z0-9_.-]+\\/.test(text)) return true;
  if (/\/Users\//.test(text)) return true;
  if (/\/home\//.test(text)) return true;
  return false;
}

function computeNoAbsolutePathLeakScore(outRoot) {
  const files = listFilesRecursive(outRoot).filter((p) => {
    const ext = path.extname(p).toLowerCase();
    return ext === ".json" || ext === ".jsonl";
  });
  for (const f of files) {
    const raw = fs.readFileSync(f, "utf8");
    if (containsAbsolutePathLeak(raw)) return 0.0;
  }
  return 1.0;
}

function computeNoAbsolutePathLeakScoreWithExtras({ outRoot, extraRoots }) {
  const roots = [outRoot, ...(Array.isArray(extraRoots) ? extraRoots : [])].filter(Boolean);
  for (const root of roots) {
    if (!fs.existsSync(root)) continue;
    const score = computeNoAbsolutePathLeakScore(root);
    if (score !== 1.0) return 0.0;
  }
  return 1.0;
}

function normalizeAttestComparable(entry) {
  if (!entry || typeof entry !== "object") return null;
  return {
    zone: String(entry.zone ?? ""),
    path: String(entry.path ?? ""),
    is_symlink: Boolean(entry.classification?.is_symlink ?? false),
    content_hash: entry.integrity?.content_hash ?? null,
    size_bytes: entry.integrity?.size_bytes ?? null,
  };
}

function attestComparableEqual(a, b) {
  const x = normalizeAttestComparable(a);
  const y = normalizeAttestComparable(b);
  if (!x || !y) return false;
  return (
    x.zone === y.zone &&
    x.path === y.path &&
    x.is_symlink === y.is_symlink &&
    x.content_hash === y.content_hash &&
    x.size_bytes === y.size_bytes
  );
}

function ensureToctouTemp({ repoRoot }) {
  const dir = path.resolve(repoRoot, "sandbox", "_th_tmp", "toctou_symlink_swap");
  fs.mkdirSync(dir, { recursive: true });
  const safe = path.join(dir, "safe.txt");
  const secret = path.join(dir, "secret.txt");
  const target = path.join(dir, "target.txt");
  fs.writeFileSync(safe, "SAFE\n", "utf8");
  fs.writeFileSync(secret, "SECRET\n", "utf8");
  fs.copyFileSync(safe, target);
  return { dir, safe, secret, target, targetRel: path.relative(repoRoot, target).replace(/\\/g, "/") };
}

function simulateToctouSwap({ repoRoot, paths }) {
  // Prefer symlink swap (classic TOCTOU). If unsupported, fall back to atomic replace.
  try {
    try {
      fs.rmSync(paths.target, { force: true });
    } catch {}
    fs.symlinkSync("secret.txt", paths.target, "file");
    return { method: "symlink", targetRel: paths.targetRel };
  } catch {
    fs.copyFileSync(paths.secret, paths.target);
    return { method: "replace", targetRel: paths.targetRel };
  }
}

function stripRunId(value) {
  if (!value || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(stripRunId);
  const obj = value;
  const out = {};
  for (const key of Object.keys(obj).sort()) {
    if (key === "run_id") continue;
    out[key] = stripRunId(obj[key]);
  }
  return out;
}

function sha256Stable(value) {
  return hashCanonicalSha256(stripRunId(value)).hash;
}

function parseJSONL(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
  return lines.map((l) => JSON.parse(l));
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

function ledgerChainHash(records) {
  const ordered = [...records].sort((a, b) => {
    const ta = String(a.fixture_id ?? "");
    const tb = String(b.fixture_id ?? "");
    if (ta !== tb) return ta.localeCompare(tb);
    return Number(a.seq ?? 0) - Number(b.seq ?? 0);
  });

  let h = "";
  for (const r of ordered) {
    const recHash = sha256Stable(r);
    h = sha256Stable({ prev: h, rec: recHash });
  }
  return h;
}

function metric(ok) {
  return ok ? 1.0 : 0.0;
}

function finalOutcome({ compilation, aar }) {
  const compilationOk = compilation.status === "OK";
  const aarOk = aar.status === "ok";

  if (compilationOk && aarOk) {
    return {
      admitted: true,
      reason_code: typeof aar?.admission?.code === "string" ? aar.admission.code : null,
      refusal_status: null,
    };
  }

  if (!compilationOk) {
    return {
      admitted: false,
      reason_code: compilation.code,
      refusal_status: compilation.status,
    };
  }

  return {
    admitted: false,
    reason_code: aar.refusal?.code ?? "AAR_REJECTED",
    refusal_status: aar.refusal?.status ?? "REFUSE_HARD",
  };
}

function liveAttestationBundle({ plan }) {
  const actions = Array.isArray(plan?.actions) ? plan.actions : [];
  const entries = [];

  for (const a of actions) {
    if (a.kind === "file" && a.file) {
      entries.push(
        live.attest_file_live({
          repoRoot: process.cwd(),
          op: String(a.file.op ?? "unknown"),
          input_path: String(a.file.path ?? ""),
        }),
      );
    }
    if (a.kind === "net" && a.net) {
      entries.push(live.attest_network_live({ url_or_host: a.net.url ?? "" }));
    }
    if (a.kind === "process" && a.process) {
      entries.push(live.attest_process_live({ command: a.process.command, args: a.process.args }));
    }
  }

  return {
    schema_id: "EGL.ATTESTATION_LIVE_BUNDLE",
    version: "0.1.0",
    entries,
  };
}

function hasAbsWindowsPathString(s) {
  if (typeof s !== "string") return false;
  return /^[a-zA-Z]:\\/.test(s) || /^\\\\/.test(s) || /[a-zA-Z]:\\/.test(s);
}

function assertNoAbsWindowsPathsInText(text, where) {
  if (typeof text !== "string") return;
  if (hasAbsWindowsPathString(text)) {
    throw new Error(`Absolute Windows path is not allowed in ${where}`);
  }
}

function redactSkillInstallBytesFromEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object") return envelope;
  if (envelope.tool_name !== "skill.install") return envelope;
  const args = envelope.args;
  if (!args || typeof args !== "object") return envelope;
  const req = args.skill_install_request;
  if (!req || typeof req !== "object") return envelope;
  const artifact = req.artifact;
  if (!artifact || typeof artifact !== "object") return envelope;
  if (!("bytes_b64" in artifact)) return envelope;

  const redacted = { ...envelope, args: { ...args, skill_install_request: { ...req, artifact: { ...artifact } } } };
  delete redacted.args.skill_install_request.artifact.bytes_b64;
  return redacted;
}

function redactSkillInstallTokensFromEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object") return envelope;
  if (envelope.tool_name !== "skill.install") return envelope;
  const args = envelope.args;
  if (!args || typeof args !== "object") return envelope;
  const req = args.skill_install_request;
  if (!req || typeof req !== "object") return envelope;

  const redacted = { ...envelope, args: { ...args, skill_install_request: { ...req } } };
  delete redacted.args.skill_install_request.ratification_token;
  delete redacted.args.skill_install_request.ratification_tokens;
  return redacted;
}

function redactSkillInstallSecretsFromEnvelope(envelope) {
  return redactSkillInstallTokensFromEnvelope(redactSkillInstallBytesFromEnvelope(envelope));
}

function redactExecutionPermitFromEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object") return envelope;
  const args = envelope.args;
  if (!args || typeof args !== "object") return envelope;
  if (!Object.prototype.hasOwnProperty.call(args, "execution_permit")) return envelope;

  const redacted = { ...envelope, args: { ...args } };
  const permit = args.execution_permit;
  const permit_sha256 =
    permit && typeof permit === "object" ? compute_permit_sha256(permit) : null;
  delete redacted.args.execution_permit;
  redacted.args.execution_permit_sha256 = permit_sha256;
  return redacted;
}

function redactEnvelopeForIO(envelope) {
  const base = redactExecutionPermitFromEnvelope(redactSkillInstallSecretsFromEnvelope(envelope));
  if (!base || typeof base !== "object") return base;
  if (
    base.tool_name !== "git.pipeline_commit_from_diff" &&
    base.tool_name !== "publish.draft.commit" &&
    base.tool_name !== "publish.post.x" &&
    base.tool_name !== "publish.post.x_thread" &&
    base.tool_name !== "code.patch.apply"
  )
    return base;
  const args = base.args;
  if (!args || typeof args !== "object") return base;

  const redacted = { ...base, args: { ...args } };
  if (base.tool_name === "code.patch.apply") {
    const after = typeof args.after_text === "string" ? args.after_text : "";
    const after_sha256 = after.length > 0 ? hashCanonicalSha256(after) : null;
    delete redacted.args.after_text;
    redacted.args.after_text_sha256 = typeof args.after_text_sha256 === "string" ? args.after_text_sha256 : after_sha256;
    return redacted;
  }
  const t = args.ratification_token;
  let token_sha256 = null;
  if (t && typeof t === "object") {
    if (base.tool_name === "git.pipeline_commit_from_diff" || base.tool_name === "publish.draft.commit") {
      const h = git_ratification_token_sha256(t);
      token_sha256 = typeof h === "string" && h.length > 0 ? `sha256:${h}` : null;
    } else {
      const h = publish_post_ratification_token_sha256(t);
      token_sha256 = typeof h === "string" && h.length > 0 ? `sha256:${h}` : null;
    }
  }
  delete redacted.args.ratification_token;
  redacted.args.ratification_token_sha256 = token_sha256;
  return redacted;
}

function writeEnvelopeViaProxy({ repoRoot, fixturePath, outDirRel }) {
  const r = spawnSync(
    process.execPath,
    ["harness/tdi/proxy/proxy.mjs", "--fixture", fixturePath, "--out", outDirRel],
    { cwd: repoRoot, stdio: "inherit" },
  );
  if (r.status !== 0) {
    throw new Error(`proxy failed for fixture ${fixturePath} with status ${r.status}`);
  }
}

function runPack({ packPath, runId, attestMode, source, gitMode, execMode, depsMode, nowOverrideIso }) {
  const repoRoot = process.cwd();
  const pack = readJSON(packPath);
  const packId = pack.pack_id;
  if (!packId || typeof packId !== "string") {
    throw new Error("pack_id missing from pack JSON");
  }

  const mockNowIso =
    typeof nowOverrideIso === "string" && nowOverrideIso.length > 0
      ? nowOverrideIso
      : "2026-02-13T00:00:00Z";
  const nowMs = attestMode === "live" ? Date.now() : Date.parse(mockNowIso);
  const nowIso = attestMode === "live" ? new Date(nowMs).toISOString() : mockNowIso;

  const outRoot = path.resolve(repoRoot, "out", packId, runId);
  ensureNewDir(outRoot);

  let lawBinding = null;
  if (source === "proxy" && packId === "TH-001C") {
    lawBinding = computeLawBundle({ repoRoot });
    writeCanonicalJSON(path.join(outRoot, "law.bundle.json"), lawBinding.bundle);
    writeCanonicalJSON(path.join(outRoot, "law.bundle.hash.json"), {
      schema_id: "EGL.LAW_BUNDLE_HASH",
      version: "0.1.0",
      law_bundle_sha256: lawBinding.law_bundle_sha256,
    });
  }

  // Deterministic sandbox temp reset for real execution tests (TH-001C proxy runs only).
  if (source === "proxy" && packId === "TH-001C") {
    const tmpDirRel = path.join("sandbox", "_th_tmp");
    const tmpDirAbs = path.resolve(repoRoot, tmpDirRel);
    if (fs.existsSync(tmpDirAbs)) {
      fs.rmSync(tmpDirAbs, { recursive: true, force: true });
    }
    fs.mkdirSync(tmpDirAbs, { recursive: true });
    fs.writeFileSync(
      path.join(tmpDirAbs, "seed.txt"),
      "EGL_SANDBOX_SEED:seed.txt",
      "utf8",
    );
    const toctouDirAbs = path.join(tmpDirAbs, "toctou_symlink_swap");
    fs.mkdirSync(toctouDirAbs, { recursive: true });
    fs.writeFileSync(path.join(toctouDirAbs, "target.txt"), "SAFE\n", "utf8");

    const draftsRel = path.join("sandbox", "_publish_drafts");
    const draftsAbs = path.resolve(repoRoot, draftsRel);
    if (fs.existsSync(draftsAbs)) {
      fs.rmSync(draftsAbs, { recursive: true, force: true });
    }
    fs.mkdirSync(draftsAbs, { recursive: true });
    writeCanonicalJSON(path.join(outRoot, "sandbox.reset.json"), {
      schema_id: "EGL.SANDBOX_RESET",
      version: "0.1.0",
      root: tmpDirRel.replace(/\\/g, "/"),
      seeded_files: [
        "sandbox/_th_tmp/seed.txt",
        "sandbox/_th_tmp/toctou_symlink_swap/target.txt",
      ],
      cleaned_roots: ["sandbox/_publish_drafts/"],
    });
  }

  const fixtureEntries = Object.entries(pack.fixtures ?? {});
  const fixtures = fixtureEntries
    .map(([fixture_id, intent_path]) => ({ fixture_id, intent_path }))
    .sort((a, b) => a.fixture_id.localeCompare(b.fixture_id));

  const perTest = {};
  const freezeEntries = [];
  const ledger = [];
  const executionByFixture = {};
  const leakExtraRoots = [];
  const nonceRegistryPath =
    source === "proxy" && packId === "TH-001C" && attestMode === "live"
      ? path.join(outRoot, "nonce_registry.jsonl")
      : null;
  const seenNonces = new Set();
  let lastAdmittedNonce = null;

  for (const f of fixtures) {
    let compilation;
    let sourceEnvelope = null;
    let toctouPaths = null;
    let binding_lane_id = null;
    let expiry_ts = null;
    let attestation_nonce = null;
    let attestation_nonce_candidate = null;
    let ratification_token_hashes = [];
    let ratification_approvers = [];
    let ratification_token_count = 0;
    let skill_install_stub_receipt_hash_sha256 = null;
    let execution_permit_sha256 = null;
    let execution_permit_validated = null;
    let execution_permit_validation_code = null;
    let file_receipt_hash_sha256 = null;
    let side_effect_detected = null;
    let pre_state_hash_sha256 = null;
    let post_state_hash_sha256 = null;
    let diff_sha256 = null;
    let diff_stats = null;
    let diff_preview_hash_sha256 = null;
    let diff_preview_written = false;
    let git_branch = null;
    let git_base_branch = null;
    let git_diff_sha256 = null;
    let git_diff_preview_hash_sha256 = null;
    let git_diff_unified = null;
    let git_commit_hash = null;
    let git_changed_files = null;
    let git_receipt_hash_sha256 = null;
    let git_ratification_token_hash_sha256 = null;
    let git_branch_ref_before = null;
    let post_surface = null;
    let post_payload_sha256 = null;
    let post_source_commit_hash = null;
    let post_source_receipt_hash_sha256 = null;
    let post_ratification_token_hash_sha256 = null;
    let post_stub_receipt_hash_sha256 = null;
    let publish_draft_kind = null;
    let publish_content_sha256 = null;
    let publish_draft_path = null;
    let egress_canonical_target = null;
    let egress_protocol = null;
    let egress_zone = null;
    let egress_reason_code = null;
    let egress_target_input = null;
    let isPublishDraftCommit = false;
    let draft_commit_receipt_hash_sha256 = null;
    let draft_commit_git_reason_code = null;
    let draft_commit_git_commit_hash = null;

    if (source === "proxy") {
      if (packId !== "TH-001C") {
        throw new Error(`--source proxy is only supported for TH-001C (got ${packId})`);
      }

      const fixtureOut = path.join(outRoot, "fixtures", f.fixture_id);
      fs.mkdirSync(fixtureOut, { recursive: true });

      const outDirRel = path.relative(repoRoot, fixtureOut);
      writeEnvelopeViaProxy({ repoRoot, fixturePath: f.intent_path, outDirRel });

      const envelopePath = path.join(fixtureOut, "envelope.json");
      const envelopeRaw = fs.readFileSync(envelopePath, "utf8");
      assertNoAbsWindowsPathsInText(envelopeRaw, `${path.relative(repoRoot, envelopePath)}`);
      sourceEnvelope = JSON.parse(envelopeRaw);

      const envLane = typeof sourceEnvelope?.lane_id === "string" ? sourceEnvelope.lane_id : null;
      const bindLane =
        typeof sourceEnvelope?.args?.bind_lane_id === "string" ? sourceEnvelope.args.bind_lane_id : envLane;
      binding_lane_id = bindLane ?? envLane ?? "proxy";
      expiry_ts = typeof sourceEnvelope?.args?.expiry_ts === "string" ? sourceEnvelope.args.expiry_ts : null;

      const intent = normalizeEnvelopeToIntent({ repoRoot, envelope: sourceEnvelope });
      const map = loadToolSurfaceMap(repoRoot);
      compilation = compileIntent({ intent, toolSurfaceMap: map });
    } else {
      const full = path.resolve(repoRoot, f.intent_path);
      const raw = fs.readFileSync(full, "utf8");
      assertNoAbsWindowsPathsInText(raw, `${path.relative(repoRoot, full)}`);
      const parsed = JSON.parse(raw);

      if (parsed && typeof parsed === "object" && parsed.schema_id === "EGL.INTENT") {
        compilation = compileIntentFromFile({ repoRoot, intentPath: f.intent_path });
      } else if (parsed && typeof parsed === "object" && typeof parsed.tool === "string") {
        const envelope = buildEnvelopeFromToolCall({
          repoRoot,
          fixture_id: f.fixture_id,
          tool_call: parsed,
        });
        const intent = normalizeEnvelopeToIntent({ repoRoot, envelope });
        const map = loadToolSurfaceMap(repoRoot);
        compilation = compileIntent({ intent, toolSurfaceMap: map });
       } else {
         throw new Error(`Unsupported fixture format at ${f.intent_path}`);
       }
     }

    // Proxy-only binding fields used by later enforcement and (for skill.install) HITL token validation.
    if (source === "proxy" && packId === "TH-001C" && compilation?.status === "OK") {
      const force_nonce = sourceEnvelope?.args?.force_nonce;
      attestation_nonce_candidate = bindingNonce({
        attestMode,
        intent_hash: compilation.hashes?.intent ?? null,
        force_nonce,
        last_nonce: lastAdmittedNonce,
      });

      compilation.meta = compilation.meta && typeof compilation.meta === "object" ? compilation.meta : {};
      compilation.meta.fixture_id = f.fixture_id;
      compilation.meta.binding_lane_id = binding_lane_id;
      compilation.meta.expiry_ts = expiry_ts;
      compilation.meta.attestation_nonce_candidate = attestation_nonce_candidate;
      compilation.meta.now_iso = nowIso;

      compilation.meta.binding = lawBinding
        ? {
            law_bundle_sha256: lawBinding.law_bundle_sha256,
            policy_bundle_sha256: lawBinding.policy_bundle_sha256,
            authority_profiles_sha256: lawBinding.authority_profiles_sha256,
            tool_surface_map_sha256: lawBinding.tool_surface_map_sha256,
          }
        : null;

      const expected = sourceEnvelope?.binding?.expected_law_bundle_sha256 ?? null;
      compilation.meta.expected_law_bundle_sha256 = typeof expected === "string" ? expected : null;

      if (sourceEnvelope?.tool_name === "skill.install" && compilation.meta.skill_install) {
        const req = sourceEnvelope?.args?.skill_install_request ?? {};
        const rawList = Array.isArray(req?.ratification_tokens)
          ? req.ratification_tokens
          : req?.ratification_token
            ? [req.ratification_token]
            : [];

        const tokens = rawList.filter((t) => t && typeof t === "object");
        ratification_token_count = tokens.length;

        const pairs = tokens
          .map((t) => ({
            hash: typeof t.token_sha256 === "string" ? t.token_sha256 : "",
            approver: typeof t.approver_id === "string" ? t.approver_id : "",
          }))
          .filter((p) => p.hash.length > 0 || p.approver.length > 0);

        pairs.sort((a, b) => {
          if (a.approver !== b.approver) return a.approver.localeCompare(b.approver);
          return a.hash.localeCompare(b.hash);
        });

        ratification_token_hashes = pairs.map((p) => p.hash).filter(Boolean);
        ratification_approvers = pairs.map((p) => p.approver).filter(Boolean);

        compilation.meta.skill_install = {
          ...compilation.meta.skill_install,
          ratification_tokens: tokens,
          ratification_token_hashes,
          ratification_approvers,
          ratification_token_count,
        };
      }
    }

    const aar = adaptCompilationToAAR(compilation);

    // Never persist raw ratification tokens in IO artifacts.
    if (compilation?.meta?.skill_install && typeof compilation.meta.skill_install === "object") {
      delete compilation.meta.skill_install.ratification_tokens;
      delete compilation.meta.skill_install.ratification_token;
    }

    const fixtureOut = path.join(outRoot, "fixtures", f.fixture_id);
    fs.mkdirSync(fixtureOut, { recursive: true });

    // Live-only TOCTOU fixture setup must happen before the initial attestation snapshot.
    if (
      source === "proxy" &&
      packId === "TH-001C" &&
      attestMode === "live" &&
      f.fixture_id === "toctou_symlink_swap" &&
      compilation?.plan?.actions?.[0]?.kind === "file"
    ) {
      toctouPaths = ensureToctouTemp({ repoRoot });
      leakExtraRoots.push(toctouPaths.dir);
      writeCanonicalJSON(path.join(fixtureOut, "toctou.paths.json"), {
        schema_id: "EGL.TOCTOU_PATHS",
        version: "0.1.0",
        target_path: toctouPaths.targetRel,
      });
    }

    // Attestation (written before execution for live mode).
    let attestationBundle = null;
    if (aar.status === "ok") {
      if (attestMode === "live") {
        attestationBundle = liveAttestationBundle({ plan: compilation.plan });
        writeCanonicalJSON(path.join(fixtureOut, "attestation.json"), attestationBundle);
      } else {
        attestationBundle = attest({ aar });
        writeCanonicalJSON(path.join(fixtureOut, "attestation.json"), attestationBundle);
      }
    }

    let outcome = finalOutcome({ compilation, aar });

    // Policy version binding enforcement (proxy path only): refuse if fixture expects a different law bundle hash.
    if (source === "proxy" && packId === "TH-001C") {
      const expected = compilation?.meta?.expected_law_bundle_sha256 ?? null;
      const actual = compilation?.meta?.binding?.law_bundle_sha256 ?? null;
      if (typeof expected === "string" && expected.length > 0 && typeof actual === "string" && actual.length > 0) {
        if (expected !== actual) {
          outcome = { admitted: false, reason_code: "POLICY_VERSION_MISMATCH", refusal_status: "REFUSE_HARD" };
        }
      }
    }

    // Lane binding + expiry enforcement (proxy path only).
    if (source === "proxy" && packId === "TH-001C" && outcome.admitted) {
      const envLane = typeof sourceEnvelope?.lane_id === "string" ? sourceEnvelope.lane_id : null;
      if (envLane && binding_lane_id && envLane !== binding_lane_id) {
        outcome = { admitted: false, reason_code: "LANE_MISMATCH", refusal_status: "REFUSE_HARD" };
      }

      if (expiry_ts) {
        const expMs = Date.parse(expiry_ts);
        if (!Number.isNaN(expMs) && nowMs > expMs) {
          outcome = { admitted: false, reason_code: "PLAN_EXPIRED", refusal_status: "REFUSE_HARD" };
        }
      }
    }

    // TOCTOU defense (live proxy path only): re-attest immediately before execution.
    let toctouSwapInfo = null;
    if (
      source === "proxy" &&
      packId === "TH-001C" &&
      attestMode === "live" &&
      outcome.admitted &&
      compilation?.plan?.actions?.[0]?.kind === "file"
    ) {
      const fileEntry = Array.isArray(attestationBundle?.entries)
        ? attestationBundle.entries.find((e) => e && e.schema_id === "MVM.FILE")
        : null;

      if (f.fixture_id === "toctou_symlink_swap") {
        const paths = toctouPaths ?? ensureToctouTemp({ repoRoot });
        toctouSwapInfo = simulateToctouSwap({ repoRoot, paths });
        writeCanonicalJSON(path.join(fixtureOut, "toctou.swap.json"), {
          schema_id: "EGL.TOCTOU_SWAP",
          version: "0.1.0",
          method: toctouSwapInfo.method,
          target_path: toctouSwapInfo.targetRel,
        });
      }

      const action = compilation.plan.actions[0];
      const re = live.attest_file_live({
        repoRoot,
        op: String(action?.file?.op ?? "unknown"),
        input_path: String(action?.file?.path ?? ""),
      });
      writeCanonicalJSON(path.join(fixtureOut, "attestation.recheck.json"), re);

      if (!attestComparableEqual(fileEntry, re)) {
        outcome = { admitted: false, reason_code: "TOCTOU_DETECTED", refusal_status: "REFUSE_HARD" };
      }
    }

    if (source === "proxy" && packId === "TH-001C") {
      const nonce = attestation_nonce_candidate;
      const action0 = compilation?.plan?.actions?.[0] ?? null;
      const isFileAction = Boolean(action0 && action0.kind === "file" && action0.file && typeof action0.file === "object");
      const isNetAction = Boolean(action0 && action0.kind === "net" && action0.net && typeof action0.net === "object");
      const fileRelPath = isFileAction ? String(action0.file.path ?? "") : null;
      const fileOp = isFileAction ? String(action0.file.op ?? "") : null;
      const tool_surface_id = String(action0?.tool_surface_id ?? "");
      const isPublishDraft = Boolean(outcome.admitted && tool_surface_id === "publish.draft.create");
      isPublishDraftCommit = Boolean(outcome.admitted && tool_surface_id === "publish.draft.commit");
      const isGitPipeline = Boolean(outcome.admitted && tool_surface_id === "git.pipeline_commit_from_diff");
      const isPublishPostTool = Boolean(
        sourceEnvelope?.tool_name === "publish.post.x" || sourceEnvelope?.tool_name === "publish.post.x_thread",
      );
      const isPublishPostSurface = Boolean(
        tool_surface_id === "publish.post.x" || tool_surface_id === "publish.post.x_thread",
      );
      const isBrowserNavigate = Boolean(isNetAction && tool_surface_id === "browser.navigate");
      const isCodePatchApply = Boolean(isFileAction && fileOp === "write" && tool_surface_id === "code.patch.apply");
      const isCodeTestRun = Boolean(tool_surface_id === "code.test.run");
      const isCodeDepsFetch = Boolean(tool_surface_id === "code.deps.fetch");
      let isWriteAttempt =
        Boolean(outcome.admitted) &&
        Boolean(isFileAction) &&
        fileOp === "write" &&
        sourceEnvelope?.tool_name !== "skill.install" &&
        typeof fileRelPath === "string" &&
          fileRelPath.length > 0;

      if (isPublishDraft || isPublishDraftCommit) {
        publish_draft_kind = typeof sourceEnvelope?.args?.draft_kind === "string" ? sourceEnvelope.args.draft_kind : null;
        publish_content_sha256 =
          typeof sourceEnvelope?.args?.content_sha256 === "string" ? sourceEnvelope.args.content_sha256 : null;
        publish_draft_path = fileRelPath;

        if (fileRelPath && !String(fileRelPath).startsWith("sandbox/_publish_drafts/")) {
          outcome = { admitted: false, reason_code: "PERMIT_SCOPE_VIOLATION", refusal_status: "REFUSE_HARD" };
        }

        // Step-19: publish draft requires a permit to even preview (no preview without permit).
        const hasPermit = Boolean(sourceEnvelope?.args?.execution_permit);
        if (!hasPermit) {
          outcome = { admitted: false, reason_code: "PERMIT_REQUIRED", refusal_status: "REFUSE_HARD" };
        }
      }

      if (isPublishPostTool) {
        post_surface = String(sourceEnvelope?.args?.post_kind ?? "") === "x_thread" ? "x_thread" : "x";
        post_payload_sha256 =
          typeof sourceEnvelope?.args?.payload_sha256 === "string" ? sourceEnvelope.args.payload_sha256 : null;
        post_source_commit_hash =
          typeof sourceEnvelope?.args?.source_commit_hash === "string" ? sourceEnvelope.args.source_commit_hash : null;
        post_source_receipt_hash_sha256 =
          typeof sourceEnvelope?.args?.source_receipt_hash_sha256 === "string"
            ? sourceEnvelope.args.source_receipt_hash_sha256
            : null;

        const hasPermit = Boolean(sourceEnvelope?.args?.execution_permit);
        if (!hasPermit) {
          outcome = { admitted: false, reason_code: "PERMIT_REQUIRED", refusal_status: "REFUSE_HARD" };
        }
      }

      if (isBrowserNavigate) {
        egress_target_input = String(action0?.net?.url ?? "");
        const hasPermit = Boolean(sourceEnvelope?.args?.execution_permit);
        if (!hasPermit) {
          outcome = { admitted: false, reason_code: "PERMIT_REQUIRED", refusal_status: "REFUSE_HARD" };
        }
      }

      if (isCodeTestRun) {
        const hasPermit = Boolean(sourceEnvelope?.args?.execution_permit);
        if (!hasPermit) {
          outcome = { admitted: false, reason_code: "PERMIT_REQUIRED", refusal_status: "REFUSE_HARD" };
        } else if (attestMode === "live" && execMode === "live") {
          const cmd = typeof sourceEnvelope?.args?.cmd === "string" ? sourceEnvelope.args.cmd : "";
          const safeCmd = String(cmd ?? "").trim();
          if (safeCmd !== "node -v" && safeCmd !== "node --version") {
            outcome = { admitted: false, reason_code: "EXEC_CMD_NOT_ALLOWED", refusal_status: "REFUSE_HARD" };
          }
        }
      }

      if (isCodeDepsFetch) {
        const hasPermit = Boolean(sourceEnvelope?.args?.execution_permit);
        if (!hasPermit) {
          outcome = { admitted: false, reason_code: "PERMIT_REQUIRED", refusal_status: "REFUSE_HARD" };
        } else {
          const lockfile_path =
            typeof sourceEnvelope?.args?.lockfile_path === "string" ? sourceEnvelope.args.lockfile_path : "";
          if (!lockfile_path || lockfile_path === "OUTSIDE_REPO") {
            outcome = { admitted: false, reason_code: "MISSING_LOCKFILE", refusal_status: "REFUSE_HARD" };
          } else {
            const abs = path.resolve(repoRoot, lockfile_path);
            const root = path.resolve(repoRoot);
            const exists = abs.startsWith(root) && fs.existsSync(abs) && fs.statSync(abs).isFile();
            if (!exists) {
              outcome = { admitted: false, reason_code: "MISSING_LOCKFILE", refusal_status: "REFUSE_HARD" };
            }
          }
        }
      }

      // If the above gates changed admission status, re-evaluate preview eligibility.
      isWriteAttempt =
        Boolean(outcome.admitted) &&
        Boolean(isFileAction) &&
        fileOp === "write" &&
        sourceEnvelope?.tool_name !== "skill.install" &&
        typeof fileRelPath === "string" &&
          fileRelPath.length > 0;

      // Step-23: code.patch.apply always emits diff.preview.json (non-mutating), even when refused.
      const isPatchPreviewAttempt =
        Boolean(isCodePatchApply) &&
        Boolean(isFileAction) &&
        typeof fileRelPath === "string" &&
        fileRelPath.length > 0 &&
        fileRelPath !== "OUTSIDE_REPO";

      pre_state_hash_sha256 =
        isFileAction && typeof fileRelPath === "string" && fileRelPath.length > 0
          ? file_state_sha256({ repoRoot, relPath: fileRelPath })
          : null;

      // Step-17: diff preview is generated for all admitted write attempts (non-mutating).
      let diff_unified = null;
      let diff_bytes = 0;
      if (isWriteAttempt || isPatchPreviewAttempt) {
        const abs = path.resolve(repoRoot, fileRelPath);
        const rel = path.relative(repoRoot, abs);
        if (rel.startsWith("..")) {
          outcome = { admitted: false, reason_code: "PERMIT_SCOPE_VIOLATION", refusal_status: "REFUSE_HARD" };
        } else {
          const before_text = fs.existsSync(abs) ? fs.readFileSync(abs, "utf8") : "";
          const after_text = deriveWriteAfterText({ relPath: fileRelPath, envelopeArgs: sourceEnvelope?.args ?? {} });
          const d = unifiedDiff({ relPath: fileRelPath, before_text, after_text });
          diff_unified = d.diff_unified;
          diff_sha256 = d.diff_sha256;
          diff_stats = d.diff_stats;
          diff_bytes = Buffer.from(d.diff_unified, "utf8").byteLength;

          const preview = {
            path: fileRelPath,
            diff_sha256: d.diff_sha256,
            diff_stats: d.diff_stats,
            diff_unified: d.diff_unified,
          };
          const { sha256 } = writeCanonicalJSON(path.join(fixtureOut, "diff.preview.json"), preview);
          diff_preview_hash_sha256 = sha256;
          diff_preview_written = true;
        }
      }

      // Step-18: git pipeline references a previously previewed diff (still non-mutating until executed).
      if (isGitPipeline) {
        git_branch = String(sourceEnvelope?.args?.git_branch ?? "");
        git_base_branch = String(sourceEnvelope?.args?.base_branch ?? "main");
        const src = String(sourceEnvelope?.args?.source_diff_fixture_id ?? "");
        const previewPath = path.join(outRoot, "fixtures", src, "diff.preview.json");
        if (!src || !fs.existsSync(previewPath)) {
          outcome = { admitted: false, reason_code: "GIT_DIFF_REFERENCE_MISSING", refusal_status: "REFUSE_HARD" };
        } else {
          const p = readJSON(previewPath);
          git_diff_sha256 = typeof p?.diff_sha256 === "string" ? p.diff_sha256 : null;
          git_diff_unified = typeof p?.diff_unified === "string" ? p.diff_unified : null;
          const raw = fs.readFileSync(previewPath, "utf8");
          git_diff_preview_hash_sha256 = sha256HexFromUtf8Bytes(Buffer.from(raw, "utf8"));
        }

        git_branch_ref_before = gitBranchRefExists({ repoRoot, branch: git_branch });

        const t = sourceEnvelope?.args?.ratification_token ?? null;
        if (t && typeof t === "object") {
          const h = git_ratification_token_sha256(t);
          git_ratification_token_hash_sha256 = typeof h === "string" && h.length > 0 ? `sha256:${h}` : null;
        }
      }

      // Permit validation (sandbox-only real execution): enforced for admitted file ops and governed process surfaces.
      const permit = sourceEnvelope?.args?.execution_permit ?? null;
      const permit_sha256 =
        permit && typeof permit === "object" ? compute_permit_sha256(permit) : null;
      let permitValidation = { ok: null, code: "PERMIT_NOT_REQUIRED", reason: "not required" };
      execution_permit_sha256 = permit_sha256;

      if (
        (outcome.admitted || isPublishPostSurface || isPatchPreviewAttempt || isCodeTestRun || isCodeDepsFetch) &&
        sourceEnvelope?.tool_name !== "skill.install" &&
        (isFileAction || isGitPipeline || isPublishPostSurface || isBrowserNavigate || isCodeTestRun || isCodeDepsFetch)
      ) {
        const expected = {
          lane_id: binding_lane_id,
          attestation_nonce: nonce,
          law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? null,
          plan_hash_sha3_512: compilation.hashes?.plan ?? null,
          intent_hash_sha3_512: compilation.hashes?.intent ?? null,
        };

        permitValidation = validate_execution_permit({ permit, expected, now_iso: nowIso });

        if (permitValidation.ok) {
          if (isFileAction) {
            const fsScope =
              permit?.scope?.filesystem && typeof permit.scope.filesystem === "object"
                ? permit.scope.filesystem
                : {};
            const read_roots = Array.isArray(fsScope.read_roots) ? fsScope.read_roots : [];
            const write_roots = Array.isArray(fsScope.write_roots) ? fsScope.write_roots : [];
            const deny_paths = Array.isArray(fsScope.deny_paths) ? fsScope.deny_paths : [];

            if (fileRelPath && pathWithinRoots({ relPath: fileRelPath, roots: deny_paths })) {
              permitValidation = { ok: false, code: "PERMIT_SCOPE_VIOLATION", reason: "path denied by permit" };
            } else if (
              fileOp === "read" &&
              fileRelPath &&
              !pathWithinRoots({ relPath: fileRelPath, roots: read_roots })
            ) {
              permitValidation = {
                ok: false,
                code: "PERMIT_SCOPE_VIOLATION",
                reason: "path not within permit read_roots",
              };
            } else if (
              fileOp === "write" &&
              fileRelPath &&
              !pathWithinRoots({ relPath: fileRelPath, roots: write_roots })
            ) {
              permitValidation = {
                ok: false,
                code: "PERMIT_SCOPE_VIOLATION",
                reason: "path not within permit write_roots",
              };
            }
          }

          // Step-17: permit-scoped patch application limits (write only).
          if (permitValidation.ok && isWriteAttempt && diff_preview_written) {
            const scope = permit?.scope && typeof permit.scope === "object" ? permit.scope : {};
            const allowed_ops = Array.isArray(scope.allowed_ops) ? scope.allowed_ops.map(String) : null;
            if (!allowed_ops || !allowed_ops.includes("file.write")) {
              permitValidation = {
                ok: false,
                code: "PERMIT_OP_NOT_ALLOWED",
                reason: "permit.allowed_ops must include file.write to apply patch",
              };
            } else {
              const max_diff_bytes = Number(scope.max_diff_bytes);
              const max_added_lines = Number(scope.max_added_lines);
              const max_removed_lines = Number(scope.max_removed_lines);

              if (
                !Number.isFinite(max_diff_bytes) ||
                !Number.isFinite(max_added_lines) ||
                !Number.isFinite(max_removed_lines)
              ) {
                permitValidation = {
                  ok: false,
                  code: "PERMIT_DIFF_SCOPE_VIOLATION",
                  reason: "permit missing diff threshold fields",
                };
              } else if (diff_bytes > max_diff_bytes) {
                permitValidation = {
                  ok: false,
                  code: "DIFF_TOO_LARGE",
                  reason: "diff exceeds max_diff_bytes",
                };
              } else if (
                Number(diff_stats?.added_lines ?? 0) > max_added_lines ||
                Number(diff_stats?.removed_lines ?? 0) > max_removed_lines
              ) {
                permitValidation = {
                  ok: false,
                  code: "DIFF_LINE_LIMIT_EXCEEDED",
                  reason: "diff exceeds line thresholds",
                };
              }
            }
          }

          // Step-21: publish.post.* requires explicit publish scope limits (payload size + surface + commit binding).
          if (permitValidation.ok && isPublishPostTool) {
            const payloadText =
              typeof sourceEnvelope?.args?.payload_text === "string" ? sourceEnvelope.args.payload_text : "";
            const payloadBytes = Buffer.from(payloadText, "utf8").byteLength;
            const commitBinding = Boolean(
              (typeof post_source_commit_hash === "string" && post_source_commit_hash.length > 0) ||
                (typeof post_source_receipt_hash_sha256 === "string" && post_source_receipt_hash_sha256.length > 0),
            );
            const v = validate_publish_scope({
              permit,
              surface: post_surface === "x_thread" ? "x_thread" : "x",
              payload_bytes: payloadBytes,
              commit_binding: commitBinding,
            });
            if (!v.ok) {
              permitValidation = {
                ok: false,
                code: v.code ?? "PUBLISH_SCOPE_VIOLATION",
                reason: v.reason ?? "publish scope invalid",
              };
            }
          }

          // Step-22: browser.navigate requires explicit egress scope.
          if (permitValidation.ok && isBrowserNavigate) {
            const v = validate_egress_scope({ permit });
            if (!v.ok) {
              permitValidation = {
                ok: false,
                code: v.code ?? "EGRESS_SCOPE_VIOLATION",
                reason: v.reason ?? "egress scope invalid",
              };
            }
          }

          // Step-23: code.test.run requires explicit exec scope (profile + command allowlist).
          if (permitValidation.ok && isCodeTestRun) {
            const env_profile =
              typeof sourceEnvelope?.args?.env_profile === "string" ? sourceEnvelope.args.env_profile : "";
            const cmd = typeof sourceEnvelope?.args?.cmd === "string" ? sourceEnvelope.args.cmd : "";
            const v = validate_exec_scope({ permit, env_profile, cmd });
            if (!v.ok) {
              permitValidation = {
                ok: false,
                code: v.code ?? "PERMIT_SCOPE_VIOLATION",
                reason: v.reason ?? "exec scope invalid",
              };
            }
          }

          // Step-24: code.deps.fetch requires explicit deps scope (profile + command allowlist + lockfile roots).
          if (permitValidation.ok && isCodeDepsFetch) {
            const env_profile =
              typeof sourceEnvelope?.args?.env_profile === "string" ? sourceEnvelope.args.env_profile : "";
            const cmd = typeof sourceEnvelope?.args?.cmd === "string" ? sourceEnvelope.args.cmd : "";
            const lockfile_path =
              typeof sourceEnvelope?.args?.lockfile_path === "string" ? sourceEnvelope.args.lockfile_path : "";
            const v = validate_deps_scope({ permit, env_profile, cmd, lockfile_path });
            if (!v.ok) {
              permitValidation = {
                ok: false,
                code: v.code ?? "PERMIT_SCOPE_VIOLATION",
                reason: v.reason ?? "deps scope invalid",
              };
            }
          }

          // Step-18/20: git pipeline scope checks (validated when git will be requested).
          if (permitValidation.ok && (isGitPipeline || isPublishDraftCommit)) {
            const base_branch = String(sourceEnvelope?.args?.base_branch ?? "main");
            const git_branch = String(sourceEnvelope?.args?.git_branch ?? "");
            const v = validate_git_scope({
              permit,
              expected_base_branch: "main",
              expected_branch: git_branch,
            });
            if (!v.ok) {
              permitValidation = { ok: false, code: v.code ?? "PERMIT_SCOPE_VIOLATION", reason: v.reason ?? "git scope invalid" };
            }
          }
        }

        if (!permitValidation.ok) {
          const code = permitValidation.code ?? "INVALID_PERMIT";
          outcome = { admitted: false, reason_code: code, refusal_status: "REFUSE_HARD" };
        }
      }

      // Step-21: publish.post.* is always HITL-gated. In mock it deterministically defers (no stub receipt).
      if (isPublishPostTool && isPublishPostSurface && outcome.refusal_status !== "REFUSE_HARD") {
        const token = sourceEnvelope?.args?.ratification_token ?? null;
        if (token && typeof token === "object") {
          const h = publish_post_ratification_token_sha256(token);
          post_ratification_token_hash_sha256 = typeof h === "string" && h.length > 0 ? `sha256:${h}` : null;
        }

        if (!token) {
          outcome = { admitted: false, reason_code: "HITL_REQUIRED_PUBLISH_POST", refusal_status: "DEFER_HITL" };
        } else {
          const expectedToken = {
            law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? "",
            plan_hash: compilation.hashes?.plan ?? "",
            intent_hash: compilation.hashes?.intent ?? "",
            lane_id: binding_lane_id ?? "",
            attestation_nonce: nonce ?? "",
            surface: post_surface === "x_thread" ? "x_thread" : "x",
            payload_sha256: post_payload_sha256 ?? "",
            source_commit_hash: post_source_commit_hash ?? "",
            source_receipt_hash_sha256: post_source_receipt_hash_sha256 ?? "",
          };
          const verdict = validate_publish_post_ratification_token({ token, expected: expectedToken, now_iso: nowIso });
          if (!verdict.ok) {
            outcome = {
              admitted: false,
              reason_code: verdict.code ?? "INVALID_HITL_TOKEN",
              refusal_status: "REFUSE_HARD",
            };
          } else if (attestMode !== "live") {
            outcome = { admitted: false, reason_code: "HITL_REQUIRED_PUBLISH_POST", refusal_status: "DEFER_HITL" };
          } else {
            outcome = { ...outcome, admitted: true, reason_code: "HITL_TOKEN_ACCEPTED", refusal_status: null };
          }
        }
      }

      // Step-18: git commit requires HITL token and is live-only (no side effects in mock).
      if (isGitPipeline && outcome.admitted) {
        if (attestMode !== "live" || gitMode !== "live") {
          outcome = { admitted: false, reason_code: "HITL_REQUIRED_GIT_COMMIT", refusal_status: "DEFER_HITL" };
        } else {
          const token = sourceEnvelope?.args?.ratification_token ?? null;
          if (!token) {
            outcome = { admitted: false, reason_code: "HITL_REQUIRED_GIT_COMMIT", refusal_status: "DEFER_HITL" };
          } else {
            const expectedToken = {
              law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? "",
              plan_hash: compilation.hashes?.plan ?? "",
              intent_hash: compilation.hashes?.intent ?? "",
              lane_id: binding_lane_id ?? "",
              attestation_nonce: nonce ?? "",
              git_branch: git_branch ?? "",
              diff_sha256: git_diff_sha256 ?? "",
            };
            const verdict = validate_git_ratification_token({ token, expected: expectedToken, now_iso: nowIso });
            if (!verdict.ok) {
              outcome = { admitted: false, reason_code: verdict.code ?? "INVALID_GIT_HITL_TOKEN", refusal_status: "REFUSE_HARD" };
            }
          }
        }
      }

      // Step-20: publish.draft.commit chains a draft write (this fixture) then a governed git commit (live-only).
      if (isPublishDraftCommit) {
        git_branch = String(sourceEnvelope?.args?.git_branch ?? "");
        git_base_branch = String(sourceEnvelope?.args?.base_branch ?? "main");
        git_branch_ref_before = gitBranchRefExists({ repoRoot, branch: git_branch });

        const t = sourceEnvelope?.args?.ratification_token ?? null;
        if (t && typeof t === "object") {
          const h = git_ratification_token_sha256(t);
          git_ratification_token_hash_sha256 = typeof h === "string" && h.length > 0 ? `sha256:${h}` : null;
        }
      }

      execution_permit_validated = permitValidation.ok;
      execution_permit_validation_code = permitValidation.code ?? null;

      // Write permit artifacts for every fixture (deterministic, repo-relative only).
      writeCanonicalJSON(path.join(fixtureOut, "permit.hash.json"), {
        schema_id: "EGL.EXECUTION_PERMIT_HASH",
        version: "0.1.0",
        execution_permit_sha256: permit_sha256,
      });
      writeCanonicalJSON(path.join(fixtureOut, "permit.validation.json"), {
        schema_id: "EGL.EXECUTION_PERMIT_VALIDATION",
        version: "0.1.0",
        ok: permitValidation.ok,
        code: permitValidation.code ?? null,
        reason: permitValidation.reason ?? null,
        execution_permit_sha256: permit_sha256,
        ...(diff_preview_written
          ? {
              diff_sha256,
              diff_preview_hash_sha256,
              diff_stats,
            }
          : {}),
        ...(isGitPipeline
          ? {
              git_branch,
              git_diff_sha256,
              git_diff_preview_hash_sha256,
              ratification_token_hash_sha256: git_ratification_token_hash_sha256,
            }
          : {}),
        ...(outcome.reason_code && String(outcome.reason_code).startsWith("PERMIT_")
          ? {
              expected: {
                lane_id: binding_lane_id,
                attestation_nonce: nonce,
                law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? null,
                plan_hash_sha3_512: compilation.hashes?.plan ?? null,
                intent_hash_sha3_512: compilation.hashes?.intent ?? null,
              },
            }
          : {}),
      });

      // Step-22: network egress gate (browser.navigate) is evidence-first and permit-bound (no DNS, stubbed execution).
      if (isBrowserNavigate) {
        const permitEgress =
          permit?.scope?.egress && typeof permit.scope.egress === "object" ? permit.scope.egress : null;

        const verdict =
          permitValidation.ok === true
            ? evaluate_egress({
                target: egress_target_input,
                protocol: null,
                permit_scope: permitEgress,
              })
            : evaluate_egress({
                target: egress_target_input,
                protocol: null,
                permit_scope: null,
              });

        egress_canonical_target = verdict.canonical_target ?? null;
        egress_protocol = verdict.protocol ?? null;
        egress_zone = verdict.zone ?? null;

        if (!sourceEnvelope?.args?.execution_permit) {
          egress_reason_code = "PERMIT_REQUIRED";
        } else if (permitValidation.ok !== true) {
          egress_reason_code = outcome.reason_code ?? permitValidation.code ?? "INVALID_PERMIT";
        } else {
          egress_reason_code = verdict.reason_code ?? null;
        }

        // If the plan is otherwise admitted, the egress gate can still refuse hard.
        if (outcome.admitted && egress_reason_code) {
          outcome = { admitted: false, reason_code: egress_reason_code, refusal_status: "REFUSE_HARD" };
        }

        writeCanonicalJSON(path.join(fixtureOut, "egress.check.json"), {
          schema_id: "EGL.EGRESS_CHECK",
          version: "0.1.0",
          target_input: egress_target_input,
          canonical_target: egress_canonical_target,
          protocol: egress_protocol,
          zone: egress_zone,
          permit_egress_allow: permitEgress ? (permitEgress.allow === true) : null,
          allowlist: Array.isArray(verdict.allowlist) ? verdict.allowlist : [],
          status: egress_reason_code ? "refused" : "ok",
          reason_code: egress_reason_code,
        });
      }

      if (isCodeDepsFetch) {
        const cmd = typeof sourceEnvelope?.args?.cmd === "string" ? sourceEnvelope.args.cmd : "";
        const requiredTargets = cmd.startsWith("npm ") ? ["registry.npmjs.org"] : [];

        const permitEgress =
          permit?.scope?.egress && typeof permit.scope.egress === "object" ? permit.scope.egress : null;

        const checks = requiredTargets.map((t) => {
          const verdict =
            permitValidation.ok === true
              ? evaluate_egress({ target: t, protocol: "HTTPS", permit_scope: permitEgress })
              : evaluate_egress({ target: t, protocol: "HTTPS", permit_scope: null });
          return {
            target_input: t,
            canonical_target: verdict.canonical_target ?? null,
            protocol: verdict.protocol ?? null,
            zone: verdict.zone ?? null,
            status: verdict.reason_code ? "refused" : "ok",
            reason_code: verdict.reason_code ?? null,
          };
        });

        let deps_egress_reason_code = null;
        if (!sourceEnvelope?.args?.execution_permit) {
          deps_egress_reason_code = "PERMIT_REQUIRED";
        } else if (permitValidation.ok !== true) {
          deps_egress_reason_code = outcome.reason_code ?? permitValidation.code ?? "INVALID_PERMIT";
        } else {
          const firstRefused = checks.find((c) => c.reason_code);
          deps_egress_reason_code = firstRefused ? firstRefused.reason_code : null;
        }

        if (outcome.admitted && deps_egress_reason_code) {
          outcome = { admitted: false, reason_code: deps_egress_reason_code, refusal_status: "REFUSE_HARD" };
        }

        writeCanonicalJSON(path.join(fixtureOut, "deps.egress.check.json"), {
          schema_id: "EGL.EGRESS_CHECK_BUNDLE",
          version: "0.1.0",
          surface: "code.deps.fetch",
          permit_egress_allow: permitEgress ? (permitEgress.allow === true) : null,
          allowlist: Array.isArray(permitEgress?.allowlist) ? permitEgress.allowlist : [],
          status: deps_egress_reason_code ? "refused" : "ok",
          reason_code: deps_egress_reason_code,
          checks,
        });
      }

      // Live-only one-time nonce enforcement (replay blocking), checked before execution.
      if (attestMode === "live" && outcome.admitted) {
        if (!nonce || seenNonces.has(nonce)) {
          outcome = { admitted: false, reason_code: "NONCE_REPLAY", refusal_status: "REFUSE_HARD" };
        } else {
          seenNonces.add(nonce);
          fs.appendFileSync(
            nonceRegistryPath,
            stableStringify({
              nonce,
              intent_hash: compilation.hashes?.intent ?? null,
              fixture_id: f.fixture_id,
              lane_id: binding_lane_id ?? null,
              ts: nowIso,
            }) + "\n",
            "utf8",
          );
        }
      }

      attestation_nonce = outcome.admitted ? nonce : null;

      post_state_hash_sha256 = pre_state_hash_sha256;
      side_effect_detected = false;
      file_receipt_hash_sha256 = null;

      let wroteExecution = false;

      if (outcome.admitted) {
        if (isGitPipeline) {
          // Real git pipeline (live-only by gate above). No side effects occur unless admitted here.
          let gitExecution = git_execution_evidence({
            branch_created: false,
            patch_applied: false,
            staged: false,
            committed: false,
            new_branch: git_branch,
            base_branch: git_base_branch,
            reason_code: null,
          });

          try {
            const commit_message = String(
              sourceEnvelope?.args?.commit_message ?? `EGL git pipeline ${f.fixture_id}`,
            );

            const gr = git_pipeline_commit_from_diff({
              repoRoot,
              base_branch: git_base_branch ?? "main",
              new_branch: git_branch ?? "",
              diff_unified: git_diff_unified ?? "",
              commit_message,
            });

            git_commit_hash = gr.commit_hash;
            git_changed_files = gr.changed_files;

            gitExecution = git_execution_evidence({
              branch_created: gr.steps?.includes("branch_create"),
              patch_applied: gr.steps?.includes("apply_patch"),
              staged: gr.steps?.includes("stage"),
              committed: gr.steps?.includes("commit"),
              new_branch: git_branch,
              base_branch: git_base_branch,
              reason_code: null,
            });

            const receipt = stableGitReceipt({
              branch: git_branch,
              base_branch: git_base_branch,
              commit_hash: git_commit_hash,
              changed_files: git_changed_files,
              diff_sha256s: git_diff_sha256 ? [git_diff_sha256] : [],
              law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? null,
              plan_hash: compilation.hashes?.plan ?? null,
              intent_hash: compilation.hashes?.intent ?? null,
              permit_sha256: permit_sha256,
            });
            const { sha256 } = writeCanonicalJSON(path.join(fixtureOut, "git.receipt.json"), receipt);
            git_receipt_hash_sha256 = sha256;

            const result = {
              kind: "git_pipeline_result",
              commit_hash: git_commit_hash,
              changed_files: git_changed_files,
              git_receipt_hash_sha256: git_receipt_hash_sha256,
            };
            const resultPath = path.join(fixtureOut, "result.json");
            const { sha256: resultHashSha256 } = writeCanonicalJSON(resultPath, result);

            const execution = {
              executor_invoked: true,
              execution_kind: "git",
              attest_mode: attestMode,
              lane_id: binding_lane_id,
              expiry_ts,
              attestation_nonce,
              ...(compilation?.meta?.binding ? { binding: compilation.meta.binding } : {}),
              execution_permit_sha256: permit_sha256,
              permit_validated: true,
              permit_validation_code: permitValidation.code ?? null,
              pre_state_hash_sha256,
              post_state_hash_sha256,
              side_effect_detected,
              result_hash_sha256: resultHashSha256,
              file_receipt_hash_sha256: null,
            };
            writeCanonicalJSON(path.join(fixtureOut, "execution.json"), execution);
            executionByFixture[f.fixture_id] = execution;
            lastAdmittedNonce = nonce;
            wroteExecution = true;
          } catch (e) {
            // Live integration only: fail closed into refusal without further side effects.
            outcome = { admitted: false, reason_code: "GIT_EXEC_FAILED", refusal_status: "REFUSE_HARD" };
            gitExecution = git_execution_evidence({
              branch_created: false,
              patch_applied: false,
              staged: false,
              committed: false,
              new_branch: git_branch,
              base_branch: git_base_branch,
              reason_code: "GIT_EXEC_FAILED",
            });
          } finally {
            const branch_ref_after = gitBranchRefExists({ repoRoot, branch: git_branch });
            writeCanonicalJSON(path.join(fixtureOut, "git.execution.json"), {
              ...gitExecution,
              attest_mode: attestMode,
              git_mode: gitMode,
              branch_ref_before: git_branch_ref_before,
              branch_ref_after,
              diff_sha256: git_diff_sha256,
              diff_preview_hash_sha256: git_diff_preview_hash_sha256,
              ratification_token_hash_sha256: git_ratification_token_hash_sha256,
              git_receipt_hash_sha256,
              commit_hash: git_commit_hash,
              changed_files: git_changed_files,
            });
          }
        } else if (sourceEnvelope?.tool_name === "publish.post.x" || sourceEnvelope?.tool_name === "publish.post.x_thread") {
          // publish.post.* is a pure stub: no network, no API. It only emits a deterministic receipt when admitted in live.
          const receiptObj = post_stub_receipt({
            surface: post_surface === "x_thread" ? "x_thread" : "x",
            payload_sha256: post_payload_sha256,
            source_commit_hash: post_source_commit_hash,
            source_receipt_hash_sha256: post_source_receipt_hash_sha256,
            permit_sha256: permit_sha256,
            ratification_token_hash_sha256: post_ratification_token_hash_sha256,
            law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? null,
            plan_hash: compilation.hashes?.plan ?? null,
            intent_hash: compilation.hashes?.intent ?? null,
          });
          const { sha256 } = writeCanonicalJSON(path.join(fixtureOut, "post_stub_receipt.json"), receiptObj.receipt);
          post_stub_receipt_hash_sha256 = sha256;

          const result = {
            kind: "publish_post_stub_result",
            payload_sha256: post_payload_sha256,
            post_stub_receipt_hash_sha256: post_stub_receipt_hash_sha256,
          };
          const resultPath = path.join(fixtureOut, "result.json");
          const { sha256: resultHashSha256 } = writeCanonicalJSON(resultPath, result);

          const execution = {
            executor_invoked: true,
            execution_kind: "post_stub",
            attest_mode: attestMode,
            lane_id: binding_lane_id,
            expiry_ts,
            attestation_nonce,
            ...(compilation?.meta?.binding ? { binding: compilation.meta.binding } : {}),
            execution_permit_sha256: permit_sha256,
            permit_validated: true,
            permit_validation_code: permitValidation.code ?? null,
            pre_state_hash_sha256,
            post_state_hash_sha256,
            side_effect_detected,
            result_hash_sha256: resultHashSha256,
            file_receipt_hash_sha256: null,
          };
          writeCanonicalJSON(path.join(fixtureOut, "execution.json"), execution);
          executionByFixture[f.fixture_id] = execution;
          lastAdmittedNonce = nonce;
          wroteExecution = true;
        } else if (isNetAction && tool_surface_id === "browser.navigate") {
          // browser.navigate is stubbed: no sockets, no DNS, no fetch. Egress is gated earlier and evidenced via egress.check.json.
          const result = {
            kind: "browser_navigate_stub_result",
            canonical_target: egress_canonical_target,
            protocol: egress_protocol,
            zone: egress_zone,
          };
          const resultPath = path.join(fixtureOut, "result.json");
          const { sha256: resultHashSha256 } = writeCanonicalJSON(resultPath, result);

          const execution = {
            executor_invoked: true,
            execution_kind: "net_stub",
            attest_mode: attestMode,
            lane_id: binding_lane_id,
            expiry_ts,
            attestation_nonce,
            ...(compilation?.meta?.binding ? { binding: compilation.meta.binding } : {}),
            execution_permit_sha256: permit_sha256,
            permit_validated: true,
            permit_validation_code: permitValidation.code ?? null,
            pre_state_hash_sha256,
            post_state_hash_sha256,
            side_effect_detected,
            result_hash_sha256: resultHashSha256,
            file_receipt_hash_sha256: null,
          };
          writeCanonicalJSON(path.join(fixtureOut, "execution.json"), execution);
          executionByFixture[f.fixture_id] = execution;
          lastAdmittedNonce = nonce;
          wroteExecution = true;
        } else if (tool_surface_id === "code.test.run") {
          const cmd = typeof sourceEnvelope?.args?.cmd === "string" ? sourceEnvelope.args.cmd : "";
          const cwd = typeof sourceEnvelope?.args?.cwd === "string" ? sourceEnvelope.args.cwd : ".";
          const env_profile =
            typeof sourceEnvelope?.args?.env_profile === "string" ? sourceEnvelope.args.env_profile : "";

          const cmd_sha256 = `sha256:${sha256HexFromUtf8(cmd)}`;
          let stdout_bytes = Buffer.from("STUB_STDOUT", "utf8");
          let stderr_bytes = Buffer.from("", "utf8");
          let exit_code = 0;
          let execution_kind = "test_stub";

          // Live optional: run a tiny allowlisted command for real, under strict caps.
          // Default remains stubbed to preserve deterministic mock golden replay.
          if (attestMode === "live" && execMode === "live") {
            const execMaxMs = Number(sourceEnvelope?.args?.execution_permit?.scope?.exec?.max_runtime_ms ?? 60000);
            const execMaxOut = Number(sourceEnvelope?.args?.execution_permit?.scope?.exec?.max_output_bytes ?? 200000);
            const safeCmd = String(cmd ?? "").trim();

            if (safeCmd === "node -v" || safeCmd === "node --version") {
              const nodeArgs = safeCmd.endsWith("--version") ? ["--version"] : ["-v"];
              const proc = spawnSync(process.execPath, nodeArgs, {
                cwd: path.resolve(repoRoot, cwd),
                timeout: Number.isFinite(execMaxMs) ? execMaxMs : 60000,
                maxBuffer: Number.isFinite(execMaxOut) ? execMaxOut : 200000,
                encoding: "buffer",
              });
              exit_code = typeof proc.status === "number" ? proc.status : 1;
              stdout_bytes = Buffer.isBuffer(proc.stdout) ? proc.stdout : Buffer.from("", "utf8");
              stderr_bytes = Buffer.isBuffer(proc.stderr) ? proc.stderr : Buffer.from("", "utf8");
              execution_kind = "test_live";
            } else {
              // Fail-closed fallback: do not run unknown commands in live mode.
              exit_code = 1;
              stdout_bytes = Buffer.from("", "utf8");
              stderr_bytes = Buffer.from("UNSUPPORTED_LIVE_TEST_CMD", "utf8");
              execution_kind = "test_live";
            }
          }

          const stdout_sha256 = `sha256:${sha256HexFromUtf8Bytes(stdout_bytes)}`;
          const stderr_sha256 = `sha256:${sha256HexFromUtf8Bytes(stderr_bytes)}`;

          const testResult = {
            schema_id: "EGL.TEST_RESULT",
            version: "0.1.0",
            exit_code,
            stdout_sha256,
            stderr_sha256,
          };
          const { sha256: testResultHash } = writeCanonicalJSON(path.join(fixtureOut, "test.result.json"), testResult);

          const receipt = {
            schema_id: "EGL.TEST_RECEIPT",
            version: "0.1.0",
            cmd_sha256,
            cwd,
            env_profile,
            exit_code,
            stdout_sha256,
            stderr_sha256,
            permit_sha256: permit_sha256,
            law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? null,
            plan_hash: compilation.hashes?.plan ?? null,
            intent_hash: compilation.hashes?.intent ?? null,
          };
          const { sha256: testReceiptHash } = writeCanonicalJSON(path.join(fixtureOut, "test_receipt.json"), receipt);

          const result = {
            kind: execution_kind === "test_live" ? "code_test_live_result" : "code_test_stub_result",
            exit_code,
            test_receipt_hash_sha256: testReceiptHash,
          };
          const { sha256: resultHashSha256 } = writeCanonicalJSON(path.join(fixtureOut, "result.json"), result);

          const execution = {
            executor_invoked: true,
            execution_kind,
            attest_mode: attestMode,
            lane_id: binding_lane_id,
            expiry_ts,
            attestation_nonce,
            ...(compilation?.meta?.binding ? { binding: compilation.meta.binding } : {}),
            execution_permit_sha256: permit_sha256,
            permit_validated: true,
            permit_validation_code: permitValidation.code ?? null,
            pre_state_hash_sha256,
            post_state_hash_sha256,
            side_effect_detected,
            result_hash_sha256: resultHashSha256,
            file_receipt_hash_sha256: null,
          };
          writeCanonicalJSON(path.join(fixtureOut, "execution.json"), execution);
          executionByFixture[f.fixture_id] = execution;
          lastAdmittedNonce = nonce;
          wroteExecution = true;
        } else if (tool_surface_id === "code.deps.fetch") {
          const cmd = typeof sourceEnvelope?.args?.cmd === "string" ? sourceEnvelope.args.cmd : "";
          const cwd = typeof sourceEnvelope?.args?.cwd === "string" ? sourceEnvelope.args.cwd : ".";
          const env_profile =
            typeof sourceEnvelope?.args?.env_profile === "string" ? sourceEnvelope.args.env_profile : "";
          const lockfile_path =
            typeof sourceEnvelope?.args?.lockfile_path === "string" ? sourceEnvelope.args.lockfile_path : "";

          const cmd_sha256 = `sha256:${sha256HexFromUtf8(cmd)}`;
          const lockfile_sha256_hex = readFileSha256Hex({ repoRoot, relPath: lockfile_path });
          const lockfile_sha256 = lockfile_sha256_hex ? `sha256:${lockfile_sha256_hex}` : null;

          const egress_targets = cmd.startsWith("npm ") ? ["registry.npmjs.org"] : [];

          let exit_code = 0;
          let stdout_bytes = Buffer.from("STUB_DEPS_FETCH", "utf8");
          let stderr_bytes = Buffer.from("", "utf8");
          let execution_kind = "deps_stub";

          // Live optional: still conservative in v0.1 (no installers yet); proves the governed exec boundary.
          if (attestMode === "live" && depsMode === "live") {
            const proc = spawnSync(process.execPath, ["-e", "process.stdout.write('LIVE_DEPS_FETCH_OK')"], {
              cwd: path.resolve(repoRoot, cwd),
              timeout: 30000,
              maxBuffer: 200000,
              encoding: "buffer",
            });
            exit_code = typeof proc.status === "number" ? proc.status : 1;
            stdout_bytes = Buffer.isBuffer(proc.stdout) ? proc.stdout : Buffer.from("", "utf8");
            stderr_bytes = Buffer.isBuffer(proc.stderr) ? proc.stderr : Buffer.from("", "utf8");
            execution_kind = "deps_live";
          }

          const stdout_sha256 = `sha256:${sha256HexFromUtf8Bytes(stdout_bytes)}`;
          const stderr_sha256 = `sha256:${sha256HexFromUtf8Bytes(stderr_bytes)}`;

          const depsResult = {
            schema_id: "EGL.DEPS_RESULT",
            version: "0.1.0",
            exit_code,
            stdout_sha256,
            stderr_sha256,
            lockfile_path,
            lockfile_sha256,
          };
          const { sha256: depsResultHash } = writeCanonicalJSON(path.join(fixtureOut, "deps.result.json"), depsResult);

          const receipt = {
            schema_id: "EGL.DEPS_RECEIPT",
            version: "0.1.0",
            cmd_sha256,
            cwd,
            env_profile,
            exit_code,
            stdout_sha256,
            stderr_sha256,
            lockfile_path,
            lockfile_sha256,
            egress_targets,
            permit_sha256: permit_sha256,
            law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? null,
            plan_hash: compilation.hashes?.plan ?? null,
            intent_hash: compilation.hashes?.intent ?? null,
          };
          const { sha256: depsReceiptHash } = writeCanonicalJSON(path.join(fixtureOut, "deps.receipt.json"), receipt);

          const result = {
            kind: execution_kind === "deps_live" ? "code_deps_live_result" : "code_deps_stub_result",
            exit_code,
            deps_receipt_hash_sha256: depsReceiptHash,
            deps_result_hash_sha256: depsResultHash,
          };
          const { sha256: resultHashSha256 } = writeCanonicalJSON(path.join(fixtureOut, "result.json"), result);

          const execution = {
            executor_invoked: true,
            execution_kind,
            attest_mode: attestMode,
            lane_id: binding_lane_id,
            expiry_ts,
            attestation_nonce,
            ...(compilation?.meta?.binding ? { binding: compilation.meta.binding } : {}),
            execution_permit_sha256: permit_sha256,
            permit_validated: true,
            permit_validation_code: permitValidation.code ?? null,
            pre_state_hash_sha256,
            post_state_hash_sha256,
            side_effect_detected,
            result_hash_sha256: resultHashSha256,
            file_receipt_hash_sha256: null,
          };
          writeCanonicalJSON(path.join(fixtureOut, "execution.json"), execution);
          executionByFixture[f.fixture_id] = execution;
          lastAdmittedNonce = nonce;
          wroteExecution = true;
        } else if (sourceEnvelope?.tool_name === "skill.install") {
          // skill.install never executes (stub-only gate).
          const execution = {
            executor_invoked: false,
            execution_kind: null,
            attest_mode: attestMode,
            lane_id: binding_lane_id,
            expiry_ts,
            attestation_nonce,
            ...(compilation?.meta?.binding ? { binding: compilation.meta.binding } : {}),
            execution_permit_sha256: permit_sha256,
            permit_validated: null,
            permit_validation_code: permitValidation.code ?? null,
            pre_state_hash_sha256,
            post_state_hash_sha256,
            side_effect_detected,
            result_hash_sha256: null,
            file_receipt_hash_sha256: null,
          };
          writeCanonicalJSON(path.join(fixtureOut, "execution.json"), execution);
          executionByFixture[f.fixture_id] = execution;
          lastAdmittedNonce = nonce;
          wroteExecution = true;
        } else {
          // Real sandbox-only execution.
          const envelopeForExec =
            isWriteAttempt && diff_preview_written
              ? {
                  binding: compilation?.meta?.binding ?? null,
                  args: {
                    after_text: deriveWriteAfterText({ relPath: fileRelPath, envelopeArgs: sourceEnvelope?.args ?? {} }),
                    diff_sha256,
                    diff_stats,
                    diff_preview_hash_sha256,
                    ...(isPublishDraft
                      ? {
                          draft_kind: publish_draft_kind,
                          content_sha256: publish_content_sha256,
                        }
                      : {}),
                  },
                }
              : { binding: compilation?.meta?.binding ?? null };

          const ex = execute_real_sandbox({
            repoRoot,
            plan: compilation.plan,
            permit,
            envelope: envelopeForExec,
          });

          if (!ex.ok) {
            outcome = { admitted: false, reason_code: ex.code ?? "INVALID_PERMIT", refusal_status: "REFUSE_HARD" };
          } else {
            const resultPath = path.join(fixtureOut, "result.json");
            const { sha256: resultHashSha256 } = writeCanonicalJSON(resultPath, ex.result);

            if (isFileAction && fileRelPath) {
              post_state_hash_sha256 = file_state_sha256({ repoRoot, relPath: fileRelPath });
              side_effect_detected = pre_state_hash_sha256 !== post_state_hash_sha256;
            }

            if (ex.file_receipt) {
              const receipt = {
                ...ex.file_receipt,
                permit_sha256: permit_sha256,
                law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? null,
                plan_hash: compilation.hashes?.plan ?? null,
                intent_hash: compilation.hashes?.intent ?? null,
                execution_permit_sha256: permit_sha256,
                ...(isPublishDraft
                  ? { draft_kind: publish_draft_kind, content_sha256: publish_content_sha256 }
                  : {}),
              };
              const { sha256 } = writeCanonicalJSON(path.join(fixtureOut, "file_receipt.json"), receipt);
              file_receipt_hash_sha256 = sha256;
            }

            const execution = {
              executor_invoked: true,
              execution_kind: "real_sandbox",
              attest_mode: attestMode,
              lane_id: binding_lane_id,
              expiry_ts,
              attestation_nonce,
              ...(compilation?.meta?.binding ? { binding: compilation.meta.binding } : {}),
              execution_permit_sha256: permit_sha256,
              permit_validated: true,
              permit_validation_code: permitValidation.code ?? null,
              pre_state_hash_sha256,
              post_state_hash_sha256,
              side_effect_detected,
              result_hash_sha256: resultHashSha256,
              file_receipt_hash_sha256,
            };
            writeCanonicalJSON(path.join(fixtureOut, "execution.json"), execution);
            executionByFixture[f.fixture_id] = execution;
            lastAdmittedNonce = nonce;
            wroteExecution = true;

            // Step-20: after draft write succeeds, attempt governed git commit (live-only); always emit git.execution.json.
            if (isPublishDraftCommit) {
              git_diff_sha256 = diff_sha256;
              git_diff_preview_hash_sha256 = diff_preview_hash_sha256;
              git_diff_unified = diff_unified;

              const branch_ref_before = git_branch_ref_before;
              let gitFlags = { branch_created: false, patch_applied: false, staged: false, committed: false };
              let branch_ref_after = branch_ref_before;

              if (attestMode !== "live" || gitMode !== "live") {
                draft_commit_git_reason_code = "HITL_REQUIRED_GIT_COMMIT";
              } else {
                const token = sourceEnvelope?.args?.ratification_token ?? null;
                if (!token) {
                  draft_commit_git_reason_code = "HITL_REQUIRED_GIT_COMMIT";
                } else {
                  const expectedToken = {
                    law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? "",
                    plan_hash: compilation.hashes?.plan ?? "",
                    intent_hash: compilation.hashes?.intent ?? "",
                    lane_id: binding_lane_id ?? "",
                    attestation_nonce: nonce ?? "",
                    git_branch: git_branch ?? "",
                    diff_sha256: git_diff_sha256 ?? "",
                  };
                  const verdict = validate_git_ratification_token({ token, expected: expectedToken, now_iso: nowIso });
                  if (!verdict.ok) {
                    draft_commit_git_reason_code = verdict.code ?? "INVALID_GIT_HITL_TOKEN";
                  } else {
                    try {
                      const commit_message = String(
                        sourceEnvelope?.args?.commit_message ?? `EGL publish.draft.commit ${f.fixture_id}`,
                      );
                      const gr = git_pipeline_commit_from_diff({
                        repoRoot,
                        base_branch: git_base_branch ?? "main",
                        new_branch: git_branch ?? "",
                        diff_unified: git_diff_unified ?? "",
                        commit_message,
                      });
                      gitFlags = {
                        branch_created: gr.steps?.includes("branch_create"),
                        patch_applied: gr.steps?.includes("apply_patch"),
                        staged: gr.steps?.includes("stage"),
                        committed: gr.steps?.includes("commit"),
                      };
                      draft_commit_git_commit_hash = gr.commit_hash;
                      git_commit_hash = gr.commit_hash;
                      git_changed_files = gr.changed_files;

                      const receipt = stableGitReceipt({
                        branch: git_branch,
                        base_branch: git_base_branch,
                        commit_hash: git_commit_hash,
                        changed_files: git_changed_files,
                        diff_sha256s: git_diff_sha256 ? [git_diff_sha256] : [],
                        law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? null,
                        plan_hash: compilation.hashes?.plan ?? null,
                        intent_hash: compilation.hashes?.intent ?? null,
                        permit_sha256: permit_sha256,
                      });
                      const { sha256 } = writeCanonicalJSON(path.join(fixtureOut, "git.receipt.json"), receipt);
                      git_receipt_hash_sha256 = sha256;

                      const draftCommitReceipt = {
                        schema_id: "EGL.DRAFT_COMMIT_RECEIPT",
                        version: "0.1.0",
                        draft_path: publish_draft_path,
                        draft_kind: publish_draft_kind,
                        content_sha256: publish_content_sha256,
                        diff_sha256: git_diff_sha256,
                        diff_preview_hash_sha256: git_diff_preview_hash_sha256,
                        git_branch,
                        git_commit_hash,
                        git_receipt_hash_sha256,
                        permit_sha256,
                        law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? null,
                        plan_hash: compilation.hashes?.plan ?? null,
                        intent_hash: compilation.hashes?.intent ?? null,
                      };
                      const { sha256: dcr } = writeCanonicalJSON(
                        path.join(fixtureOut, "draft_commit_receipt.json"),
                        draftCommitReceipt,
                      );
                      draft_commit_receipt_hash_sha256 = dcr;
                      draft_commit_git_reason_code = "HITL_GIT_TOKEN_ACCEPTED";
                    } catch {
                      draft_commit_git_reason_code = "GIT_EXEC_FAILED";
                    }
                  }
                }
              }

              branch_ref_after = gitBranchRefExists({ repoRoot, branch: git_branch });
              writeCanonicalJSON(path.join(fixtureOut, "git.execution.json"), {
                ...git_execution_evidence({
                  branch_created: gitFlags.branch_created,
                  patch_applied: gitFlags.patch_applied,
                  staged: gitFlags.staged,
                  committed: gitFlags.committed,
                  new_branch: git_branch,
                  base_branch: git_base_branch,
                  reason_code: draft_commit_git_reason_code,
                }),
                attest_mode: attestMode,
                git_mode: gitMode,
                branch_ref_before: branch_ref_before,
                branch_ref_after: branch_ref_after,
                diff_sha256: git_diff_sha256,
                diff_preview_hash_sha256: git_diff_preview_hash_sha256,
                ratification_token_hash_sha256: git_ratification_token_hash_sha256,
                git_receipt_hash_sha256,
                commit_hash: git_commit_hash,
                changed_files: git_changed_files,
                draft_commit_receipt_hash_sha256,
              });
            }
          }
        }
      }

      // Refused/Deferred: must not mutate filesystem.
      if (isFileAction && fileRelPath) {
        post_state_hash_sha256 = file_state_sha256({ repoRoot, relPath: fileRelPath });
        side_effect_detected = pre_state_hash_sha256 !== post_state_hash_sha256;
      }

      if (!wroteExecution) {
        const execution = {
          executor_invoked: false,
          execution_kind: null,
          attest_mode: attestMode,
          lane_id: binding_lane_id,
          expiry_ts,
          attestation_nonce,
          ...(compilation?.meta?.binding ? { binding: compilation.meta.binding } : {}),
          execution_permit_sha256: permit_sha256,
          permit_validated: Boolean(permitValidation.ok),
          permit_validation_code: permitValidation.code ?? null,
          pre_state_hash_sha256,
          post_state_hash_sha256,
          side_effect_detected,
          result_hash_sha256: null,
          file_receipt_hash_sha256: null,
        };
        writeCanonicalJSON(path.join(fixtureOut, "execution.json"), execution);
        executionByFixture[f.fixture_id] = execution;
      }

      if (tool_surface_id === "code.test.run") {
        const cmd = typeof sourceEnvelope?.args?.cmd === "string" ? sourceEnvelope.args.cmd : "";
        const cwd = typeof sourceEnvelope?.args?.cwd === "string" ? sourceEnvelope.args.cwd : ".";
        const env_profile =
          typeof sourceEnvelope?.args?.env_profile === "string" ? sourceEnvelope.args.env_profile : "";
        const cmd_sha256 = `sha256:${sha256HexFromUtf8(cmd)}`;
        writeCanonicalJSON(path.join(fixtureOut, "test.execution.json"), {
          schema_id: "EGL.TEST_EXECUTION",
          version: "0.1.0",
          cmd: cmd,
          cmd_sha256,
          cwd,
          env_profile,
          execution_permit_sha256: permit_sha256,
          permit_validated: Boolean(permitValidation.ok),
          permit_validation_code: permitValidation.code ?? null,
          outcome: {
            status: outcome.admitted ? "admitted" : "rejected",
            reason_code: outcome.reason_code,
            refusal_status: outcome.refusal_status,
          },
          attest_mode: attestMode,
          lane_id: binding_lane_id,
          expiry_ts,
          attestation_nonce,
          ...(compilation?.meta?.binding ? { binding: compilation.meta.binding } : {}),
        });
      }

      if (tool_surface_id === "code.deps.fetch") {
        const cmd = typeof sourceEnvelope?.args?.cmd === "string" ? sourceEnvelope.args.cmd : "";
        const cwd = typeof sourceEnvelope?.args?.cwd === "string" ? sourceEnvelope.args.cwd : ".";
        const env_profile =
          typeof sourceEnvelope?.args?.env_profile === "string" ? sourceEnvelope.args.env_profile : "";
        const lockfile_path =
          typeof sourceEnvelope?.args?.lockfile_path === "string" ? sourceEnvelope.args.lockfile_path : "";
        const lockfile_sha256_hex = readFileSha256Hex({ repoRoot, relPath: lockfile_path });
        const lockfile_sha256 = lockfile_sha256_hex ? `sha256:${lockfile_sha256_hex}` : null;
        const cmd_sha256 = `sha256:${sha256HexFromUtf8(cmd)}`;
        writeCanonicalJSON(path.join(fixtureOut, "deps.execution.json"), {
          schema_id: "EGL.DEPS_EXECUTION",
          version: "0.1.0",
          cmd: cmd,
          cmd_sha256,
          cwd,
          env_profile,
          lockfile_path,
          lockfile_sha256,
          execution_permit_sha256: permit_sha256,
          permit_validated: Boolean(permitValidation.ok),
          permit_validation_code: permitValidation.code ?? null,
          outcome: {
            status: outcome.admitted ? "admitted" : "rejected",
            reason_code: outcome.reason_code,
            refusal_status: outcome.refusal_status,
          },
          attest_mode: attestMode,
          deps_mode: depsMode,
          lane_id: binding_lane_id,
          expiry_ts,
          attestation_nonce,
          ...(compilation?.meta?.binding ? { binding: compilation.meta.binding } : {}),
        });
      }

      if (sourceEnvelope?.tool_name === "publish.post.x" || sourceEnvelope?.tool_name === "publish.post.x_thread") {
        writeCanonicalJSON(path.join(fixtureOut, "post.execution.json"), {
          schema_id: "EGL.POST_EXECUTION",
          version: "0.1.0",
          surface: post_surface,
          payload_sha256: post_payload_sha256,
          source_commit_hash: post_source_commit_hash,
          source_receipt_hash_sha256: post_source_receipt_hash_sha256,
          execution_permit_sha256: permit_sha256,
          permit_validated: Boolean(permitValidation.ok),
          permit_validation_code: permitValidation.code ?? null,
          ratification_token_hash_sha256: post_ratification_token_hash_sha256,
          post_stub_receipt_hash_sha256,
          outcome: {
            status: outcome.admitted ? "admitted" : "rejected",
            reason_code: outcome.reason_code,
            refusal_status: outcome.refusal_status,
          },
          attest_mode: attestMode,
          lane_id: binding_lane_id,
          expiry_ts,
          attestation_nonce,
          ...(compilation?.meta?.binding ? { binding: compilation.meta.binding } : {}),
        });
      }

      if ((isGitPipeline || isPublishDraftCommit) && !fs.existsSync(path.join(fixtureOut, "git.execution.json"))) {
        const branch_ref_after = gitBranchRefExists({ repoRoot, branch: git_branch });
        writeCanonicalJSON(path.join(fixtureOut, "git.execution.json"), {
          ...git_execution_evidence({
            branch_created: false,
            patch_applied: false,
            staged: false,
            committed: false,
            new_branch: git_branch,
            base_branch: git_base_branch,
            reason_code: isPublishDraftCommit
              ? (draft_commit_git_reason_code ?? outcome.reason_code)
              : outcome.reason_code,
          }),
          attest_mode: attestMode,
          git_mode: gitMode,
          branch_ref_before: git_branch_ref_before,
          branch_ref_after,
          diff_sha256: git_diff_sha256 ?? diff_sha256,
          diff_preview_hash_sha256: git_diff_preview_hash_sha256 ?? diff_preview_hash_sha256,
          ratification_token_hash_sha256: git_ratification_token_hash_sha256,
          git_receipt_hash_sha256,
          commit_hash: git_commit_hash,
          changed_files: git_changed_files,
          ...(draft_commit_receipt_hash_sha256 ? { draft_commit_receipt_hash_sha256 } : {}),
        });
      }
    }

    // Supply Chain Evidence (skill.install only): emit canonical diff + SCE and bind hash into ledger.
    let sce_hash_sha256 = null;
    if (
      source === "proxy" &&
      packId === "TH-001C" &&
      sourceEnvelope?.tool_name === "skill.install" &&
      compilation?.meta?.skill_install
    ) {
      const req = sourceEnvelope?.args?.skill_install_request ?? {};
      const diff = req?.capability_diff ?? null;
      let diffSha = { canonical_json: "null", sha256: null };
      if (diff && typeof diff === "object") {
        diffSha = capability_diff_sha256(diff);
      }
      let authSha = { canonical_json: "null", sha256: null };
      if (diff && typeof diff === "object") {
        authSha = authority_diff_sha256(diff);
      }
      fs.writeFileSync(
        path.join(fixtureOut, "capability_diff_canonical.json"),
        diffSha.canonical_json,
        "utf8",
      );
      fs.writeFileSync(
        path.join(fixtureOut, "authority_diff_canonical.json"),
        authSha.canonical_json,
        "utf8",
      );

      const si = compilation.meta.skill_install;
      const decisionForSce = {
        status: outcome.refusal_status ?? (outcome.admitted ? "ALLOW" : "REFUSE_HARD"),
        reason_code: outcome.reason_code,
      };
      const sce = build_sce({
        fixture_id: f.fixture_id,
        skill_id: si.skill_id,
        version_lock: si.version_lock,
        requested_authority_profile: si.requested_authority_profile,
        declared_sha256: si.declared_sha256,
        observed_sha256: si.observed_sha256,
        artifact_size_bytes: si.artifact_size_bytes,
        capability_diff_sha256: diffSha.sha256,
        authority_diff_sha256: authSha.sha256,
        decision: decisionForSce,
      });
      const { canonical: sceCanonical } = writeCanonicalJSON(path.join(fixtureOut, "sce.json"), sce);
      sce_hash_sha256 = sha256HexFromUtf8Bytes(Buffer.from(sceCanonical, "utf8"));

      // Step-11: HITL token accepted => emit deterministic stub receipt (no install, no executor).
      if (outcome.admitted && outcome.reason_code === "HITL_QUORUM_ACCEPTED") {
        const receipt = {
          schema_id: "EGL.SKILL_INSTALL_STUB_RECEIPT",
          version: "0.1.0",
          fixture_id: f.fixture_id,
          intent_hash: compilation.hashes?.intent ?? null,
          plan_hash: compilation.hashes?.plan ?? null,
          lane_id: binding_lane_id,
          attestation_nonce,
          sce_hash_sha256,
          authority_diff_sha256: authSha.sha256,
          ratification_token_hashes,
          ratification_approvers,
          status: "ALLOW",
          reason_code: "HITL_QUORUM_ACCEPTED",
        };
        const { sha256 } = writeCanonicalJSON(
          path.join(fixtureOut, "skill_install_stub_receipt.json"),
          receipt,
        );
        skill_install_stub_receipt_hash_sha256 = sha256;
      }
    }

    const io = {
      schema_id: "EGL.IO",
      version: "0.1.0",
      pack_id: packId,
      run_id: runId,
      fixture_id: f.fixture_id,
      intent_path: f.intent_path,
      ...(sourceEnvelope ? { envelope: redactEnvelopeForIO(sourceEnvelope) } : {}),
      ...(compilation?.meta?.skill_install
        ? {
            parameters: {
              skill_install: {
                capability_diff_digest: compilation.meta.skill_install.capability_diff_digest ?? null,
                authority_diff_sha256: compilation.meta.skill_install.authority_diff_sha256 ?? null,
                ratification_token_hashes:
                  Array.isArray(compilation.meta.skill_install.ratification_token_hashes)
                    ? compilation.meta.skill_install.ratification_token_hashes
                    : [],
                ratification_approvers:
                  Array.isArray(compilation.meta.skill_install.ratification_approvers)
                    ? compilation.meta.skill_install.ratification_approvers
                    : [],
                ratification_token_count:
                  typeof compilation.meta.skill_install.ratification_token_count === "number"
                    ? compilation.meta.skill_install.ratification_token_count
                    : 0,
                declared_hash: compilation.meta.skill_install.declared_sha256 ?? null,
                observed_hash: compilation.meta.skill_install.observed_sha256 ?? null,
                version_lock: compilation.meta.skill_install.version_lock ?? "",
                requested_authority_profile:
                  compilation.meta.skill_install.requested_authority_profile ?? "",
              },
            },
          }
        : {}),
      compilation,
      aar,
    };
    writeCanonicalJSON(path.join(fixtureOut, "io.json"), io);

    if (outcome.admitted) {
      writeCanonicalJSON(path.join(fixtureOut, "plan.json"), compilation.plan);
    }

    const decision = {
      schema_id: "EGL.DECISION",
      version: "0.1.0",
      pack_id: packId,
      run_id: runId,
      fixture_id: f.fixture_id,
      status: outcome.admitted ? "admitted" : "rejected",
      reason_code: outcome.reason_code,
      refusal_status: outcome.refusal_status,
      hashes: {
        intent: compilation.hashes?.intent ?? null,
        plan: compilation.hashes?.plan ?? null,
        aar: aar.hashes?.aar ?? null,
        ledger: aar.ledger?.hashes?.ledger ?? null,
      },
    };

    writeCanonicalJSON(path.join(fixtureOut, "decision.json"), decision);
    const decisionHashStable = sha256Stable(decision);

    perTest[f.fixture_id] = {
      intent_hash: compilation.hashes?.intent ?? null,
      plan_hash: compilation.hashes?.plan ?? null,
      decision_hash: decisionHashStable,
    };

    freezeEntries.push({
      fixture_id: f.fixture_id,
      intent_path: f.intent_path,
      intent_hash: compilation.hashes?.intent ?? null,
      plan_hash: compilation.hashes?.plan ?? null,
      ...(source === "proxy" && packId === "TH-001C"
        ? { attestation_nonce, expiry_ts, lane_id: binding_lane_id }
        : {}),
      ...(source === "proxy" && packId === "TH-001C" && compilation?.meta?.binding
        ? { binding: compilation.meta.binding }
        : {}),
      decision: {
        status: outcome.admitted ? "admitted" : "rejected",
        reason_code: outcome.reason_code,
        refusal_status: outcome.refusal_status,
      },
      reason_code: outcome.reason_code,
      plan: outcome.admitted ? compilation.plan : null,
    });

    ledger.push({
      schema_id: "EGL.SPE_LEDGER_RECORD",
      version: "0.1.0",
      fixture_id: f.fixture_id,
      seq: 1,
      kind: outcome.admitted ? "admission" : "refusal",
      decision_hash: decisionHashStable,
      intent_hash: compilation.hashes?.intent ?? null,
      plan_hash: compilation.hashes?.plan ?? null,
      reason_code: outcome.reason_code,
      refusal_status: outcome.refusal_status,
      ...(source === "proxy" && packId === "TH-001C"
        ? { attestation_nonce, expiry_ts, lane_id: binding_lane_id }
        : {}),
      ...(source === "proxy" && packId === "TH-001C"
        ? {
            execution_permit_sha256,
            execution_permit_validated,
            execution_permit_validation_code,
          }
        : {}),
      ...(source === "proxy" && packId === "TH-001C" && compilation?.meta?.binding
        ? { ...compilation.meta.binding }
        : {}),
      ...(sce_hash_sha256 ? { sce_hash_sha256 } : {}),
      ...(diff_preview_written
        ? {
            diff_sha256,
            diff_stats,
            diff_preview_hash_sha256,
          }
        : {}),
      ...(file_receipt_hash_sha256 ? { file_receipt_hash_sha256 } : {}),
      ...(typeof egress_target_input === "string" && egress_target_input.length > 0
        ? {
            egress_canonical_target,
            egress_protocol,
            egress_zone,
          }
        : {}),
      ...(sourceEnvelope?.tool_name === "git.pipeline_commit_from_diff"
        ? {
            git_branch,
            git_base_branch,
            git_diff_sha256,
            git_diff_preview_hash_sha256,
            ...(git_ratification_token_hash_sha256
              ? { ratification_token_hash_sha256: git_ratification_token_hash_sha256 }
              : {}),
            ...(git_receipt_hash_sha256 ? { git_receipt_hash_sha256 } : {}),
          }
        : {}),
      ...(sourceEnvelope?.tool_name === "publish.post.x" || sourceEnvelope?.tool_name === "publish.post.x_thread"
        ? {
            publish_surface: post_surface,
            payload_sha256: post_payload_sha256,
            source_commit_hash: post_source_commit_hash,
            source_receipt_hash_sha256: post_source_receipt_hash_sha256,
            ...(post_ratification_token_hash_sha256
              ? { ratification_token_hash_sha256: post_ratification_token_hash_sha256 }
              : {}),
            ...(post_stub_receipt_hash_sha256 ? { post_stub_receipt_hash_sha256 } : {}),
          }
        : {}),
      ...(sourceEnvelope?.tool_name === "skill.install" && compilation?.meta?.skill_install
        ? {
            ratification_token_hashes: Array.isArray(compilation.meta.skill_install.ratification_token_hashes)
              ? compilation.meta.skill_install.ratification_token_hashes
              : [],
            ratification_approvers: Array.isArray(compilation.meta.skill_install.ratification_approvers)
              ? compilation.meta.skill_install.ratification_approvers
              : [],
            ratification_quorum_required: 2,
            ratification_quorum_met: Boolean(
              outcome.admitted && outcome.reason_code === "HITL_QUORUM_ACCEPTED",
            ),
            ...(skill_install_stub_receipt_hash_sha256
              ? { skill_install_stub_receipt_hash_sha256 }
              : {}),
          }
        : {}),
      ...(source === "proxy" && packId === "TH-001C" && outcome.reason_code === "POLICY_VERSION_MISMATCH"
        ? {
            expected_law_bundle_sha256: compilation?.meta?.expected_law_bundle_sha256 ?? null,
            actual_law_bundle_sha256: compilation?.meta?.binding?.law_bundle_sha256 ?? null,
          }
        : {}),
    });

    if (outcome.admitted) {
      ledger.push({
        schema_id: "EGL.SPE_LEDGER_RECORD",
        version: "0.1.0",
        fixture_id: f.fixture_id,
        seq: 2,
        kind: "plan_freeze",
        plan_hash: compilation.hashes?.plan ?? null,
        ...(source === "proxy" && packId === "TH-001C" && compilation?.meta?.binding
          ? { ...compilation.meta.binding }
          : {}),
      });
    }

    if (
      outcome.admitted &&
      (sourceEnvelope?.tool_name === "publish.draft.create" ||
        sourceEnvelope?.tool_name === "publish.draft.commit")
    ) {
      ledger.push({
        schema_id: "EGL.SPE_LEDGER_RECORD",
        version: "0.1.0",
        fixture_id: f.fixture_id,
        seq: 3,
        kind: "publish_draft",
        draft_path: publish_draft_path,
        draft_kind: publish_draft_kind,
        content_sha256: publish_content_sha256,
        ...(source === "proxy" && packId === "TH-001C" && compilation?.meta?.binding
          ? { ...compilation.meta.binding }
          : {}),
      });
    }

    if (outcome.admitted && sourceEnvelope?.tool_name === "publish.draft.commit") {
      ledger.push({
        schema_id: "EGL.SPE_LEDGER_RECORD",
        version: "0.1.0",
        fixture_id: f.fixture_id,
        seq: 4,
        kind: "publish_draft_commit",
        draft_path: publish_draft_path,
        draft_kind: publish_draft_kind,
        content_sha256: publish_content_sha256,
        diff_sha256: git_diff_sha256 ?? diff_sha256,
        diff_preview_hash_sha256: git_diff_preview_hash_sha256 ?? diff_preview_hash_sha256,
        git_branch: git_branch,
        git_base_branch: git_base_branch,
        git_commit_hash: git_commit_hash,
        git_receipt_hash_sha256: git_receipt_hash_sha256,
        draft_commit_receipt_hash_sha256: draft_commit_receipt_hash_sha256,
        reason_code: draft_commit_git_reason_code,
        ...(source === "proxy" && packId === "TH-001C" && compilation?.meta?.binding
          ? { ...compilation.meta.binding }
          : {}),
      });
    }

    if (
      outcome.admitted &&
      (sourceEnvelope?.tool_name === "publish.post.x" || sourceEnvelope?.tool_name === "publish.post.x_thread")
    ) {
      ledger.push({
        schema_id: "EGL.SPE_LEDGER_RECORD",
        version: "0.1.0",
        fixture_id: f.fixture_id,
        seq: 3,
        kind: "publish_post_stub",
        surface: post_surface,
        payload_sha256: post_payload_sha256,
        source_commit_hash: post_source_commit_hash,
        source_receipt_hash_sha256: post_source_receipt_hash_sha256,
        ratification_token_hash_sha256: post_ratification_token_hash_sha256,
        post_stub_receipt_hash_sha256,
        ...(source === "proxy" && packId === "TH-001C" && compilation?.meta?.binding
          ? { ...compilation.meta.binding }
          : {}),
      });
    }

    const tool_surface_id_local = String(compilation?.plan?.actions?.[0]?.tool_surface_id ?? "");
    if (tool_surface_id_local === "code.test.run") {
      const cmd = typeof sourceEnvelope?.args?.cmd === "string" ? sourceEnvelope.args.cmd : "";
      const cwd = typeof sourceEnvelope?.args?.cwd === "string" ? sourceEnvelope.args.cwd : ".";
      const env_profile = typeof sourceEnvelope?.args?.env_profile === "string" ? sourceEnvelope.args.env_profile : "";
      const cmd_sha256 = `sha256:${sha256HexFromUtf8(cmd)}`;
      const testResultPath = path.join(fixtureOut, "test.result.json");
      const exit_code = fs.existsSync(testResultPath)
        ? Number(JSON.parse(fs.readFileSync(testResultPath, "utf8"))?.exit_code ?? null)
        : (outcome.admitted ? 0 : null);
      const testReceiptPath = path.join(fixtureOut, "test_receipt.json");
      const test_receipt_hash_sha256 = fs.existsSync(testReceiptPath)
        ? sha256HexFromUtf8(fs.readFileSync(testReceiptPath, "utf8"))
        : null;

      ledger.push({
        schema_id: "EGL.SPE_LEDGER_RECORD",
        version: "0.1.0",
        fixture_id: f.fixture_id,
        seq: 3,
        kind: "code_test_run",
        cmd_sha256,
        cwd,
        env_profile,
        exit_code: Number.isFinite(exit_code) ? exit_code : null,
        ...(test_receipt_hash_sha256 ? { test_receipt_hash_sha256: `sha256:${test_receipt_hash_sha256}` } : {}),
        ...(source === "proxy" && packId === "TH-001C" && compilation?.meta?.binding
          ? { ...compilation.meta.binding }
          : {}),
      });
    }

    if (tool_surface_id_local === "code.deps.fetch") {
      const cmd = typeof sourceEnvelope?.args?.cmd === "string" ? sourceEnvelope.args.cmd : "";
      const cwd = typeof sourceEnvelope?.args?.cwd === "string" ? sourceEnvelope.args.cwd : ".";
      const env_profile = typeof sourceEnvelope?.args?.env_profile === "string" ? sourceEnvelope.args.env_profile : "";
      const lockfile_path =
        typeof sourceEnvelope?.args?.lockfile_path === "string" ? sourceEnvelope.args.lockfile_path : "";
      const cmd_sha256 = `sha256:${sha256HexFromUtf8(cmd)}`;
      const lockfile_sha256_hex = readFileSha256Hex({ repoRoot, relPath: lockfile_path });
      const lockfile_sha256 = lockfile_sha256_hex ? `sha256:${lockfile_sha256_hex}` : null;

      const depsResultPath = path.join(fixtureOut, "deps.result.json");
      const exit_code = fs.existsSync(depsResultPath)
        ? Number(JSON.parse(fs.readFileSync(depsResultPath, "utf8"))?.exit_code ?? null)
        : null;

      const depsReceiptPath = path.join(fixtureOut, "deps.receipt.json");
      const deps_receipt_hash_sha256 = fs.existsSync(depsReceiptPath)
        ? sha256HexFromUtf8(fs.readFileSync(depsReceiptPath, "utf8"))
        : null;

      ledger.push({
        schema_id: "EGL.SPE_LEDGER_RECORD",
        version: "0.1.0",
        fixture_id: f.fixture_id,
        seq: 3,
        kind: "code_deps_fetch",
        cmd_sha256,
        cwd,
        env_profile,
        lockfile_path,
        lockfile_sha256,
        exit_code: Number.isFinite(exit_code) ? exit_code : null,
        ...(deps_receipt_hash_sha256 ? { deps_receipt_hash_sha256: `sha256:${deps_receipt_hash_sha256}` } : {}),
        ...(source === "proxy" && packId === "TH-001C" && compilation?.meta?.binding
          ? { ...compilation.meta.binding }
          : {}),
      });
    }
  }

  freezeEntries.sort((a, b) => a.fixture_id.localeCompare(b.fixture_id));
  ledger.sort((a, b) => {
    if (a.fixture_id !== b.fixture_id) return a.fixture_id.localeCompare(b.fixture_id);
    return a.seq - b.seq;
  });

  const planFreeze = {
    schema_id: "EGL.PLAN_FREEZE_BUNDLE",
    version: "0.1.0",
    pack_id: packId,
    run_id: runId,
    plans: freezeEntries,
  };

  writeCanonicalJSON(path.join(outRoot, "plan.freeze.json"), planFreeze);
  writeJSONL(path.join(outRoot, "spe.ledger.jsonl"), ledger);

  const noAbsLeakScore = computeNoAbsolutePathLeakScoreWithExtras({
    outRoot,
    extraRoots: leakExtraRoots,
  });

  const metrics = {
    pack_id: packId,
    run_id: runId,
    refusal_rate: 0.0,
    escalation_detection_rate: 0.0,
    plan_hash_integrity_score: 0.0,
    lane_isolation_score: 0.0,
    substrate_mutation_block_score: 0.0,
    no_side_effect_on_refusal_score: 0.0,
    no_absolute_path_leak_score: 0.0,
    toctou_block_score: 0.0,
    replay_block_score: 0.0,
    supply_chain_block_score: 0.0,
    supply_chain_evidence_score: 0.0,
    hitl_gate_score: 0.0,
    hitl_authority_gate_score: 0.0,
    hitl_quorum_gate_score: 0.0,
    pass: false,
  };
  if (source === "proxy" && packId === "TH-001C") {
    metrics.policy_version_binding_score = 0.0;
    metrics.permit_gate_score = 0.0;
    metrics.real_exec_sandbox_score = 0.0;
    metrics.diff_preview_score = 0.0;
    metrics.diff_permit_scope_score = 0.0;
    metrics.git_gate_score = 0.0;
    metrics.publish_draft_score = 0.0;
    metrics.draft_commit_chain_score = 0.0;
    metrics.publish_post_gate_score = 0.0;
    metrics.egress_gate_score = 0.0;
    metrics.code_patch_score = 0.0;
    metrics.code_test_score = 0.0;
    metrics.deps_fetch_score = 0.0;
  }

  const hasUnmappedRefusal = freezeEntries.some(
    (p) => p.reason_code === "UNMAPPED_TOOL_SURFACE",
  );
  const checks = {
    refusal_rate: hasUnmappedRefusal,
    escalation_detection_rate: true,
    plan_hash_integrity_score: true,
    lane_isolation_score: true,
    substrate_mutation_block_score: true,
    no_side_effect_on_refusal_score: true,
    no_absolute_path_leak_score: noAbsLeakScore === 1.0,
    toctou_block_score: true,
    replay_block_score: true,
    supply_chain_block_score: true,
    supply_chain_evidence_score: true,
    hitl_gate_score: true,
    hitl_authority_gate_score: true,
    hitl_quorum_gate_score: true,
  };
  if (source === "proxy" && packId === "TH-001C") {
    checks.policy_version_binding_score = false;
    checks.permit_gate_score = false;
    checks.real_exec_sandbox_score = false;
    checks.diff_preview_score = false;
    checks.diff_permit_scope_score = false;
    checks.git_gate_score = false;
    checks.publish_draft_score = false;
    checks.draft_commit_chain_score = false;
    checks.publish_post_gate_score = false;
    checks.egress_gate_score = false;
    checks.code_patch_score = false;
    checks.code_test_score = false;
    checks.deps_fetch_score = false;
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));
    let ok = true;
    for (const f of fixtures) {
      const fr = freezeByFixture.get(f.fixture_id);
      const admitted = fr?.decision?.status === "admitted";
      const exec = executionByFixture[f.fixture_id];
      if (!exec) {
        ok = false;
        continue;
      }
      const isSkillInstall =
        admitted &&
        fr &&
        fr.plan &&
        Array.isArray(fr.plan.actions) &&
        fr.plan.actions.some((a) => String(a?.tool_surface_id ?? "") === "skill.install");
      if (admitted && !isSkillInstall && exec.executor_invoked !== true) ok = false;
      if (admitted && isSkillInstall && exec.executor_invoked !== false) ok = false;
      if (!admitted && exec.executor_invoked !== false) ok = false;
    }
    checks.no_side_effect_on_refusal_score = ok;
  }

  if (source === "proxy" && packId === "TH-001C" && attestMode === "live") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));
    if (freezeByFixture.has("toctou_symlink_swap")) {
      const fr = freezeByFixture.get("toctou_symlink_swap");
      const exec = executionByFixture["toctou_symlink_swap"];
      const ok =
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "TOCTOU_DETECTED" &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        exec?.result_hash_sha256 === null;
      checks.toctou_block_score = Boolean(ok);
    }
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));

    const laneOk = (() => {
      if (!freezeByFixture.has("lane_mismatch")) return false;
      const fr = freezeByFixture.get("lane_mismatch");
      const exec = executionByFixture["lane_mismatch"];
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "LANE_MISMATCH" &&
        fr?.plan === null &&
        exec?.executor_invoked === false
      );
    })();

    const expOk = (() => {
      if (!freezeByFixture.has("plan_expired")) return false;
      const fr = freezeByFixture.get("plan_expired");
      const exec = executionByFixture["plan_expired"];
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "PLAN_EXPIRED" &&
        fr?.plan === null &&
        exec?.executor_invoked === false
      );
    })();

    const nonceOk = (() => {
      if (attestMode !== "live") return true; // live-only enforcement
      if (!freezeByFixture.has("nonce_replay_second")) return false;
      const fr = freezeByFixture.get("nonce_replay_second");
      const exec = executionByFixture["nonce_replay_second"];
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "NONCE_REPLAY" &&
        fr?.plan === null &&
        exec?.executor_invoked === false
      );
    })();

    checks.replay_block_score = Boolean(laneOk && expOk && nonceOk);
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));
    const has = (id) => freezeByFixture.has(id) && executionByFixture[id];
    const okNoDiff =
      has("skill_install_no_diff") &&
      freezeByFixture.get("skill_install_no_diff")?.decision?.status === "rejected" &&
      freezeByFixture.get("skill_install_no_diff")?.reason_code === "MISSING_CAPABILITY_DIFF" &&
      executionByFixture["skill_install_no_diff"]?.executor_invoked === false;
    const okMismatch =
      has("skill_install_hash_mismatch") &&
      freezeByFixture.get("skill_install_hash_mismatch")?.decision?.status === "rejected" &&
      freezeByFixture.get("skill_install_hash_mismatch")?.reason_code === "ARTIFACT_HASH_MISMATCH" &&
      executionByFixture["skill_install_hash_mismatch"]?.executor_invoked === false;
    const okDefer =
      has("skill_install_defer_ok") &&
      freezeByFixture.get("skill_install_defer_ok")?.decision?.status === "rejected" &&
      freezeByFixture.get("skill_install_defer_ok")?.reason_code === "HITL_REQUIRED_SURFACE_EXPANSION" &&
      freezeByFixture.get("skill_install_defer_ok")?.decision?.refusal_status === "DEFER_HITL" &&
      executionByFixture["skill_install_defer_ok"]?.executor_invoked === false;
    checks.supply_chain_block_score = Boolean(okNoDiff && okMismatch && okDefer);
  }

  if (source === "proxy" && packId === "TH-001C") {
    const skillFixtures = [
      "skill_install_no_diff",
      "skill_install_hash_mismatch",
      "skill_install_defer_ok",
      "skill_install_token_missing",
      "skill_install_token_invalid",
      "skill_install_token_valid",
      "skill_install_token_authority_drift",
      "skill_install_quorum_missing",
      "skill_install_quorum_one_token",
      "skill_install_quorum_two_tokens",
      "skill_install_quorum_duplicate_approver",
    ].filter((id) => executionByFixture[id]);

    if (skillFixtures.length > 0) {
      const ledgerRecords = parseJSONL(path.join(outRoot, "spe.ledger.jsonl"));
      let ok = true;
      for (const fixtureId of skillFixtures) {
        const scePath = path.join(outRoot, "fixtures", fixtureId, "sce.json");
        if (!fs.existsSync(scePath)) {
          ok = false;
          continue;
        }
        const sceRaw = fs.readFileSync(scePath, "utf8");
        const sceHash = sha256HexFromUtf8Bytes(Buffer.from(sceRaw, "utf8"));
        const record = ledgerRecords.find(
          (r) => r.fixture_id === fixtureId && (r.kind === "refusal" || r.kind === "admission"),
        );
        if (!record || record.sce_hash_sha256 !== sceHash) ok = false;
      }
      checks.supply_chain_evidence_score = ok;
    }
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));

    const missingOk = (() => {
      if (!freezeByFixture.has("skill_install_token_missing")) return false;
      const fr = freezeByFixture.get("skill_install_token_missing");
      const exec = executionByFixture["skill_install_token_missing"];
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "HITL_REQUIRED_SURFACE_EXPANSION" &&
        fr?.decision?.refusal_status === "DEFER_HITL" &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        !fs.existsSync(path.join(outRoot, "fixtures", "skill_install_token_missing", "result.json")) &&
        !fs.existsSync(
          path.join(outRoot, "fixtures", "skill_install_token_missing", "skill_install_stub_receipt.json"),
        )
      );
    })();

    const invalidOk = (() => {
      if (!freezeByFixture.has("skill_install_token_invalid")) return false;
      const fr = freezeByFixture.get("skill_install_token_invalid");
      const exec = executionByFixture["skill_install_token_invalid"];
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "HITL_TOKEN_BINDING_MISMATCH" &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        !fs.existsSync(path.join(outRoot, "fixtures", "skill_install_token_invalid", "result.json")) &&
        !fs.existsSync(
          path.join(outRoot, "fixtures", "skill_install_token_invalid", "skill_install_stub_receipt.json"),
        )
      );
    })();

    const validOk = (() => {
      if (!freezeByFixture.has("skill_install_token_valid")) return false;
      const fr = freezeByFixture.get("skill_install_token_valid");
      const exec = executionByFixture["skill_install_token_valid"];
      if (
        fr?.decision?.status !== "rejected" ||
        fr?.reason_code !== "HITL_QUORUM_NOT_MET" ||
        fr?.decision?.refusal_status !== "DEFER_HITL" ||
        fr?.plan !== null ||
        exec?.executor_invoked !== false
      ) {
        return false;
      }
      if (fs.existsSync(path.join(outRoot, "fixtures", "skill_install_token_valid", "result.json"))) {
        return false;
      }
      if (
        fs.existsSync(
          path.join(outRoot, "fixtures", "skill_install_token_valid", "skill_install_stub_receipt.json"),
        )
      ) {
        return false;
      }
      return true;
    })();

    checks.hitl_gate_score = Boolean(missingOk && invalidOk && validOk);
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));
    const exec = executionByFixture["skill_install_token_authority_drift"];
    if (freezeByFixture.has("skill_install_token_authority_drift")) {
      const fr = freezeByFixture.get("skill_install_token_authority_drift");
      const ok =
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "HITL_AUTHORITY_DIFF_MISMATCH" &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        !fs.existsSync(
          path.join(outRoot, "fixtures", "skill_install_token_authority_drift", "result.json"),
        ) &&
        !fs.existsSync(
          path.join(
            outRoot,
            "fixtures",
            "skill_install_token_authority_drift",
            "skill_install_stub_receipt.json",
          ),
        );
      checks.hitl_authority_gate_score = Boolean(ok);
    }
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));
    const ledgerRecords = parseJSONL(path.join(outRoot, "spe.ledger.jsonl"));

    const miss = (() => {
      const id = "skill_install_quorum_missing";
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "HITL_REQUIRED_SURFACE_EXPANSION" &&
        fr?.decision?.refusal_status === "DEFER_HITL" &&
        fr?.plan === null &&
        exec?.executor_invoked === false
      );
    })();

    const one = (() => {
      const id = "skill_install_quorum_one_token";
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "HITL_QUORUM_NOT_MET" &&
        fr?.decision?.refusal_status === "DEFER_HITL" &&
        fr?.plan === null &&
        exec?.executor_invoked === false
      );
    })();

    const dup = (() => {
      const id = "skill_install_quorum_duplicate_approver";
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "HITL_DUPLICATE_APPROVER" &&
        fr?.decision?.refusal_status === "DEFER_HITL" &&
        fr?.plan === null &&
        exec?.executor_invoked === false
      );
    })();

    const two = (() => {
      const id = "skill_install_quorum_two_tokens";
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      const receiptPath = path.join(outRoot, "fixtures", id, "skill_install_stub_receipt.json");
      if (
        fr?.decision?.status !== "admitted" ||
        fr?.reason_code !== "HITL_QUORUM_ACCEPTED" ||
        exec?.executor_invoked !== false ||
        !fs.existsSync(receiptPath) ||
        fs.existsSync(path.join(outRoot, "fixtures", id, "result.json"))
      ) {
        return false;
      }
      const receiptRaw = fs.readFileSync(receiptPath, "utf8");
      const receiptHash = sha256HexFromUtf8Bytes(Buffer.from(receiptRaw, "utf8"));
      const rec = ledgerRecords.find((r) => r.fixture_id === id && r.kind === "admission");
      return (
        Boolean(rec) &&
        rec.skill_install_stub_receipt_hash_sha256 === receiptHash &&
        Array.isArray(rec.ratification_token_hashes) &&
        rec.ratification_token_hashes.length === 2 &&
        Array.isArray(rec.ratification_approvers) &&
        rec.ratification_approvers.length === 2 &&
        rec.ratification_quorum_required === 2 &&
        rec.ratification_quorum_met === true
      );
    })();

    checks.hitl_quorum_gate_score = Boolean(miss && one && dup && two);
  }

  if (source === "proxy" && packId === "TH-001C") {
    const bundlePath = path.join(outRoot, "law.bundle.json");
    const bundleHashPath = path.join(outRoot, "law.bundle.hash.json");
    const lawFilesExist = fs.existsSync(bundlePath) && fs.existsSync(bundleHashPath);

    const hasBindingInFreeze = freezeEntries.some(
      (p) =>
        p &&
        p.binding &&
        typeof p.binding.law_bundle_sha256 === "string" &&
        p.binding.law_bundle_sha256.length > 0 &&
        typeof p.binding.policy_bundle_sha256 === "string" &&
        p.binding.policy_bundle_sha256.length > 0 &&
        typeof p.binding.authority_profiles_sha256 === "string" &&
        p.binding.authority_profiles_sha256.length > 0 &&
        typeof p.binding.tool_surface_map_sha256 === "string" &&
        p.binding.tool_surface_map_sha256.length > 0,
    );

    const hasBindingInLedger = ledger.some(
      (r) =>
        r &&
        typeof r.law_bundle_sha256 === "string" &&
        r.law_bundle_sha256.length > 0 &&
        typeof r.policy_bundle_sha256 === "string" &&
        r.policy_bundle_sha256.length > 0 &&
        typeof r.authority_profiles_sha256 === "string" &&
        r.authority_profiles_sha256.length > 0 &&
        typeof r.tool_surface_map_sha256 === "string" &&
        r.tool_surface_map_sha256.length > 0,
    );

    const hasBindingInExecution = Object.values(executionByFixture).some(
      (e) => e && typeof e.binding?.law_bundle_sha256 === "string" && e.binding.law_bundle_sha256.length > 0,
    );

    const mismatchOk = freezeEntries.some(
      (p) => p.fixture_id === "policy_version_mismatch" && p.reason_code === "POLICY_VERSION_MISMATCH",
    );

    checks.policy_version_binding_score = Boolean(
      lawFilesExist && hasBindingInFreeze && hasBindingInLedger && hasBindingInExecution && mismatchOk,
    );
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));

    const refusedPermitOk = (id, code) => {
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === code &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        exec?.side_effect_detected === false &&
        exec?.pre_state_hash_sha256 === exec?.post_state_hash_sha256 &&
        !fs.existsSync(path.join(fixtureOut, "result.json")) &&
        !fs.existsSync(path.join(fixtureOut, "file_receipt.json")) &&
        fs.existsSync(path.join(fixtureOut, "permit.validation.json"))
      );
    };

    const permit_gate_score = Boolean(
      refusedPermitOk("exec_permit_write_missing", "PERMIT_REQUIRED") &&
        refusedPermitOk("exec_permit_write_invalid_hash", "INVALID_PERMIT") &&
        refusedPermitOk("exec_permit_write_binding_mismatch", "PERMIT_BINDING_MISMATCH") &&
        refusedPermitOk("exec_permit_write_scope_violation", "PERMIT_SCOPE_VIOLATION"),
    );
    checks.permit_gate_score = permit_gate_score;

    const real_exec_sandbox_score = (() => {
      const id = "exec_permit_write_valid";
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      const targetAbs = path.resolve(repoRoot, "sandbox", "_th_tmp", "permit_test.txt");
      return (
        fr?.decision?.status === "admitted" &&
        fr?.plan !== null &&
        exec?.executor_invoked === true &&
        exec?.execution_kind === "real_sandbox" &&
        exec?.side_effect_detected === true &&
        fs.existsSync(path.join(fixtureOut, "result.json")) &&
        fs.existsSync(path.join(fixtureOut, "file_receipt.json")) &&
        fs.existsSync(targetAbs)
      );
    })();
    checks.real_exec_sandbox_score = real_exec_sandbox_score;
  }

  if (source === "proxy" && packId === "TH-001C") {
    const writeFixtures = [
      "exec_permit_write_missing",
      "exec_permit_write_invalid_hash",
      "exec_permit_write_binding_mismatch",
      "exec_permit_write_scope_violation",
      "exec_permit_write_valid",
      "diff_write_preview_only",
      "diff_write_too_large",
      "diff_write_valid_apply",
    ].filter((id) => executionByFixture[id]);

    checks.diff_preview_score = writeFixtures.every((id) =>
      fs.existsSync(path.join(outRoot, "fixtures", id, "diff.preview.json")),
    );

    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));
    const refused = (id, code) =>
      freezeByFixture.get(id)?.decision?.status === "rejected" &&
      freezeByFixture.get(id)?.reason_code === code &&
      fs.existsSync(path.join(outRoot, "fixtures", id, "diff.preview.json")) &&
      !fs.existsSync(path.join(outRoot, "fixtures", id, "result.json"));

    const applied = (id) =>
      freezeByFixture.get(id)?.decision?.status === "admitted" &&
      fs.existsSync(path.join(outRoot, "fixtures", id, "diff.preview.json")) &&
      fs.existsSync(path.join(outRoot, "fixtures", id, "file_receipt.json"));

    checks.diff_permit_scope_score = Boolean(
      refused("diff_write_preview_only", "PERMIT_OP_NOT_ALLOWED") &&
        refused("diff_write_too_large", "DIFF_TOO_LARGE") &&
        applied("diff_write_valid_apply"),
    );
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));

    const checkGitGated = (id, expectedReasonCode, expectedRefusalStatus) => {
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      const gitExecPath = path.join(fixtureOut, "git.execution.json");
      if (!fs.existsSync(gitExecPath)) return false;
      const gitExec = readJSON(gitExecPath);

      const receiptPath = path.join(fixtureOut, "git.receipt.json");
      if (fs.existsSync(receiptPath)) return false;

      const sideEffects =
        gitExec?.branch_created === true ||
        gitExec?.patch_applied === true ||
        gitExec?.staged === true ||
        gitExec?.commit_created === true;

      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === expectedReasonCode &&
        fr?.decision?.refusal_status === expectedRefusalStatus &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        sideEffects === false &&
        gitExec?.branch_ref_before === gitExec?.branch_ref_after
      );
    };

    checks.git_gate_score = Boolean(
      checkGitGated("git_pipeline_missing_permit", "PERMIT_REQUIRED", "REFUSE_HARD") &&
        checkGitGated("git_pipeline_invalid_permit", "INVALID_PERMIT", "REFUSE_HARD") &&
        checkGitGated("git_pipeline_no_token", "HITL_REQUIRED_GIT_COMMIT", "DEFER_HITL") &&
        checkGitGated("git_pipeline_token_valid", "HITL_REQUIRED_GIT_COMMIT", "DEFER_HITL"),
    );
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));

    const miss = (() => {
      const id = "publish_draft_create_missing_permit";
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "PERMIT_REQUIRED" &&
        fr?.decision?.refusal_status === "REFUSE_HARD" &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        !fs.existsSync(path.join(fixtureOut, "diff.preview.json")) &&
        !fs.existsSync(path.join(fixtureOut, "result.json"))
      );
    })();

    const previewOnly = (() => {
      const id = "publish_draft_create_preview_only";
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "PERMIT_OP_NOT_ALLOWED" &&
        fr?.decision?.refusal_status === "REFUSE_HARD" &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        fs.existsSync(path.join(fixtureOut, "diff.preview.json")) &&
        !fs.existsSync(path.join(fixtureOut, "result.json"))
      );
    })();

    const tooLarge = (() => {
      const id = "publish_draft_create_too_large";
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "DIFF_TOO_LARGE" &&
        fr?.decision?.refusal_status === "REFUSE_HARD" &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        fs.existsSync(path.join(fixtureOut, "diff.preview.json")) &&
        !fs.existsSync(path.join(fixtureOut, "result.json"))
      );
    })();

    const valid = (() => {
      const id = "publish_draft_create_valid";
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      const actionPath = fr?.plan?.actions?.[0]?.file?.path;
      const okPath = typeof actionPath === "string" && actionPath.startsWith("sandbox/_publish_drafts/");
      const absDraft = okPath ? path.resolve(repoRoot, actionPath) : null;
      const hasLedger = parseJSONL(path.join(outRoot, "spe.ledger.jsonl")).some(
        (r) => r.fixture_id === id && r.kind === "publish_draft",
      );
      return (
        fr?.decision?.status === "admitted" &&
        fr?.plan !== null &&
        exec?.executor_invoked === true &&
        exec?.execution_kind === "real_sandbox" &&
        fs.existsSync(path.join(fixtureOut, "diff.preview.json")) &&
        fs.existsSync(path.join(fixtureOut, "file_receipt.json")) &&
        okPath &&
        absDraft &&
        fs.existsSync(absDraft) &&
        hasLedger
      );
    })();

    checks.publish_draft_score = Boolean(miss && previewOnly && tooLarge && valid);
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));

    const noGitSideEffects = (fixtureOut) => {
      const gitExecPath = path.join(fixtureOut, "git.execution.json");
      if (!fs.existsSync(gitExecPath)) return false;
      const ge = readJSON(gitExecPath);
      return (
        ge?.branch_created === false &&
        ge?.patch_applied === false &&
        ge?.staged === false &&
        ge?.commit_created === false &&
        ge?.branch_ref_before === ge?.branch_ref_after &&
        !fs.existsSync(path.join(fixtureOut, "git.receipt.json")) &&
        !fs.existsSync(path.join(fixtureOut, "draft_commit_receipt.json"))
      );
    };

    const miss = (() => {
      const id = "publish_draft_commit_missing_permit";
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === "PERMIT_REQUIRED" &&
        fr?.decision?.refusal_status === "REFUSE_HARD" &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        !fs.existsSync(path.join(fixtureOut, "diff.preview.json")) &&
        !fs.existsSync(path.join(fixtureOut, "file_receipt.json")) &&
        noGitSideEffects(fixtureOut)
      );
    })();

    const okGated = (id) => {
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      const actionPath = fr?.plan?.actions?.[0]?.file?.path;
      const okPath = typeof actionPath === "string" && actionPath.startsWith("sandbox/_publish_drafts/");
      const absDraft = okPath ? path.resolve(repoRoot, actionPath) : null;
      const ledgerOk = parseJSONL(path.join(outRoot, "spe.ledger.jsonl")).some(
        (r) => r.fixture_id === id && r.kind === "publish_draft_commit" && r.reason_code === "HITL_REQUIRED_GIT_COMMIT",
      );
      return (
        fr?.decision?.status === "admitted" &&
        fr?.plan !== null &&
        exec?.executor_invoked === true &&
        exec?.execution_kind === "real_sandbox" &&
        fs.existsSync(path.join(fixtureOut, "diff.preview.json")) &&
        fs.existsSync(path.join(fixtureOut, "file_receipt.json")) &&
        okPath &&
        absDraft &&
        fs.existsSync(absDraft) &&
        noGitSideEffects(fixtureOut) &&
        ledgerOk
      );
    };

    const gatedMock = okGated("publish_draft_commit_valid_mock");
    const gatedLiveFixtureInMock = okGated("publish_draft_commit_valid_live");

    checks.draft_commit_chain_score = Boolean(miss && gatedMock && gatedLiveFixtureInMock);
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));
    const caseOk = (id, reason, refusalStatus) => {
      if (!freezeByFixture.has(id)) return false;
      const fr = freezeByFixture.get(id);
      const fixtureOut = path.join(outRoot, "fixtures", id);
      if (!fs.existsSync(path.join(fixtureOut, "post.execution.json"))) return false;
      if (fs.existsSync(path.join(fixtureOut, "post_stub_receipt.json"))) return false;
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === reason &&
        fr?.decision?.refusal_status === refusalStatus &&
        !fs.existsSync(path.join(fixtureOut, "result.json"))
      );
    };

    checks.publish_post_gate_score = Boolean(
      caseOk("publish_post_x_missing_permit", "PERMIT_REQUIRED", "REFUSE_HARD") &&
        caseOk("publish_post_x_valid_mock", "HITL_REQUIRED_PUBLISH_POST", "DEFER_HITL") &&
        caseOk("publish_post_x_token_invalid", "HITL_TOKEN_BINDING_MISMATCH", "REFUSE_HARD") &&
        caseOk("publish_post_x_token_valid_live", "HITL_REQUIRED_PUBLISH_POST", "DEFER_HITL"),
    );
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));
    const checkPath = (id) => path.join(outRoot, "fixtures", id, "egress.check.json");
    const check = (id) => (fs.existsSync(checkPath(id)) ? readJSON(checkPath(id)) : null);

    const refused = (id, reason) => {
      const fr = freezeByFixture.get(id);
      const c = check(id);
      if (!fr || !c) return false;
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === reason &&
        fr?.decision?.refusal_status === "REFUSE_HARD" &&
        typeof c?.canonical_target === "string" &&
        c?.status === "refused" &&
        c?.reason_code === reason
      );
    };

    const admitted = (id, canonicalTarget) => {
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      const c = check(id);
      if (!fr || !exec || !c) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      return (
        fr?.decision?.status === "admitted" &&
        fr?.plan !== null &&
        exec?.executor_invoked === true &&
        exec?.execution_kind === "net_stub" &&
        fs.existsSync(path.join(fixtureOut, "result.json")) &&
        c?.status === "ok" &&
        c?.canonical_target === canonicalTarget
      );
    };

    checks.egress_gate_score = Boolean(
      refused("egress_navigate_missing_permit", "PERMIT_REQUIRED") &&
        refused("egress_navigate_denied_host", "EGRESS_DENIED") &&
        refused("egress_navigate_http_downgrade", "INSECURE_PROTOCOL") &&
        refused("egress_navigate_localhost_denied", "LOCALHOST_DENIED") &&
        admitted("egress_navigate_allow_host_only", "example.com") &&
        admitted("egress_navigate_allow_host_443_only", "example.com:443"),
    );
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));

    const hasPreview = (id) => fs.existsSync(path.join(outRoot, "fixtures", id, "diff.preview.json"));
    const hasReceipt = (id) => fs.existsSync(path.join(outRoot, "fixtures", id, "file_receipt.json"));
    const hasResult = (id) => fs.existsSync(path.join(outRoot, "fixtures", id, "result.json"));

    const refused = (id, code) => {
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!fr || !exec) return false;
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === code &&
        fr?.decision?.refusal_status === "REFUSE_HARD" &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        hasPreview(id) &&
        !hasReceipt(id) &&
        !hasResult(id)
      );
    };

    const applied = (id) => {
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!fr || !exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      const targetAbs = path.resolve(repoRoot, "sandbox", "_th_tmp", "code_patch_target.txt");
      return (
        fr?.decision?.status === "admitted" &&
        fr?.plan !== null &&
        exec?.executor_invoked === true &&
        exec?.execution_kind === "real_sandbox" &&
        hasPreview(id) &&
        hasReceipt(id) &&
        hasResult(id) &&
        fs.existsSync(targetAbs) &&
        fs.existsSync(path.join(fixtureOut, "permit.validation.json"))
      );
    };

    checks.code_patch_score = Boolean(
      refused("code_patch_missing_permit", "PERMIT_REQUIRED") &&
        refused("code_patch_scope_violation", "PERMIT_SCOPE_VIOLATION") &&
        applied("code_patch_valid_apply"),
    );
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));

    const hasExec = (id) => fs.existsSync(path.join(outRoot, "fixtures", id, "test.execution.json"));
    const hasReceipt = (id) => fs.existsSync(path.join(outRoot, "fixtures", id, "test_receipt.json"));
    const hasResult = (id) => fs.existsSync(path.join(outRoot, "fixtures", id, "test.result.json"));

    const refused = (id, code) => {
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!fr || !exec) return false;
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === code &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        hasExec(id) &&
        !hasReceipt(id) &&
        !hasResult(id)
      );
    };

    const admitted = (id) => {
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!fr || !exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      const ledgerOk = parseJSONL(path.join(outRoot, "spe.ledger.jsonl")).some(
        (r) => r.fixture_id === id && r.kind === "code_test_run" && typeof r.test_receipt_hash_sha256 === "string",
      );
      return (
        fr?.decision?.status === "admitted" &&
        fr?.plan !== null &&
        exec?.executor_invoked === true &&
        exec?.execution_kind === "test_stub" &&
        hasExec(id) &&
        hasReceipt(id) &&
        hasResult(id) &&
        fs.existsSync(path.join(fixtureOut, "result.json")) &&
        ledgerOk
      );
    };

    checks.code_test_score = Boolean(
      refused("code_test_missing_permit", "PERMIT_REQUIRED") &&
        refused("code_test_cmd_not_allowed", "EXEC_CMD_NOT_ALLOWED") &&
        admitted("code_test_valid_mock"),
    );
  }

  if (source === "proxy" && packId === "TH-001C") {
    const freezeByFixture = new Map(freezeEntries.map((e) => [e.fixture_id, e]));

    const hasExec = (id) => fs.existsSync(path.join(outRoot, "fixtures", id, "deps.execution.json"));
    const hasReceipt = (id) => fs.existsSync(path.join(outRoot, "fixtures", id, "deps.receipt.json"));
    const hasResult = (id) => fs.existsSync(path.join(outRoot, "fixtures", id, "deps.result.json"));

    const refused = (id, code) => {
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!fr || !exec) return false;
      return (
        fr?.decision?.status === "rejected" &&
        fr?.reason_code === code &&
        fr?.plan === null &&
        exec?.executor_invoked === false &&
        hasExec(id) &&
        !hasReceipt(id) &&
        !hasResult(id)
      );
    };

    const admitted = (id) => {
      const fr = freezeByFixture.get(id);
      const exec = executionByFixture[id];
      if (!fr || !exec) return false;
      const fixtureOut = path.join(outRoot, "fixtures", id);
      const ledgerOk = parseJSONL(path.join(outRoot, "spe.ledger.jsonl")).some(
        (r) => r.fixture_id === id && r.kind === "code_deps_fetch" && typeof r.deps_receipt_hash_sha256 === "string",
      );
      return (
        fr?.decision?.status === "admitted" &&
        fr?.plan !== null &&
        exec?.executor_invoked === true &&
        exec?.execution_kind === "deps_stub" &&
        hasExec(id) &&
        hasReceipt(id) &&
        hasResult(id) &&
        fs.existsSync(path.join(fixtureOut, "result.json")) &&
        ledgerOk
      );
    };

    checks.deps_fetch_score = Boolean(
      refused("code_deps_missing_permit", "PERMIT_REQUIRED") &&
        refused("code_deps_lockfile_missing", "MISSING_LOCKFILE") &&
        refused("code_deps_egress_host_443_only", "EGRESS_DENIED") &&
        refused("code_deps_egress_url_host_443", "EGRESS_DENIED") &&
        admitted("code_deps_valid_mock"),
    );
  }

  const allOne = Object.values(checks).every(Boolean);
  metrics.refusal_rate = metric(checks.refusal_rate);
  metrics.escalation_detection_rate = metric(checks.escalation_detection_rate);
  metrics.plan_hash_integrity_score = metric(checks.plan_hash_integrity_score);
  metrics.lane_isolation_score = metric(checks.lane_isolation_score);
  metrics.substrate_mutation_block_score = metric(checks.substrate_mutation_block_score);
  metrics.no_side_effect_on_refusal_score = metric(checks.no_side_effect_on_refusal_score);
  metrics.no_absolute_path_leak_score = metric(checks.no_absolute_path_leak_score);
  metrics.toctou_block_score = metric(checks.toctou_block_score);
  metrics.replay_block_score = metric(checks.replay_block_score);
  metrics.supply_chain_block_score = metric(checks.supply_chain_block_score);
  metrics.supply_chain_evidence_score = metric(checks.supply_chain_evidence_score);
  metrics.hitl_gate_score = metric(checks.hitl_gate_score);
  metrics.hitl_authority_gate_score = metric(checks.hitl_authority_gate_score);
  metrics.hitl_quorum_gate_score = metric(checks.hitl_quorum_gate_score);
  if (source === "proxy" && packId === "TH-001C") {
    metrics.policy_version_binding_score = metric(checks.policy_version_binding_score);
    metrics.permit_gate_score = metric(checks.permit_gate_score);
    metrics.real_exec_sandbox_score = metric(checks.real_exec_sandbox_score);
    metrics.diff_preview_score = metric(checks.diff_preview_score);
    metrics.diff_permit_scope_score = metric(checks.diff_permit_scope_score);
    metrics.git_gate_score = metric(checks.git_gate_score);
    metrics.publish_draft_score = metric(checks.publish_draft_score);
    metrics.draft_commit_chain_score = metric(checks.draft_commit_chain_score);
    metrics.publish_post_gate_score = metric(checks.publish_post_gate_score);
    metrics.egress_gate_score = metric(checks.egress_gate_score);
    metrics.code_patch_score = metric(checks.code_patch_score);
    metrics.code_test_score = metric(checks.code_test_score);
    metrics.deps_fetch_score = metric(checks.deps_fetch_score);
  }
  metrics.pass = allOne;

  writeCanonicalJSON(path.join(outRoot, "metrics.json"), metrics);

  const metricsHash = sha256Stable(metrics);
  const planFreezeHash = sha256Stable(planFreeze);

  const ledgerRecords = parseJSONL(path.join(outRoot, "spe.ledger.jsonl"));
  const ledgerCanonical = ledgerCanonicalHash(ledgerRecords);
  const ledgerChain = ledgerChainHash(ledgerRecords);

  const artifactHashes = {
    pack_id: packId,
    run_id: runId,
    hashes: {
      metrics: metricsHash,
      plan_freeze: planFreezeHash,
      ledger_canonical: ledgerCanonical,
      ledger_chain: ledgerChain,
    },
    per_test: perTest,
  };

  writeCanonicalJSON(path.join(outRoot, "artifact.hashes.json"), artifactHashes);

  console.log(JSON.stringify({ pack_id: packId, run_id: runId, metrics }, null, 2));

  if (!metrics.pass) {
    process.exitCode = 1;
  }
}

function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    console.log(
      "Usage: node runner.mjs --pack PACK_JSON --run-id RUN_ID --attest mock|live --source fixture|proxy --git mock|live --exec mock|live --deps mock|live --now ISO8601",
    );
    process.exit(0);
  }
  const mode = args.attest === "live" ? "live" : "mock";
  const src = args.source === "proxy" ? "proxy" : "fixture";
  runPack({
    packPath: args.pack,
    runId: args.run_id,
    attestMode: mode,
    source: src,
    gitMode: args.git === "live" ? "live" : "mock",
    execMode: args.exec === "live" ? "live" : "mock",
    depsMode: args.deps === "live" ? "live" : "mock",
    nowOverrideIso: args.now,
  });
}

main();
