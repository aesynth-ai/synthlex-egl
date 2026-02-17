import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

function readJSON(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function readJSONL(p) {
  return fs
    .readFileSync(p, "utf8")
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));
}

function hasAbsWindowsPathString(s) {
  if (typeof s !== "string") return false;
  return /^[a-zA-Z]:\\/.test(s) || /^\\\\/.test(s) || /[a-zA-Z]:\\/.test(s);
}

function sha256Hex(bytesOrString) {
  const b = typeof bytesOrString === "string" ? Buffer.from(bytesOrString, "utf8") : bytesOrString;
  return createHash("sha256").update(b).digest("hex");
}

function expectedEnvelopeCoreFromToolCall(toolCall) {
  const tool_call_id = String(toolCall?.id ?? toolCall?.call_id ?? "");
  const tool_name = String(toolCall?.tool ?? toolCall?.name ?? "");
  const args = {};
  for (const [k, v] of Object.entries(toolCall ?? {})) {
    if (k === "tool" || k === "name" || k === "id" || k === "call_id") continue;
    args[k] = v;
  }
  return {
    session_id: "proxy",
    lane_id: "proxy",
    tool_call_id,
    tool_name,
    args,
    agent_id: "proxy",
    channel: "cli",
    origin: "proxy",
  };
}

function run(packPath, runId) {
  const r = spawnSync(
    process.execPath,
    ["runner.mjs", "--pack", packPath, "--run-id", runId, "--attest", "mock", "--source", "proxy"],
    { stdio: "inherit" },
  );
  if (r.status !== 0) {
    throw new Error(`runner failed for run ${runId} with status ${r.status}`);
  }
}

function main() {
  const packPath = process.argv.includes("--pack")
    ? process.argv[process.argv.indexOf("--pack") + 1]
    : "tests/packs/TH-001C.pack.json";

  const runA = process.argv.includes("--runA") ? process.argv[process.argv.indexOf("--runA") + 1] : "A";
  const runB = process.argv.includes("--runB") ? process.argv[process.argv.indexOf("--runB") + 1] : "B";

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
  if (!fs.existsSync(goldenPath)) {
    diffs.push("missing_golden_pins");
  } else {
    const golden = readJSON(goldenPath);
    if (a.hashes.plan_freeze !== golden.expected.plan_freeze) diffs.push("golden.plan_freeze");
    if (a.hashes.ledger_canonical !== golden.expected.ledger_canonical) diffs.push("golden.ledger_canonical");
  }

  // Envelope artifact existence + absolute-path ban.
  for (const [fixtureId, fixturePath] of Object.entries(pack.fixtures ?? {})) {
    const envPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "envelope.json");
    if (!fs.existsSync(envPath)) {
      diffs.push(`envelope_missing:${fixtureId}`);
      continue;
    }
    const envRaw = fs.readFileSync(envPath, "utf8");
    if (hasAbsWindowsPathString(envRaw)) {
      diffs.push(`envelope_abs_path:${fixtureId}`);
    }
    const envelope = JSON.parse(envRaw);
    if (envelope.origin !== "proxy") diffs.push(`envelope_origin:${fixtureId}`);

    const fixtureToolCall = readJSON(path.resolve(fixturePath));
    const expectedCore = expectedEnvelopeCoreFromToolCall(fixtureToolCall);
    if (envelope.tool_call_id !== expectedCore.tool_call_id) diffs.push(`envelope_tool_call_id:${fixtureId}`);
    if (envelope.tool_name !== expectedCore.tool_name) diffs.push(`envelope_tool_name:${fixtureId}`);

    const ioPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "io.json");
    const io = readJSON(ioPath);
    if (!io.envelope) diffs.push(`io_missing_envelope:${fixtureId}`);
    else if (io.envelope.tool_call_id !== envelope.tool_call_id) diffs.push(`io_envelope_mismatch:${fixtureId}`);

    const execPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "execution.json");
    if (!fs.existsSync(execPath)) {
      diffs.push(`execution_missing:${fixtureId}`);
      continue;
    }
    const execution = readJSON(execPath);

    const decisionPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json");
    const decision = readJSON(decisionPath);
    const admitted = decision.status === "admitted";

    const resultPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "result.json");
    const resultExists = fs.existsSync(resultPath);

    if (admitted) {
      const isSkillInstallAdmit = decision.reason_code === "HITL_QUORUM_ACCEPTED";
      if (isSkillInstallAdmit) {
        if (execution.executor_invoked !== false) diffs.push(`execution_invoked:${fixtureId}`);
        if (execution.execution_kind !== null) diffs.push(`execution_kind:${fixtureId}`);
        if (execution.result_hash_sha256 !== null) diffs.push(`result_hash:${fixtureId}`);
        if (resultExists) diffs.push(`result_present_on_skill_install:${fixtureId}`);
      } else {
        if (execution.executor_invoked !== true) diffs.push(`execution_invoked:${fixtureId}`);
        const expectedKind =
          envelope.tool_name === "browser.navigate"
            ? "net_stub"
            : envelope.tool_name === "code.test.run"
              ? "test_stub"
              : envelope.tool_name === "code.deps.fetch"
                ? "deps_stub"
              : "real_sandbox";
        if (execution.execution_kind !== expectedKind) diffs.push(`execution_kind:${fixtureId}`);
        if (!resultExists) diffs.push(`result_missing:${fixtureId}`);
        else {
          const resultRaw = fs.readFileSync(resultPath, "utf8");
          const h = sha256Hex(resultRaw);
          if (execution.result_hash_sha256 !== h) diffs.push(`result_hash:${fixtureId}`);
        }
      }
    } else {
      if (execution.executor_invoked !== false) diffs.push(`execution_invoked_on_refusal:${fixtureId}`);
      if (execution.execution_kind !== null) diffs.push(`execution_kind_on_refusal:${fixtureId}`);
      if (execution.result_hash_sha256 !== null) diffs.push(`result_hash_on_refusal:${fixtureId}`);
      if (resultExists) diffs.push(`result_present_on_refusal:${fixtureId}`);
    }
  }

  // Unmapped tool evidence (ledger + per_test).
  const ledgerA = readJSONL(path.resolve("out", packId, runA, "spe.ledger.jsonl"));
  const hasUnmapped = ledgerA.some(
    (r) => r.fixture_id === "unmapped_tool" && r.kind === "refusal" && r.reason_code === "UNMAPPED_TOOL_SURFACE",
  );
  if (!hasUnmapped) diffs.push("ledger_missing:unmapped_tool");
  if (!a.per_test?.unmapped_tool) diffs.push("per_test_missing:unmapped_tool");
  const freezeA = readJSON(path.resolve("out", packId, runA, "plan.freeze.json"));
  const byFixture = new Map((freezeA.plans ?? []).map((p) => [p.fixture_id, p]));
  const entry = byFixture.get("unmapped_tool");
  if (!entry) diffs.push("freeze_missing:unmapped_tool");
  else {
    if (entry.reason_code !== "UNMAPPED_TOOL_SURFACE") diffs.push("freeze_code:unmapped_tool");
    if (entry.plan !== null) diffs.push("freeze_plan_not_null:unmapped_tool");
  }

  const laneEntry = byFixture.get("lane_mismatch");
  if (!laneEntry) diffs.push("freeze_missing:lane_mismatch");
  else {
    if (laneEntry.reason_code !== "LANE_MISMATCH") diffs.push("freeze_code:lane_mismatch");
    if (laneEntry.plan !== null) diffs.push("freeze_plan_not_null:lane_mismatch");
  }

  const expEntry = byFixture.get("plan_expired");
  if (!expEntry) diffs.push("freeze_missing:plan_expired");
  else {
    if (expEntry.reason_code !== "PLAN_EXPIRED") diffs.push("freeze_code:plan_expired");
    if (expEntry.plan !== null) diffs.push("freeze_plan_not_null:plan_expired");
  }

  // Step-16: permit gating on real sandbox execution.
  {
    const expectedPermit = {
      exec_permit_write_missing: { status: "rejected", reason_code: "PERMIT_REQUIRED" },
      exec_permit_write_invalid_hash: { status: "rejected", reason_code: "INVALID_PERMIT" },
      exec_permit_write_binding_mismatch: { status: "rejected", reason_code: "PERMIT_BINDING_MISMATCH" },
      exec_permit_write_scope_violation: { status: "rejected", reason_code: "PERMIT_SCOPE_VIOLATION" },
    };

    for (const [fixtureId, exp] of Object.entries(expectedPermit)) {
      const entry = byFixture.get(fixtureId);
      if (!entry) {
        diffs.push(`freeze_missing:${fixtureId}`);
        continue;
      }
      if (entry.decision?.status !== exp.status) diffs.push(`freeze_status:${fixtureId}`);
      if (entry.reason_code !== exp.reason_code) diffs.push(`freeze_code:${fixtureId}`);
      if (entry.plan !== null) diffs.push(`freeze_plan_not_null:${fixtureId}`);

      const execPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "execution.json");
      if (!fs.existsSync(execPath)) diffs.push(`execution_missing:${fixtureId}`);
      else {
        const ex = readJSON(execPath);
        if (ex.executor_invoked !== false) diffs.push(`execution_invoked_on_refusal:${fixtureId}`);
        if (ex.side_effect_detected !== false) diffs.push(`side_effect_on_refusal:${fixtureId}`);
      }

      const permitValPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "permit.validation.json");
      if (!fs.existsSync(permitValPath)) diffs.push(`permit_validation_missing:${fixtureId}`);

      const resultPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "result.json");
      if (fs.existsSync(resultPath)) diffs.push(`result_present_on_refusal:${fixtureId}`);

      const receiptPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "file_receipt.json");
      if (fs.existsSync(receiptPath)) diffs.push(`file_receipt_present_on_refusal:${fixtureId}`);
    }

    // Valid permit => real sandbox write executes and emits receipt.
    {
      const fixtureId = "exec_permit_write_valid";
      const entry = byFixture.get(fixtureId);
      if (!entry) diffs.push(`freeze_missing:${fixtureId}`);
      else {
        if (entry.decision?.status !== "admitted") diffs.push(`freeze_status:${fixtureId}`);
        if (entry.plan === null) diffs.push(`freeze_plan_null:${fixtureId}`);
      }

      const execPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "execution.json");
      if (!fs.existsSync(execPath)) diffs.push(`execution_missing:${fixtureId}`);
      else {
        const ex = readJSON(execPath);
        if (ex.executor_invoked !== true) diffs.push(`execution_not_invoked:${fixtureId}`);
        if (ex.execution_kind !== "real_sandbox") diffs.push(`execution_kind:${fixtureId}`);
        if (ex.side_effect_detected !== true) diffs.push(`side_effect_missing:${fixtureId}`);
      }

      const previewPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "diff.preview.json");
      if (!fs.existsSync(previewPath)) diffs.push(`diff_preview_missing:${fixtureId}`);

      const permitValPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "permit.validation.json");
      if (!fs.existsSync(permitValPath)) diffs.push(`permit_validation_missing:${fixtureId}`);
      else {
        const pv = readJSON(permitValPath);
        if (pv.ok !== true) diffs.push(`permit_validation_not_ok:${fixtureId}`);
      }

      const resultPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "result.json");
      if (!fs.existsSync(resultPath)) diffs.push(`result_missing:${fixtureId}`);

      const receiptPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "file_receipt.json");
      if (!fs.existsSync(receiptPath)) diffs.push(`file_receipt_missing:${fixtureId}`);

      const targetAbs = path.resolve("sandbox", "_th_tmp", "permit_test.txt");
      if (!fs.existsSync(targetAbs)) diffs.push("sandbox_file_missing:permit_test.txt");

      if (fs.existsSync(receiptPath)) {
        const r = readJSON(receiptPath);
        if (typeof r.permit_sha256 !== "string" || r.permit_sha256.length === 0) diffs.push(`receipt_permit_sha256:${fixtureId}`);
        if (typeof r.law_bundle_sha256 !== "string" || r.law_bundle_sha256.length === 0) diffs.push(`receipt_law_bundle_sha256:${fixtureId}`);
        if (typeof r.plan_hash !== "string" || r.plan_hash.length === 0) diffs.push(`receipt_plan_hash:${fixtureId}`);
        if (typeof r.intent_hash !== "string" || r.intent_hash.length === 0) diffs.push(`receipt_intent_hash:${fixtureId}`);
        if (typeof r.diff_sha256 !== "string" || r.diff_sha256.length === 0) diffs.push(`receipt_diff_sha256:${fixtureId}`);
        if (typeof r.diff_preview_hash_sha256 !== "string" || r.diff_preview_hash_sha256.length === 0) diffs.push(`receipt_diff_preview_hash:${fixtureId}`);
      }
    }
  }

  const policyEntry = byFixture.get("policy_version_mismatch");
  if (!policyEntry) diffs.push("freeze_missing:policy_version_mismatch");
  else {
    if (policyEntry.reason_code !== "POLICY_VERSION_MISMATCH") diffs.push("freeze_code:policy_version_mismatch");
    if (policyEntry.plan !== null) diffs.push("freeze_plan_not_null:policy_version_mismatch");
  }

  // Step-17: diff preview + permit-scoped patch application fixtures.
  {
    const expected = {
      diff_write_preview_only: { status: "rejected", reason_code: "PERMIT_OP_NOT_ALLOWED" },
      diff_write_too_large: { status: "rejected", reason_code: "DIFF_TOO_LARGE" },
      diff_write_valid_apply: { status: "admitted", reason_code: null },
    };

    for (const [fixtureId, exp] of Object.entries(expected)) {
      const entry = byFixture.get(fixtureId);
      if (!entry) {
        diffs.push(`freeze_missing:${fixtureId}`);
        continue;
      }

      const previewPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "diff.preview.json");
      if (!fs.existsSync(previewPath)) diffs.push(`diff_preview_missing:${fixtureId}`);

      if (entry.decision?.status !== exp.status) diffs.push(`freeze_status:${fixtureId}`);
      if (exp.reason_code && entry.reason_code !== exp.reason_code) diffs.push(`freeze_code:${fixtureId}`);

      const execPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "execution.json");
      if (!fs.existsSync(execPath)) diffs.push(`execution_missing:${fixtureId}`);
      else {
        const ex = readJSON(execPath);
        if (exp.status === "admitted") {
          if (ex.executor_invoked !== true) diffs.push(`execution_not_invoked:${fixtureId}`);
          if (ex.execution_kind !== "real_sandbox") diffs.push(`execution_kind:${fixtureId}`);
        } else {
          if (ex.executor_invoked !== false) diffs.push(`execution_invoked_on_refusal:${fixtureId}`);
          if (ex.side_effect_detected !== false) diffs.push(`side_effect_on_refusal:${fixtureId}`);
        }
      }

      const resultPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "result.json");
      const receiptPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "file_receipt.json");

      if (exp.status === "admitted") {
        if (!fs.existsSync(resultPath)) diffs.push(`result_missing:${fixtureId}`);
        if (!fs.existsSync(receiptPath)) diffs.push(`file_receipt_missing:${fixtureId}`);
        else {
          const r = readJSON(receiptPath);
          if (typeof r.diff_sha256 !== "string" || r.diff_sha256.length === 0) diffs.push(`receipt_diff_sha256:${fixtureId}`);
          if (typeof r.diff_preview_hash_sha256 !== "string" || r.diff_preview_hash_sha256.length === 0) diffs.push(`receipt_diff_preview_hash:${fixtureId}`);
        }
      } else {
        if (fs.existsSync(resultPath)) diffs.push(`result_present_on_refusal:${fixtureId}`);
        if (fs.existsSync(receiptPath)) diffs.push(`file_receipt_present_on_refusal:${fixtureId}`);
      }
    }

    const ledgerHas = (fixtureId) =>
      ledgerA.some((r) => r.fixture_id === fixtureId && (r.kind === "refusal" || r.kind === "admission") && typeof r.diff_sha256 === "string" && typeof r.diff_preview_hash_sha256 === "string");

    if (!ledgerHas("diff_write_preview_only")) diffs.push("ledger_missing:diff_write_preview_only");
    if (!ledgerHas("diff_write_too_large")) diffs.push("ledger_missing:diff_write_too_large");
    if (!ledgerHas("diff_write_valid_apply")) diffs.push("ledger_missing:diff_write_valid_apply");
  }

  const hasLane = ledgerA.some(
    (r) => r.fixture_id === "lane_mismatch" && r.kind === "refusal" && r.reason_code === "LANE_MISMATCH",
  );
  if (!hasLane) diffs.push("ledger_missing:lane_mismatch");

  const hasExpired = ledgerA.some(
    (r) => r.fixture_id === "plan_expired" && r.kind === "refusal" && r.reason_code === "PLAN_EXPIRED",
  );
  if (!hasExpired) diffs.push("ledger_missing:plan_expired");

  const hasPolicyMismatch = ledgerA.some(
    (r) =>
      r.fixture_id === "policy_version_mismatch" &&
      r.kind === "refusal" &&
      r.reason_code === "POLICY_VERSION_MISMATCH" &&
      typeof r.expected_law_bundle_sha256 === "string" &&
      typeof r.actual_law_bundle_sha256 === "string" &&
      r.expected_law_bundle_sha256 !== r.actual_law_bundle_sha256,
  );
  if (!hasPolicyMismatch) diffs.push("ledger_missing:policy_version_mismatch");

  const expectedSupply = {
    skill_install_no_diff: { status: "rejected", reason_code: "MISSING_CAPABILITY_DIFF" },
    skill_install_hash_mismatch: { status: "rejected", reason_code: "ARTIFACT_HASH_MISMATCH" },
    skill_install_defer_ok: { status: "rejected", reason_code: "HITL_REQUIRED_SURFACE_EXPANSION" },
    skill_install_egress_host_only: { status: "rejected", reason_code: "HITL_REQUIRED_SURFACE_EXPANSION" },
    skill_install_egress_host_443: { status: "rejected", reason_code: "HITL_REQUIRED_SURFACE_EXPANSION" },
    skill_install_egress_url_host_only: { status: "rejected", reason_code: "HITL_REQUIRED_SURFACE_EXPANSION" },
    skill_install_egress_url_host_443: { status: "rejected", reason_code: "HITL_REQUIRED_SURFACE_EXPANSION" },
    skill_install_token_missing: { status: "rejected", reason_code: "HITL_REQUIRED_SURFACE_EXPANSION" },
    skill_install_token_invalid: { status: "rejected", reason_code: "HITL_TOKEN_BINDING_MISMATCH" },
    skill_install_token_valid: { status: "rejected", reason_code: "HITL_QUORUM_NOT_MET" },
    skill_install_token_authority_drift: { status: "rejected", reason_code: "HITL_AUTHORITY_DIFF_MISMATCH" },
    skill_install_quorum_missing: { status: "rejected", reason_code: "HITL_REQUIRED_SURFACE_EXPANSION" },
    skill_install_quorum_one_token: { status: "rejected", reason_code: "HITL_QUORUM_NOT_MET" },
    skill_install_quorum_duplicate_approver: { status: "rejected", reason_code: "HITL_DUPLICATE_APPROVER" },
  };
  for (const [fixtureId, exp] of Object.entries(expectedSupply)) {
    const entry = byFixture.get(fixtureId);
    if (!entry) {
      diffs.push(`freeze_missing:${fixtureId}`);
      continue;
    }
    if (entry.decision?.status !== exp.status) diffs.push(`freeze_status:${fixtureId}`);
    if (entry.reason_code !== exp.reason_code) diffs.push(`freeze_code:${fixtureId}`);
    if (entry.plan !== null) diffs.push(`freeze_plan_not_null:${fixtureId}`);

    const execPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "execution.json");
    if (!fs.existsSync(execPath)) diffs.push(`execution_missing:${fixtureId}`);
    else {
      const ex = readJSON(execPath);
      if (ex.executor_invoked !== false) diffs.push(`execution_invoked_on_refusal:${fixtureId}`);
    }

    const ledgerOk = ledgerA.some(
      (r) => r.fixture_id === fixtureId && r.kind === "refusal" && r.reason_code === exp.reason_code,
    );
    if (!ledgerOk) diffs.push(`ledger_missing:${fixtureId}`);

    const scePath = path.resolve("out", packId, runA, "fixtures", fixtureId, "sce.json");
    if (!fs.existsSync(scePath)) diffs.push(`sce_missing:${fixtureId}`);
    else {
      const sceRaw = fs.readFileSync(scePath, "utf8");
      if (sceRaw.includes("\n")) diffs.push(`sce_not_minified:${fixtureId}`);
      const sceHash = sha256Hex(sceRaw);
      const rec = ledgerA.find(
        (r) => r.fixture_id === fixtureId && r.kind === "refusal" && r.reason_code === exp.reason_code,
      );
      if (!rec || rec.sce_hash_sha256 !== sceHash) diffs.push(`sce_hash_mismatch:${fixtureId}`);
    }

    const ioPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "io.json");
    const ioRaw = fs.readFileSync(ioPath, "utf8");
    if (ioRaw.includes("bytes_b64")) diffs.push(`io_contains_bytes:${fixtureId}`);
    if (ioRaw.includes("\"env\"")) diffs.push(`io_contains_env:${fixtureId}`);
    if (
      ioRaw.includes("\"ratification_token\"") ||
      ioRaw.includes("\"ratification_tokens\"") ||
      ioRaw.includes("EGL.RATIFICATION_TOKEN")
    ) {
      diffs.push(`io_contains_token:${fixtureId}`);
    }

    const resultPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "result.json");
    if (fs.existsSync(resultPath)) diffs.push(`result_present_on_refusal:${fixtureId}`);
  }

  // Host-only egress normalization: "Example.COM" => "example.com" (no implicit port) in authority diff.
  {
    const fixtureId = "skill_install_egress_host_only";
    const authPath = path.resolve(
      "out",
      packId,
      runA,
      "fixtures",
      fixtureId,
      "authority_diff_canonical.json",
    );
    if (!fs.existsSync(authPath)) diffs.push(`authority_diff_missing:${fixtureId}`);
    else {
      const authRaw = fs.readFileSync(authPath, "utf8");
      const auth = JSON.parse(authRaw);
      const e = Array.isArray(auth?.adds_egress) ? auth.adds_egress : [];
      if (e.length !== 1 || e[0] !== "example.com") diffs.push(`authority_diff_egress_norm:${fixtureId}`);

      const scePath = path.resolve("out", packId, runA, "fixtures", fixtureId, "sce.json");
      if (!fs.existsSync(scePath)) diffs.push(`sce_missing:${fixtureId}`);
      else {
        const sce = readJSON(scePath);
        const expectedAuthSha = sha256Hex(authRaw);
        const got = sce?.capability?.authority_diff_sha256 ?? null;
        if (got !== expectedAuthSha) diffs.push(`authority_diff_sha_mismatch:${fixtureId}`);
      }
    }
  }

  // Explicit-port egress normalization: "Example.COM:443" => "example.com:443" (port preserved).
  {
    const fixtureId = "skill_install_egress_host_443";
    const authPath = path.resolve(
      "out",
      packId,
      runA,
      "fixtures",
      fixtureId,
      "authority_diff_canonical.json",
    );
    if (!fs.existsSync(authPath)) diffs.push(`authority_diff_missing:${fixtureId}`);
    else {
      const authRaw = fs.readFileSync(authPath, "utf8");
      const auth = JSON.parse(authRaw);
      const e = Array.isArray(auth?.adds_egress) ? auth.adds_egress : [];
      if (e.length !== 1 || e[0] !== "example.com:443") diffs.push(`authority_diff_egress_norm:${fixtureId}`);

      const scePath = path.resolve("out", packId, runA, "fixtures", fixtureId, "sce.json");
      if (!fs.existsSync(scePath)) diffs.push(`sce_missing:${fixtureId}`);
      else {
        const sce = readJSON(scePath);
        const expectedAuthSha = sha256Hex(authRaw);
        const got = sce?.capability?.authority_diff_sha256 ?? null;
        if (got !== expectedAuthSha) diffs.push(`authority_diff_sha_mismatch:${fixtureId}`);
      }
    }
  }

  // Ensure host-only and explicit-port egress grants stay distinct at the digest layer.
  {
    const hostOnlyPath = path.resolve(
      "out",
      packId,
      runA,
      "fixtures",
      "skill_install_egress_host_only",
      "authority_diff_canonical.json",
    );
    const host443Path = path.resolve(
      "out",
      packId,
      runA,
      "fixtures",
      "skill_install_egress_host_443",
      "authority_diff_canonical.json",
    );
    if (fs.existsSync(hostOnlyPath) && fs.existsSync(host443Path)) {
      const a = sha256Hex(fs.readFileSync(hostOnlyPath, "utf8"));
      const b = sha256Hex(fs.readFileSync(host443Path, "utf8"));
      if (a === b) diffs.push("authority_diff_host_only_equals_host_443");
    }
  }

  // URL ambiguity normalization: URL host-only vs URL explicit-port must be deterministic and distinct.
  {
    const fixtureHostOnly = "skill_install_egress_url_host_only";
    const fixtureHost443 = "skill_install_egress_url_host_443";

    const hostOnlyPath = path.resolve("out", packId, runA, "fixtures", fixtureHostOnly, "authority_diff_canonical.json");
    const host443Path = path.resolve("out", packId, runA, "fixtures", fixtureHost443, "authority_diff_canonical.json");

    if (!fs.existsSync(hostOnlyPath)) diffs.push(`authority_diff_missing:${fixtureHostOnly}`);
    if (!fs.existsSync(host443Path)) diffs.push(`authority_diff_missing:${fixtureHost443}`);

    if (fs.existsSync(hostOnlyPath)) {
      const raw = fs.readFileSync(hostOnlyPath, "utf8");
      const auth = JSON.parse(raw);
      const e = Array.isArray(auth?.adds_egress) ? auth.adds_egress : [];
      if (e.length !== 1 || e[0] !== "example.com") diffs.push(`authority_diff_egress_norm:${fixtureHostOnly}`);
      const scePath = path.resolve("out", packId, runA, "fixtures", fixtureHostOnly, "sce.json");
      if (!fs.existsSync(scePath)) diffs.push(`sce_missing:${fixtureHostOnly}`);
      else {
        const sce = readJSON(scePath);
        const expectedAuthSha = sha256Hex(raw);
        const got = sce?.capability?.authority_diff_sha256 ?? null;
        if (got !== expectedAuthSha) diffs.push(`authority_diff_sha_mismatch:${fixtureHostOnly}`);
      }
    }

    if (fs.existsSync(host443Path)) {
      const raw = fs.readFileSync(host443Path, "utf8");
      const auth = JSON.parse(raw);
      const e = Array.isArray(auth?.adds_egress) ? auth.adds_egress : [];
      if (e.length !== 1 || e[0] !== "example.com:443") diffs.push(`authority_diff_egress_norm:${fixtureHost443}`);
      const scePath = path.resolve("out", packId, runA, "fixtures", fixtureHost443, "sce.json");
      if (!fs.existsSync(scePath)) diffs.push(`sce_missing:${fixtureHost443}`);
      else {
        const sce = readJSON(scePath);
        const expectedAuthSha = sha256Hex(raw);
        const got = sce?.capability?.authority_diff_sha256 ?? null;
        if (got !== expectedAuthSha) diffs.push(`authority_diff_sha_mismatch:${fixtureHost443}`);
      }
    }

    if (fs.existsSync(hostOnlyPath) && fs.existsSync(host443Path)) {
      const a = sha256Hex(fs.readFileSync(hostOnlyPath, "utf8"));
      const b = sha256Hex(fs.readFileSync(host443Path, "utf8"));
      if (a === b) diffs.push("authority_diff_url_host_only_equals_url_host_443");
    }
  }

  // Step-15: Law bundle artifact + binding hashes (plan freeze + ledger + execution evidence).
  {
    const bundlePath = path.resolve("out", packId, runA, "law.bundle.json");
    const bundleHashPath = path.resolve("out", packId, runA, "law.bundle.hash.json");
    if (!fs.existsSync(bundlePath)) diffs.push("law_bundle_missing");
    if (!fs.existsSync(bundleHashPath)) diffs.push("law_bundle_hash_missing");
    if (fs.existsSync(bundlePath)) {
      try {
        const b = readJSON(bundlePath);
        if (b?.schema_id !== "EGL.LAW_BUNDLE") diffs.push("law_bundle_schema");
        if (b?.version !== "0.1.0") diffs.push("law_bundle_version");
      } catch {
        diffs.push("law_bundle_parse");
      }
    }

    const hasFreezeBinding = freezeA.plans.some(
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
    if (!hasFreezeBinding) diffs.push("freeze_missing:binding");

    const hasLedgerBinding = ledgerA.some(
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
    if (!hasLedgerBinding) diffs.push("ledger_missing:binding");

    const anyExecHasBinding = Object.keys(pack.fixtures ?? {}).some((fixtureId) => {
      const execPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "execution.json");
      if (!fs.existsSync(execPath)) return false;
      try {
        const ex = readJSON(execPath);
        return typeof ex?.binding?.law_bundle_sha256 === "string" && ex.binding.law_bundle_sha256.length > 0;
      } catch {
        return false;
      }
    });
    if (!anyExecHasBinding) diffs.push("execution_missing:binding");
  }

  // Step-13: quorum accepted transitions to admitted (stub-only) and emits a deterministic receipt.
  {
    const fixtureId = "skill_install_quorum_two_tokens";
    const entry = byFixture.get(fixtureId);
    if (!entry) diffs.push(`freeze_missing:${fixtureId}`);
    else {
      if (entry.decision?.status !== "admitted") diffs.push(`freeze_status:${fixtureId}`);
      if (entry.reason_code !== "HITL_QUORUM_ACCEPTED") diffs.push(`freeze_code:${fixtureId}`);
      if (entry.plan === null) diffs.push(`freeze_plan_null:${fixtureId}`);
    }

    const execPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "execution.json");
    if (!fs.existsSync(execPath)) diffs.push(`execution_missing:${fixtureId}`);
    else {
      const ex = readJSON(execPath);
      if (ex.executor_invoked !== false) diffs.push(`execution_invoked_on_skill_install:${fixtureId}`);
    }

    const resultPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "result.json");
    if (fs.existsSync(resultPath)) diffs.push(`result_present_on_skill_install:${fixtureId}`);

    const receiptPath = path.resolve(
      "out",
      packId,
      runA,
      "fixtures",
      fixtureId,
      "skill_install_stub_receipt.json",
    );
    if (!fs.existsSync(receiptPath)) diffs.push(`receipt_missing:${fixtureId}`);
    else {
      const raw = fs.readFileSync(receiptPath, "utf8");
      if (raw.includes("\n")) diffs.push(`receipt_not_minified:${fixtureId}`);
      const receiptHash = sha256Hex(raw);
      const rec = ledgerA.find((r) => r.fixture_id === fixtureId && r.kind === "admission");
      if (!rec || rec.skill_install_stub_receipt_hash_sha256 !== receiptHash) {
        diffs.push(`receipt_hash_mismatch:${fixtureId}`);
      }
      if (!rec || !Array.isArray(rec.ratification_token_hashes) || rec.ratification_token_hashes.length !== 2) {
        diffs.push(`token_hash_missing:${fixtureId}`);
      }
      if (!rec || !Array.isArray(rec.ratification_approvers) || rec.ratification_approvers.length !== 2) {
        diffs.push(`token_approvers_missing:${fixtureId}`);
      }
      if (rec?.ratification_quorum_required !== 2 || rec?.ratification_quorum_met !== true) {
        diffs.push(`quorum_flags:${fixtureId}`);
      }
    }

    const scePath = path.resolve("out", packId, runA, "fixtures", fixtureId, "sce.json");
    if (!fs.existsSync(scePath)) diffs.push(`sce_missing:${fixtureId}`);
    else {
      const sceRaw = fs.readFileSync(scePath, "utf8");
      if (sceRaw.includes("\n")) diffs.push(`sce_not_minified:${fixtureId}`);
      const sceHash = sha256Hex(sceRaw);
      const rec = ledgerA.find((r) => r.fixture_id === fixtureId && r.kind === "admission");
      if (!rec || rec.sce_hash_sha256 !== sceHash) diffs.push(`sce_hash_mismatch:${fixtureId}`);
    }

    const ioPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "io.json");
    const ioRaw = fs.readFileSync(ioPath, "utf8");
    if (ioRaw.includes("bytes_b64")) diffs.push(`io_contains_bytes:${fixtureId}`);
    if (ioRaw.includes("\"env\"")) diffs.push(`io_contains_env:${fixtureId}`);
    if (
      ioRaw.includes("\"ratification_token\"") ||
      ioRaw.includes("\"ratification_tokens\"") ||
      ioRaw.includes("EGL.RATIFICATION_TOKEN")
    ) {
      diffs.push(`io_contains_token:${fixtureId}`);
    }
  }

  // Step-18: Governed git surface is gated in mock mode (no side effects, no receipt).
  {
    const cases = [
      ["git_pipeline_missing_permit", "PERMIT_REQUIRED", "REFUSE_HARD"],
      ["git_pipeline_invalid_permit", "INVALID_PERMIT", "REFUSE_HARD"],
      ["git_pipeline_no_token", "HITL_REQUIRED_GIT_COMMIT", "DEFER_HITL"],
      ["git_pipeline_token_valid", "HITL_REQUIRED_GIT_COMMIT", "DEFER_HITL"],
    ];

    for (const [fixtureId, reason, refusalStatus] of cases) {
      const decPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json");
      if (!fs.existsSync(decPath)) {
        diffs.push(`decision_missing:${fixtureId}`);
        continue;
      }
      const decision = readJSON(decPath);
      if (decision.status !== "rejected") diffs.push(`git_decision_status:${fixtureId}`);
      if (decision.reason_code !== reason) diffs.push(`git_reason_code:${fixtureId}`);
      if (decision.refusal_status !== refusalStatus) diffs.push(`git_refusal_status:${fixtureId}`);

      const gitExecPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "git.execution.json");
      if (!fs.existsSync(gitExecPath)) {
        diffs.push(`git_execution_missing:${fixtureId}`);
      } else {
        const ge = readJSON(gitExecPath);
        if (ge.branch_created !== false) diffs.push(`git_side_effect_branch:${fixtureId}`);
        if (ge.patch_applied !== false) diffs.push(`git_side_effect_patch:${fixtureId}`);
        if (ge.staged !== false) diffs.push(`git_side_effect_stage:${fixtureId}`);
        if (ge.commit_created !== false) diffs.push(`git_side_effect_commit:${fixtureId}`);
      }

      const receiptPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "git.receipt.json");
      if (fs.existsSync(receiptPath)) diffs.push(`git_receipt_present:${fixtureId}`);

      const ioPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "io.json");
      const ioRaw = fs.readFileSync(ioPath, "utf8");
      if (ioRaw.includes("\"ratification_token\"") || ioRaw.includes("EGL.GIT_RATIFICATION_TOKEN")) {
        diffs.push(`io_contains_git_token:${fixtureId}`);
      }
    }
  }

  // Step-19: Publish draft creation is sandbox-only, diff-first, permit-bounded, provenance-bound.
  {
    // Missing permit => hard refusal, no preview.
    {
      const fixtureId = "publish_draft_create_missing_permit";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "rejected") diffs.push(`publish_status:${fixtureId}`);
      if (dec.reason_code !== "PERMIT_REQUIRED") diffs.push(`publish_reason:${fixtureId}`);
      if (dec.refusal_status !== "REFUSE_HARD") diffs.push(`publish_refusal_status:${fixtureId}`);
      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (fs.existsSync(path.join(fixtureOut, "diff.preview.json"))) diffs.push(`publish_preview_present:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "result.json"))) diffs.push(`publish_result_present:${fixtureId}`);
    }

    // Preview-only => preview exists, refusal PERMIT_OP_NOT_ALLOWED, no side effects.
    {
      const fixtureId = "publish_draft_create_preview_only";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "rejected") diffs.push(`publish_status:${fixtureId}`);
      if (dec.reason_code !== "PERMIT_OP_NOT_ALLOWED") diffs.push(`publish_reason:${fixtureId}`);
      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (!fs.existsSync(path.join(fixtureOut, "diff.preview.json"))) diffs.push(`publish_preview_missing:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "result.json"))) diffs.push(`publish_result_present:${fixtureId}`);
    }

    // Too-large => preview exists, refusal DIFF_TOO_LARGE.
    {
      const fixtureId = "publish_draft_create_too_large";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "rejected") diffs.push(`publish_status:${fixtureId}`);
      if (dec.reason_code !== "DIFF_TOO_LARGE") diffs.push(`publish_reason:${fixtureId}`);
      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (!fs.existsSync(path.join(fixtureOut, "diff.preview.json"))) diffs.push(`publish_preview_missing:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "result.json"))) diffs.push(`publish_result_present:${fixtureId}`);
    }

    // Valid => draft file exists under sandbox/_publish_drafts/, receipt emitted, ledger has publish_draft record.
    {
      const fixtureId = "publish_draft_create_valid";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "admitted") diffs.push(`publish_status:${fixtureId}`);

      const freezeEntry = byFixture.get(fixtureId);
      const draftPath = freezeEntry?.plan?.actions?.[0]?.file?.path;
      if (typeof draftPath !== "string" || !draftPath.startsWith("sandbox/_publish_drafts/")) {
        diffs.push(`publish_draft_path:${fixtureId}`);
      } else {
        const abs = path.resolve(draftPath);
        if (!fs.existsSync(abs)) diffs.push(`publish_draft_missing:${fixtureId}`);
      }

      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (!fs.existsSync(path.join(fixtureOut, "diff.preview.json"))) diffs.push(`publish_preview_missing:${fixtureId}`);
      if (!fs.existsSync(path.join(fixtureOut, "file_receipt.json"))) diffs.push(`publish_receipt_missing:${fixtureId}`);

      const rec = ledgerA.find((r) => r.fixture_id === fixtureId && r.kind === "publish_draft");
      if (!rec) diffs.push(`publish_ledger_missing:${fixtureId}`);
      else {
        if (typeof rec.draft_path !== "string" || !rec.draft_path.startsWith("sandbox/_publish_drafts/")) {
          diffs.push(`publish_ledger_path:${fixtureId}`);
        }
        if (rec.draft_kind !== "x_post") diffs.push(`publish_ledger_kind:${fixtureId}`);
        if (typeof rec.content_sha256 !== "string" || !rec.content_sha256.startsWith("sha256:")) {
          diffs.push(`publish_ledger_content_sha:${fixtureId}`);
        }
      }
    }
  }

  // Step-20: Draft -> governed commit chain (mock: draft writes happen; git is gated with no side effects).
  {
    // Missing permit => hard refusal, no draft preview/write.
    {
      const fixtureId = "publish_draft_commit_missing_permit";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "rejected") diffs.push(`draft_commit_status:${fixtureId}`);
      if (dec.reason_code !== "PERMIT_REQUIRED") diffs.push(`draft_commit_reason:${fixtureId}`);
      if (dec.refusal_status !== "REFUSE_HARD") diffs.push(`draft_commit_refusal_status:${fixtureId}`);
      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (fs.existsSync(path.join(fixtureOut, "diff.preview.json"))) diffs.push(`draft_commit_preview_present:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "file_receipt.json"))) diffs.push(`draft_commit_receipt_present:${fixtureId}`);
    }

    const gatedCase = (fixtureId) => {
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "admitted") diffs.push(`draft_commit_status:${fixtureId}`);

      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (!fs.existsSync(path.join(fixtureOut, "diff.preview.json"))) diffs.push(`draft_commit_preview_missing:${fixtureId}`);
      if (!fs.existsSync(path.join(fixtureOut, "file_receipt.json"))) diffs.push(`draft_commit_file_receipt_missing:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "git.receipt.json"))) diffs.push(`draft_commit_git_receipt_present:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "draft_commit_receipt.json"))) diffs.push(`draft_commit_chain_receipt_present:${fixtureId}`);

      const gitExecPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "git.execution.json");
      if (!fs.existsSync(gitExecPath)) diffs.push(`git_execution_missing:${fixtureId}`);
      else {
        const ge = readJSON(gitExecPath);
        if (ge.reason_code !== "HITL_REQUIRED_GIT_COMMIT") diffs.push(`draft_commit_git_gate:${fixtureId}`);
        if (ge.branch_created !== false) diffs.push(`draft_commit_git_side_effect_branch:${fixtureId}`);
        if (ge.patch_applied !== false) diffs.push(`draft_commit_git_side_effect_patch:${fixtureId}`);
        if (ge.staged !== false) diffs.push(`draft_commit_git_side_effect_stage:${fixtureId}`);
        if (ge.commit_created !== false) diffs.push(`draft_commit_git_side_effect_commit:${fixtureId}`);
      }

      const ioPath = path.resolve("out", packId, runA, "fixtures", fixtureId, "io.json");
      const ioRaw = fs.readFileSync(ioPath, "utf8");
      if (ioRaw.includes("\"ratification_token\"") || ioRaw.includes("EGL.GIT_RATIFICATION_TOKEN")) {
        diffs.push(`io_contains_git_token:${fixtureId}`);
      }
    };

    gatedCase("publish_draft_commit_valid_mock");
    gatedCase("publish_draft_commit_valid_live");
  }

  // Step-21: Post surface stub (no network) is permit+HITL gated in mock; no stub receipt is emitted.
  {
    const cases = [
      ["publish_post_x_missing_permit", "PERMIT_REQUIRED", "REFUSE_HARD"],
      ["publish_post_x_valid_mock", "HITL_REQUIRED_PUBLISH_POST", "DEFER_HITL"],
      ["publish_post_x_token_invalid", "HITL_TOKEN_BINDING_MISMATCH", "REFUSE_HARD"],
      ["publish_post_x_token_valid_live", "HITL_REQUIRED_PUBLISH_POST", "DEFER_HITL"],
    ];

    for (const [fixtureId, reason, refusalStatus] of cases) {
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "rejected") diffs.push(`post_decision_status:${fixtureId}`);
      if (dec.reason_code !== reason) diffs.push(`post_reason_code:${fixtureId}`);
      if (dec.refusal_status !== refusalStatus) diffs.push(`post_refusal_status:${fixtureId}`);

      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      const postExecPath = path.join(fixtureOut, "post.execution.json");
      if (!fs.existsSync(postExecPath)) diffs.push(`post_execution_missing:${fixtureId}`);

      if (fs.existsSync(path.join(fixtureOut, "post_stub_receipt.json"))) diffs.push(`post_receipt_present:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "result.json"))) diffs.push(`post_result_present:${fixtureId}`);

      const ioRaw = fs.readFileSync(path.join(fixtureOut, "io.json"), "utf8");
      if (ioRaw.includes("\"ratification_token\"") || ioRaw.includes("EGL.PUBLISH_POST_RATIFICATION_TOKEN")) {
        diffs.push(`io_contains_post_token:${fixtureId}`);
      }
    }

    const ledgerA = readJSONL(path.resolve("out", packId, runA, "spe.ledger.jsonl"));
    if (ledgerA.some((r) => r && r.kind === "publish_post_stub")) diffs.push("post_ledger_stub_present_in_mock");
  }

  // Step-22: Network egress gate (browser.navigate) is permit-bound with exact allowlist semantics.
  {
    const cases = [
      ["egress_navigate_missing_permit", "PERMIT_REQUIRED", "refused", "https://example.com/path", "example.com"],
      ["egress_navigate_denied_host", "EGRESS_DENIED", "refused", "https://example.com/path", "example.com"],
      ["egress_navigate_http_downgrade", "INSECURE_PROTOCOL", "refused", "http://example.com/path", "example.com"],
      ["egress_navigate_localhost_denied", "LOCALHOST_DENIED", "refused", "http://localhost:3000", "localhost:3000"],
      ["egress_navigate_allow_host_only", null, "ok", "https://Example.COM/path", "example.com"],
      ["egress_navigate_allow_host_443_only", null, "ok", "https://example.com:443/path", "example.com:443"],
    ];

    for (const [fixtureId, expectedReason, expectedStatus, expectedTargetInput, expectedCanonical] of cases) {
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (expectedReason) {
        if (dec.status !== "rejected") diffs.push(`egress_decision_status:${fixtureId}`);
        if (dec.reason_code !== expectedReason) diffs.push(`egress_reason_code:${fixtureId}`);
        if (dec.refusal_status !== "REFUSE_HARD") diffs.push(`egress_refusal_status:${fixtureId}`);
      } else {
        if (dec.status !== "admitted") diffs.push(`egress_decision_status:${fixtureId}`);
      }

      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      const checkPath = path.join(fixtureOut, "egress.check.json");
      if (!fs.existsSync(checkPath)) diffs.push(`egress_check_missing:${fixtureId}`);
      else {
        const check = readJSON(checkPath);
        if (check.target_input !== expectedTargetInput) diffs.push(`egress_target_input:${fixtureId}`);
        if (check.canonical_target !== expectedCanonical) diffs.push(`egress_canonical_target:${fixtureId}`);
        if (check.status !== expectedStatus) diffs.push(`egress_check_status:${fixtureId}`);
        if (expectedReason && check.reason_code !== expectedReason) diffs.push(`egress_check_reason:${fixtureId}`);
        if (!expectedReason && check.reason_code !== null) diffs.push(`egress_check_reason:${fixtureId}`);
      }

      if (expectedReason) {
        if (fs.existsSync(path.join(fixtureOut, "result.json"))) diffs.push(`egress_result_present:${fixtureId}`);
      } else {
        if (!fs.existsSync(path.join(fixtureOut, "result.json"))) diffs.push(`egress_result_missing:${fixtureId}`);
      }
    }
  }

  // Step-23: Governed coding surfaces (patch + test).
  {
    // code.patch.apply: preview always; permit required; apply emits receipt and writes only under sandbox.
    {
      const fixtureId = "code_patch_missing_permit";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "rejected") diffs.push(`code_patch_status:${fixtureId}`);
      if (dec.reason_code !== "PERMIT_REQUIRED") diffs.push(`code_patch_reason:${fixtureId}`);
      if (!fs.existsSync(path.resolve("out", packId, runA, "fixtures", fixtureId, "diff.preview.json"))) {
        diffs.push(`code_patch_preview_missing:${fixtureId}`);
      }
    }
    {
      const fixtureId = "code_patch_scope_violation";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "rejected") diffs.push(`code_patch_status:${fixtureId}`);
      if (dec.reason_code !== "PERMIT_SCOPE_VIOLATION") diffs.push(`code_patch_reason:${fixtureId}`);
      if (!fs.existsSync(path.resolve("out", packId, runA, "fixtures", fixtureId, "diff.preview.json"))) {
        diffs.push(`code_patch_preview_missing:${fixtureId}`);
      }
    }
    {
      const fixtureId = "code_patch_valid_apply";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "admitted") diffs.push(`code_patch_status:${fixtureId}`);
      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (!fs.existsSync(path.join(fixtureOut, "diff.preview.json"))) diffs.push(`code_patch_preview_missing:${fixtureId}`);
      if (!fs.existsSync(path.join(fixtureOut, "file_receipt.json"))) diffs.push(`code_patch_receipt_missing:${fixtureId}`);
      const targetAbs = path.resolve("sandbox", "_th_tmp", "code_patch_target.txt");
      if (!fs.existsSync(targetAbs)) diffs.push(`code_patch_target_missing:${fixtureId}`);

      // IO must not contain raw after_text.
      const ioRaw = fs.readFileSync(path.join(fixtureOut, "io.json"), "utf8");
      if (ioRaw.includes("\"after_text\"")) diffs.push(`io_contains_after_text:${fixtureId}`);
    }

    // code.test.run: permit-gated + allowlisted; stub execution emits receipts only when admitted.
    {
      const fixtureId = "code_test_missing_permit";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "rejected") diffs.push(`code_test_status:${fixtureId}`);
      if (dec.reason_code !== "PERMIT_REQUIRED") diffs.push(`code_test_reason:${fixtureId}`);
      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (!fs.existsSync(path.join(fixtureOut, "test.execution.json"))) diffs.push(`code_test_exec_missing:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "test.result.json"))) diffs.push(`code_test_result_present:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "test_receipt.json"))) diffs.push(`code_test_receipt_present:${fixtureId}`);
    }
    {
      const fixtureId = "code_test_cmd_not_allowed";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "rejected") diffs.push(`code_test_status:${fixtureId}`);
      if (dec.reason_code !== "EXEC_CMD_NOT_ALLOWED") diffs.push(`code_test_reason:${fixtureId}`);
      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (!fs.existsSync(path.join(fixtureOut, "test.execution.json"))) diffs.push(`code_test_exec_missing:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "test.result.json"))) diffs.push(`code_test_result_present:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "test_receipt.json"))) diffs.push(`code_test_receipt_present:${fixtureId}`);
    }
    {
      const fixtureId = "code_test_valid_mock";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "admitted") diffs.push(`code_test_status:${fixtureId}`);
      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (!fs.existsSync(path.join(fixtureOut, "test.execution.json"))) diffs.push(`code_test_exec_missing:${fixtureId}`);
      if (!fs.existsSync(path.join(fixtureOut, "test.result.json"))) diffs.push(`code_test_result_missing:${fixtureId}`);
      if (!fs.existsSync(path.join(fixtureOut, "test_receipt.json"))) diffs.push(`code_test_receipt_missing:${fixtureId}`);
    }
  }

  // Step-24: Controlled dependency fetch surface (permit-gated, lockfile-bound; stubbed in mock).
  {
    {
      const fixtureId = "code_deps_missing_permit";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "rejected") diffs.push(`code_deps_status:${fixtureId}`);
      if (dec.reason_code !== "PERMIT_REQUIRED") diffs.push(`code_deps_reason:${fixtureId}`);
      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (!fs.existsSync(path.join(fixtureOut, "deps.execution.json"))) diffs.push(`code_deps_exec_missing:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "deps.result.json"))) diffs.push(`code_deps_result_present:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "deps.receipt.json"))) diffs.push(`code_deps_receipt_present:${fixtureId}`);
    }
    {
      const fixtureId = "code_deps_lockfile_missing";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "rejected") diffs.push(`code_deps_status:${fixtureId}`);
      if (dec.reason_code !== "MISSING_LOCKFILE") diffs.push(`code_deps_reason:${fixtureId}`);
      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (!fs.existsSync(path.join(fixtureOut, "deps.execution.json"))) diffs.push(`code_deps_exec_missing:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "deps.result.json"))) diffs.push(`code_deps_result_present:${fixtureId}`);
      if (fs.existsSync(path.join(fixtureOut, "deps.receipt.json"))) diffs.push(`code_deps_receipt_present:${fixtureId}`);
    }
    {
      const fixtureId = "code_deps_valid_mock";
      const dec = readJSON(path.resolve("out", packId, runA, "fixtures", fixtureId, "decision.json"));
      if (dec.status !== "admitted") diffs.push(`code_deps_status:${fixtureId}`);
      const fixtureOut = path.resolve("out", packId, runA, "fixtures", fixtureId);
      if (!fs.existsSync(path.join(fixtureOut, "deps.execution.json"))) diffs.push(`code_deps_exec_missing:${fixtureId}`);
      if (!fs.existsSync(path.join(fixtureOut, "deps.result.json"))) diffs.push(`code_deps_result_missing:${fixtureId}`);
      if (!fs.existsSync(path.join(fixtureOut, "deps.receipt.json"))) diffs.push(`code_deps_receipt_missing:${fixtureId}`);
    }
  }

  const metricsA = readJSON(path.resolve("out", packId, runA, "metrics.json"));
  if (metricsA.no_side_effect_on_refusal_score !== 1) diffs.push("metric:no_side_effect_on_refusal_score");
  if (metricsA.no_absolute_path_leak_score !== 1) diffs.push("metric:no_absolute_path_leak_score");
  if (metricsA.replay_block_score !== 1) diffs.push("metric:replay_block_score");
  if (metricsA.supply_chain_block_score !== 1) diffs.push("metric:supply_chain_block_score");
  if (metricsA.supply_chain_evidence_score !== 1) diffs.push("metric:supply_chain_evidence_score");
  if (metricsA.hitl_gate_score !== 1) diffs.push("metric:hitl_gate_score");
  if (metricsA.hitl_authority_gate_score !== 1) diffs.push("metric:hitl_authority_gate_score");
  if (metricsA.hitl_quorum_gate_score !== 1) diffs.push("metric:hitl_quorum_gate_score");
  if (metricsA.git_gate_score !== 1) diffs.push("metric:git_gate_score");
  if (metricsA.publish_draft_score !== 1) diffs.push("metric:publish_draft_score");
  if (metricsA.draft_commit_chain_score !== 1) diffs.push("metric:draft_commit_chain_score");
  if (metricsA.publish_post_gate_score !== 1) diffs.push("metric:publish_post_gate_score");
  if (metricsA.egress_gate_score !== 1) diffs.push("metric:egress_gate_score");
  if (metricsA.code_patch_score !== 1) diffs.push("metric:code_patch_score");
  if (metricsA.code_test_score !== 1) diffs.push("metric:code_test_score");
  if (metricsA.deps_fetch_score !== 1) diffs.push("metric:deps_fetch_score");
  if (metricsA.pass !== true) diffs.push("metric:pass");

  if (diffs.length > 0) {
    console.error("TH-001C proxy golden mismatch:");
    for (const d of diffs) console.error(`- ${d}`);
    process.exit(1);
  }

  console.log("TH-001C proxy golden: OK");
}

main();
