import fs from "node:fs";
import path from "node:path";
import { loadToolSurfaceMap } from "../harness/intent_compiler/tool_surface_map.mjs";
import { compileIntent } from "../harness/intent_compiler/compile_intent.mjs";
import { computeLawBundle } from "../harness/provenance/law_bundle.mjs";
import { compute_permit_sha256 } from "../harness/provenance/execution_permit.mjs";
import {
  build_git_ratification_token,
  build_publish_post_ratification_token,
} from "../harness/provenance/ratification_token.mjs";
import { unifiedDiff } from "../harness/executor_real/diff_engine.mjs";
import { sha256_hex } from "../harness/intent_compiler/hash.mjs";
import {
  buildEnvelopeFromFixtureFile,
  normalizeEnvelopeToIntent,
} from "../harness/tdi/proxy/envelope.mjs";

function deriveWriteAfterText({ relPath, fixture }) {
  if (typeof fixture?.draft_kind === "string" && typeof fixture?.content === "string") {
    const kind = String(fixture.draft_kind ?? "x_post");
    const contentRaw = String(fixture.content ?? "");
    const contentLf = contentRaw.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const contentTrimmed = contentLf
      .split("\n")
      .map((line) => line.replace(/[ \t]+$/g, ""))
      .join("\n");
    const contentNorm = contentTrimmed.endsWith("\n") ? contentTrimmed : `${contentTrimmed}\n`;
    const contentSha = sha256_hex(Buffer.from(contentTrimmed, "utf8"));
    const header =
      `---\n` +
      `schema_id: EGL.PUBLISH_DRAFT\n` +
      `version: 0.1.0\n` +
      `draft_kind: ${kind}\n` +
      `content_sha256: sha256:${contentSha}\n` +
      `---\n`;
    return `${header}${contentNorm}`;
  }

  const spec = fixture?.write_spec && typeof fixture.write_spec === "object" ? fixture.write_spec : null;
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
  return `EGL_DIFF_WRITE:${String(relPath ?? "")}`;
}

function computeDiffForWriteFixture({ relPath, fixture }) {
  // In TH-001C, sandbox reset ensures these targets do not exist initially.
  const before_text = "";
  const after_text = deriveWriteAfterText({ relPath, fixture });
  return unifiedDiff({ relPath, before_text, after_text });
}

function normalizePostPayloadText(payloadTextRaw) {
  const raw = typeof payloadTextRaw === "string" ? payloadTextRaw : "";
  const lf = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const trimmed = lf
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, ""))
    .join("\n");
  return trimmed.endsWith("\n") ? trimmed : `${trimmed}\n`;
}

function main() {
  const repoRoot = process.cwd();
  const fixturesDir = path.resolve(repoRoot, "tests", "fixtures", "proxy");
  const packPath = path.resolve(repoRoot, "tests", "packs", "TH-001C.pack.json");
  const pack = JSON.parse(fs.readFileSync(packPath, "utf8"));
  const law = computeLawBundle({ repoRoot });
  const toolSurfaceMap = loadToolSurfaceMap(repoRoot);

  const diffFixtureId = "diff_write_valid_apply";
  const diffFixturePath = pack.fixtures?.[diffFixtureId];
  if (!diffFixturePath) throw new Error(`Pack missing fixture '${diffFixtureId}'`);
  const diffFixture = JSON.parse(fs.readFileSync(path.resolve(repoRoot, diffFixturePath), "utf8"));
  const diffRelPath = String(diffFixture?.path ?? "");
  const diff = computeDiffForWriteFixture({ relPath: diffRelPath, fixture: diffFixture });

  const files = fs
    .readdirSync(fixturesDir)
    .filter((f) => f.endsWith(".json") && f.startsWith("TH-001C."))
    .map((f) => path.resolve(fixturesDir, f));

  for (const filePath of files) {
    const raw = fs.readFileSync(filePath, "utf8");
    const fixture = JSON.parse(raw);
    const fileBase = path.basename(filePath);

    // Compile to get current plan/intent hashes.
    const relFixturePath = path.relative(repoRoot, filePath).replace(/\\/g, "/");
    const envelope = buildEnvelopeFromFixtureFile({
      repoRoot,
      fixturePath: relFixturePath,
      fixture_id: fileBase,
    });
    const intent = normalizeEnvelopeToIntent({ repoRoot, envelope });
    const compilation = compileIntent({ intent, toolSurfaceMap });

    const permit = fixture?.execution_permit && typeof fixture.execution_permit === "object" ? fixture.execution_permit : null;
    if (permit && permit.schema_id === "EGL.EXECUTION_PERMIT") {
      permit.bindings = permit.bindings && typeof permit.bindings === "object" ? permit.bindings : {};

      // Always update law binding (law bundle changes whenever policy/mapping changes).
      permit.bindings.law_bundle_sha256 = law.law_bundle_sha256;

      // Keep the "binding mismatch" fixture mismatched.
      const isBindingMismatch = fileBase.includes("binding_mismatch");
      if (!isBindingMismatch) {
        permit.bindings.plan_hash_sha3_512 = compilation.hashes?.plan ?? null;
        permit.bindings.intent_hash_sha3_512 = compilation.hashes?.intent ?? null;
      }

      const isInvalidHash =
        fileBase.includes("invalid_hash") || fileBase.includes("git.pipeline_invalid_permit");
      if (!isInvalidHash) {
        permit.permit_sha256 = compute_permit_sha256(permit);
      }
    }

    if (fixture?.ratification_token && String(fixture.tool ?? "") === "git.pipeline_commit_from_diff") {
      fixture.ratification_token = build_git_ratification_token({
        law_bundle_sha256: law.law_bundle_sha256,
        plan_hash: compilation.hashes?.plan ?? "",
        intent_hash: compilation.hashes?.intent ?? "",
        lane_id: "proxy",
        attestation_nonce: String(fixture.force_nonce ?? ""),
        expires_ts: "2099-01-01T00:00:00Z",
        approver_id: "HUMAN_TEST",
        git_branch: String(fixture.git_branch ?? ""),
        diff_sha256: String(diff.diff_sha256 ?? ""),
      });
    }

    if (fixture?.ratification_token && String(fixture.tool ?? "") === "publish.draft.commit") {
      const relPath = String(compilation?.plan?.actions?.[0]?.file?.path ?? "");
      const d = computeDiffForWriteFixture({ relPath, fixture });
      fixture.ratification_token = build_git_ratification_token({
        law_bundle_sha256: law.law_bundle_sha256,
        plan_hash: compilation.hashes?.plan ?? "",
        intent_hash: compilation.hashes?.intent ?? "",
        lane_id: "proxy",
        attestation_nonce: String(fixture.force_nonce ?? ""),
        expires_ts: "2099-01-01T00:00:00Z",
        approver_id: "HUMAN_TEST",
        git_branch: String(fixture.git_branch ?? ""),
        diff_sha256: String(d.diff_sha256 ?? ""),
      });
    }

    if (
      fixture?.ratification_token &&
      (String(fixture.tool ?? "") === "publish.post.x" || String(fixture.tool ?? "") === "publish.post.x_thread")
    ) {
      // Only refresh the known-valid live token fixture. Invalid-token fixtures are intentionally mismatched.
      if (fileBase.includes("token_valid_live")) {
        const surface = String(fixture.tool ?? "") === "publish.post.x_thread" ? "x_thread" : "x";
        const payloadNorm = normalizePostPayloadText(fixture.payload_text);
        const payload_sha256 = `sha256:${sha256_hex(Buffer.from(payloadNorm, "utf8"))}`;
        const source_commit_hash = typeof fixture.source_commit_hash === "string" ? fixture.source_commit_hash : "";
        const source_receipt_hash_sha256 =
          typeof fixture.source_receipt_hash_sha256 === "string" ? fixture.source_receipt_hash_sha256 : "";

        fixture.ratification_token = build_publish_post_ratification_token({
          law_bundle_sha256: law.law_bundle_sha256,
          plan_hash: compilation.hashes?.plan ?? "",
          intent_hash: compilation.hashes?.intent ?? "",
          lane_id: "proxy",
          attestation_nonce: String(fixture.force_nonce ?? ""),
          expires_ts: "2099-01-01T00:00:00Z",
          approver_id: "HUMAN_TEST",
          surface,
          payload_sha256,
          source_commit_hash,
          source_receipt_hash_sha256,
        });
      }
    }

    fs.writeFileSync(filePath, JSON.stringify(fixture, null, 2) + "\n", "utf8");
  }

  console.log(JSON.stringify({ ok: true, law_bundle_sha256: law.law_bundle_sha256 }, null, 2));
}

main();
