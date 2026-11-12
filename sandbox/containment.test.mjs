import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import {
  CONTRACT, CONTROL_CONTRACT, CONTROL_PATH, WORKSPACE_PATH,
  createSandbox, loadConfig,
} from "./server.mjs";

const enabled = process.env.OMNI_SANDBOX_CONTAINMENT === "1";
const skip = enabled ? false : "Opt in only inside an isolated Linux staging runtime.";
const secret = "staging-workspace-secret-".padEnd(48, "s");
const controlSecret = "staging-control-secret-".padEnd(48, "c");

function makeConfig(dataDir) {
  return loadConfig({
    PORT: "8080",
    OMNI_SANDBOX_CLIENT_ID: "mothership-staging",
    OMNI_SANDBOX_HMAC_SECRET: secret,
    OMNI_SANDBOX_CONTROL_SECRET: controlSecret,
    OMNI_SANDBOX_PROJECT_ID: "omni-staging",
    OMNI_SANDBOX_DATA_DIR: dataDir,
    OMNI_SANDBOX_ENABLED: "true",
    OMNI_SANDBOX_COMMAND_TIMEOUT_SEC: "3",
    OMNI_SANDBOX_CPU_SEC: "1",
    OMNI_SANDBOX_MEMORY_MB: "128",
    OMNI_SANDBOX_MAX_PROCESSES: "8",
    OMNI_SANDBOX_FILE_MB: "1",
    OMNI_SANDBOX_OUTPUT_CAP_BYTES: "4096",
    OMNI_SANDBOX_MAX_SESSIONS: "3",
    OMNI_SANDBOX_WORKSPACE_MB: "16",
    OMNI_SANDBOX_WORKSPACE_INODES: "256",
  });
}

function headers(body, route, contract, key, prefix, clientId) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(16).toString("hex");
  const digest = createHash("sha256").update(body).digest("hex");
  const signature = createHmac("sha256", key)
    .update(`${contract}\nPOST\n${route}\n${timestamp}\n${nonce}\n${digest}`)
    .digest("hex");
  return {
    "content-type": "application/json",
    ...(clientId ? { "x-omni-client": clientId } : {}),
    [`${prefix}timestamp`]: timestamp,
    [`${prefix}nonce`]: nonce,
    [`${prefix}signature`]: signature,
    requestNonce: nonce,
  };
}

async function request(origin, action, payload = {}, control = false) {
  const route = control ? CONTROL_PATH : WORKSPACE_PATH;
  const contract = control ? CONTROL_CONTRACT : CONTRACT;
  const key = control ? controlSecret : secret;
  const prefix = control ? "x-omni-control-" : "x-omni-";
  const body = JSON.stringify(control ? { action } : {
    action, projectId: "omni-staging", ...payload,
  });
  const { requestNonce, ...requestHeaders } = headers(body, route, contract, key, prefix, control ? undefined : "mothership-staging");
  const response = await fetch(`${origin}${route}`, {
    method: "POST",
    headers: requestHeaders,
    body,
  });
  const raw = await response.text();
  const proof = createHmac("sha256", key)
    .update(`${contract}\nresponse\n${requestNonce}\n${response.status}\n${raw}`)
    .digest("hex");
  assert.equal(response.headers.get("x-omni-proof"), proof, "response signature must verify");
  return { status: response.status, body: JSON.parse(raw) };
}

async function withSandbox(t, callback) {
  assert.equal(process.platform, "linux", "containment suite requires Linux");
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "omni-sandbox-stage-"));
  const app = await createSandbox(makeConfig(dataDir));
  await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${app.server.address().port}`;
  t.after(async () => {
    await app.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  assert.equal(app.health.network, "isolated");
  assert.equal(app.health.uid > 0, true);
  assert.equal(app.health.probeExitCode, 0);
  const clear = await request(origin, "clear", {}, true);
  assert.equal(clear.status, 200);
  return { app, origin, dataDir };
}

async function startSession(origin, sessionId = randomUUID()) {
  const result = await request(origin, "session.start", {
    sessionId, agentId: "omni", allowedActions: ["run_commands"],
  });
  assert.equal(result.status, 200, JSON.stringify(result.body));
  return sessionId;
}

async function runCommand(origin, sessionId, command) {
  const jobId = randomUUID();
  const proposed = await request(origin, "command.run", { sessionId, jobId, command });
  assert.equal(proposed.status, 202);
  assert.equal(proposed.body.job.status, "queued");
  assert.equal(proposed.body.steps[0].status, "pending_approval");
  const approved = await request(origin, "step.decide", {
    sessionId, jobId, stepId: "cmd", approve: true,
  });
  assert.equal(approved.status, 200);
  return jobId;
}

async function pollUntilDone(origin, sessionId, jobId, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  const steps = [];
  let status = "running";
  while (Date.now() < deadline) {
    const result = await request(origin, "events.poll", { sessionId, jobId });
    assert.equal(result.status, 200);
    steps.push(...result.body.steps);
    status = result.body.job.status;
    if (["done", "failed", "stopped"].includes(status)) return { status, steps };
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`job ${jobId} did not finish before test deadline`);
}

test("real sandbox runs approved work and blocks access to service files and external network", { skip }, async (t) => {
  const { origin } = await withSandbox(t);
  const sessionId = await startSession(origin);
  const jobId = await runCommand(
    origin, sessionId,
    "printf 'OMNI_EXECUTOR_OK\\n'; test ! -e /data/state.json; test ! -e /etc/hostname; test ! -e /proc/1/root/data/state.json",
  );
  const result = await pollUntilDone(origin, sessionId, jobId);
  assert.equal(result.status, "done", JSON.stringify(result.steps));
  assert.match(result.steps.map((step) => step.body).join(""), /OMNI_EXECUTOR_OK/);

  const networkJob = await runCommand(origin, sessionId, "test \"$(grep -c ':' /proc/net/dev)\" -eq 1");
  const network = await pollUntilDone(origin, sessionId, networkJob);
  assert.equal(network.status, "failed");

  const outputJob = await runCommand(origin, sessionId, "yes sandbox-output | head -c 16384");
  const output = await pollUntilDone(origin, sessionId, outputJob);
  assert.equal(output.status, "failed");
  const streamedBytes = output.steps
    .filter((step) => step.stream === "stdout" || step.stream === "stderr")
    .reduce((total, step) => total + Buffer.byteLength(step.body), 0);
  assert.equal(streamedBytes <= 4096, true);
});

test("separate sessions have distinct workspaces and workspace storage is bounded", { skip }, async (t) => {
  const { origin } = await withSandbox(t);
  const first = await startSession(origin);
  const second = await startSession(origin);
  const writeJob = await runCommand(origin, first, "printf secret > /workspace/marker");
  assert.equal((await pollUntilDone(origin, first, writeJob)).status, "done");
  const readJob = await runCommand(origin, second, "test ! -e /workspace/marker");
  assert.equal((await pollUntilDone(origin, second, readJob)).status, "done");

  const quotaJob = await runCommand(
    origin, second,
    "dd if=/dev/zero of=/workspace/too-large bs=1M count=32 2>/dev/null; test $? -ne 0",
  );
  assert.equal((await pollUntilDone(origin, second, quotaJob)).status, "done");

  const fileJob = await runCommand(
    origin, second,
    "dd if=/dev/zero of=/workspace/file-limit bs=2M count=1 2>/dev/null",
  );
  assert.equal((await pollUntilDone(origin, second, fileJob)).status, "failed");
});

test("resource limits, cancellation, and restart recovery fail closed", { skip }, async (t) => {
  const { app, origin, dataDir } = await withSandbox(t);
  const sessionId = await startSession(origin);
  const limitJob = await runCommand(
    origin, sessionId,
    "test \"$(ulimit -t)\" = 1 && test \"$(ulimit -v)\" = 131072 && test \"$(ulimit -u)\" = 8",
  );
  assert.equal((await pollUntilDone(origin, sessionId, limitJob)).status, "done");

  const memoryJob = await runCommand(origin, sessionId, "/usr/bin/awk 'BEGIN { s = sprintf(\"%200000000s\", \"x\"); print length(s) }'");
  assert.equal((await pollUntilDone(origin, sessionId, memoryJob)).status, "failed");

  const cpuJob = await runCommand(origin, sessionId, "while :; do :; done");
  const cpuResult = await pollUntilDone(origin, sessionId, cpuJob);
  assert.equal(cpuResult.status, "failed");
  assert.equal(cpuResult.steps.some((step) => /time limit/i.test(step.body)), true);

  const cancelledJob = await runCommand(origin, sessionId, "sleep 30");
  const stopped = await request(origin, "job.stop", { sessionId, jobId: cancelledJob });
  assert.equal(stopped.status, 200);
  assert.equal((await pollUntilDone(origin, sessionId, cancelledJob)).status, "stopped");

  await app.close();
  const restarted = await createSandbox(makeConfig(dataDir));
  assert.equal(restarted.state.emergencyStop, true);
  assert.equal(restarted.state.sessions[sessionId].status, "ended");
  assert.equal(restarted.state.sessions[sessionId].jobs[cancelledJob].status, "stopped");
  await restarted.close();
});
