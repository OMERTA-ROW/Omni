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

const SECRET = "workspace-test-secret-".padEnd(48, "w");
const CONTROL_SECRET = "control-test-secret-".padEnd(48, "c");
const goodProbe = {
  network: "isolated",
  uid: 65534,
  perSessionUser: true,
  envNames: ["HOME", "LANG", "PATH", "TERM"],
  probeExitCode: 0,
};

function config(dataDir, enabled = true, overrides = {}) {
  return {
    port: 0,
    clientId: "mothership-test",
    secret: SECRET,
    controlSecret: CONTROL_SECRET,
    projectId: "omni",
    dataDir,
    enabled,
    bwrapPath: "/unused",
    supervisorPath: "/unused",
    limits: {
      commandTimeoutSec: 2,
      cpuSec: 1,
      memoryMb: 128,
      maxProcesses: 8,
      fileSizeMb: 1,
      outputCapBytes: 1024,
      maxSessions: 3,
      idleMinutes: 10,
      sessionMinutes: 60,
      workspaceMb: 16,
      workspaceInodes: 256,
      ...overrides,
    },
  };
}

function fakeLauncher() {
  const created = [];
  function launch() {
    const listeners = new Map();
    const runner = {
      runs: [],
      cancellations: [],
      closed: false,
      ready: Promise.resolve({
        type: "ready", uid: 65534, networkIsolated: true, envNames: goodProbe.envNames, exitCode: 0,
      }),
      run(jobId, command, limits, listener) {
        this.runs.push({ jobId, command, limits });
        listeners.set(jobId, listener);
      },
      cancel(jobId) {
        this.cancellations.push(jobId);
        listeners.get(jobId)?.({ type: "done", jobId, exitCode: -1, reason: "cancelled" });
      },
      finish(jobId) { listeners.delete(jobId); },
      async close() { this.closed = true; },
      async terminate() { this.closed = true; },
      output(jobId, stream, text) {
        listeners.get(jobId)?.({ type: "output", jobId, stream, text });
      },
      complete(jobId, exitCode = 0, reason = "") {
        listeners.get(jobId)?.({ type: "done", jobId, exitCode, reason });
      },
    };
    created.push(runner);
    return runner;
  }
  launch.created = created;
  return launch;
}

async function startApp(t, { enabled = true, limits = {} } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "omni-sandbox-test-"));
  const launcher = fakeLauncher();
  const app = await createSandbox(config(dir, enabled, limits), { launchSession: launcher, probe: goodProbe });
  await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const address = app.server.address();
  const origin = `http://127.0.0.1:${address.port}`;
  t.after(async () => {
    await app.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { app, launcher, origin, dir };
}

function signedHeaders({ body, urlPath, contract = CONTRACT, secret = SECRET, clientId, nonce, timestamp, control = false }) {
  timestamp ??= String(Math.floor(Date.now() / 1000));
  const requestNonce = nonce ?? randomBytes(16).toString("hex");
  const digest = createHash("sha256").update(body).digest("hex");
  const message = `${contract}\nPOST\n${urlPath}\n${timestamp}\n${requestNonce}\n${digest}`;
  const signature = createHmac("sha256", secret).update(message).digest("hex");
  const prefix = control ? "x-omni-control-" : "x-omni-";
  return {
    "content-type": "application/json",
    ...(clientId ? { "x-omni-client": clientId } : {}),
    [`${prefix}timestamp`]: timestamp,
    [`${prefix}nonce`]: requestNonce,
    [`${prefix}signature`]: signature,
  };
}

async function callWorkspace(origin, action, payload = {}, options = {}) {
  const body = JSON.stringify({ action, projectId: "omni", ...payload });
  const headers = signedHeaders({
    body, urlPath: WORKSPACE_PATH, nonce: options.nonce,
    clientId: options.clientId ?? "mothership-test",
  });
  const response = await fetch(`${origin}${WORKSPACE_PATH}`, { method: "POST", headers, body });
  return { response, body: await response.json().catch(() => ({})) };
}

async function callControl(origin, action, nonce) {
  const body = JSON.stringify({ action });
  const headers = signedHeaders({
    body, urlPath: CONTROL_PATH, contract: CONTROL_CONTRACT, secret: CONTROL_SECRET,
    nonce, control: true,
  });
  const response = await fetch(`${origin}${CONTROL_PATH}`, { method: "POST", headers, body });
  return { response, body: await response.json().catch(() => ({})) };
}

function verifyProof(response, rawBody, contract, secret, nonce) {
  const expected = createHmac("sha256", secret)
    .update(`${contract}\nresponse\n${nonce}\n${response.status}\n${rawBody}`)
    .digest("hex");
  assert.equal(response.headers.get("x-omni-proof"), expected);
}

test("configuration is disabled by default and requires an independent stop key to enable", () => {
  const config = loadConfig({
    OMNI_SANDBOX_CLIENT_ID: "mothership",
    OMNI_SANDBOX_HMAC_SECRET: SECRET,
  });
  assert.equal(config.enabled, false);
  assert.throws(() => loadConfig({
    OMNI_SANDBOX_CLIENT_ID: "mothership",
    OMNI_SANDBOX_HMAC_SECRET: SECRET,
    OMNI_SANDBOX_ENABLED: "true",
  }), /CONTROL_SECRET/);
  assert.throws(() => loadConfig({
    OMNI_SANDBOX_CLIENT_ID: "mothership",
    OMNI_SANDBOX_HMAC_SECRET: SECRET,
    OMNI_SANDBOX_CONTROL_SECRET: SECRET,
    OMNI_SANDBOX_ENABLED: "true",
  }), /distinct secret/);
});

test("workspace handshake is signed and replayed or invalid authorization is rejected", async (t) => {
  const { origin } = await startApp(t, { enabled: false });
  const nonce = randomBytes(16).toString("hex");
  const body = JSON.stringify({ action: "health.check", projectId: "omni" });
  const headers = signedHeaders({ body, urlPath: WORKSPACE_PATH, nonce, clientId: "mothership-test" });
  const first = await fetch(`${origin}${WORKSPACE_PATH}`, { method: "POST", headers, body });
  const firstBody = await first.text();
  assert.equal(first.status, 200);
  verifyProof(first, firstBody, CONTRACT, SECRET, nonce);

  const replay = await fetch(`${origin}${WORKSPACE_PATH}`, { method: "POST", headers, body });
  assert.equal(replay.status, 401);

  const badClient = await callWorkspace(origin, "health.check", {}, { clientId: "wrong-client" });
  assert.equal(badClient.response.status, 401);

  const wrongProject = await callWorkspace(origin, "health.check", { projectId: "other-project" });
  assert.equal(wrongProject.response.status, 409);

  const badSignatureHeaders = signedHeaders({ body, urlPath: WORKSPACE_PATH, clientId: "mothership-test" });
  badSignatureHeaders["x-omni-signature"] = "0".repeat(64);
  const badSignature = await fetch(`${origin}${WORKSPACE_PATH}`, { method: "POST", headers: badSignatureHeaders, body });
  assert.equal(badSignature.status, 401);

  const expiredHeaders = signedHeaders({
    body, urlPath: WORKSPACE_PATH, clientId: "mothership-test",
    timestamp: String(Math.floor(Date.now() / 1000) - 61),
  });
  const expired = await fetch(`${origin}${WORKSPACE_PATH}`, { method: "POST", headers: expiredHeaders, body });
  assert.equal(expired.status, 401);
});

test("disabled service serves signed diagnostics but refuses session creation", async (t) => {
  const { origin } = await startApp(t, { enabled: false });
  const health = await callWorkspace(origin, "health.check");
  assert.equal(health.response.status, 200);
  assert.equal(health.body.health.executionEnabled, false);
  assert.equal(health.body.health.emergencyStop, true);
  const session = await callWorkspace(origin, "session.start", {
    sessionId: randomUUID(), agentId: "omni", allowedActions: ["run_commands"],
  });
  assert.equal(session.response.status, 409);
  assert.match(session.body.error, /disabled/);
});

test("commands require scoped permission and explicit approval; output is bounded and polled", async (t) => {
  const { origin, launcher } = await startApp(t, { limits: { outputCapBytes: 1024 } });
  const release = await callControl(origin, "clear");
  assert.equal(release.response.status, 200);

  const sessionId = randomUUID();
  const started = await callWorkspace(origin, "session.start", {
    sessionId, agentId: "omni", allowedActions: ["run_commands"], autonomous: true,
  });
  assert.equal(started.response.status, 200);
  assert.match(started.body.session.sandboxId, /^sbx-/);
  const runner = launcher.created[0];

  const jobId = randomUUID();
  const queued = await callWorkspace(origin, "command.run", {
    sessionId, jobId, command: "printf 'OMNI_EXECUTOR_OK\\n'", autonomous: true,
  });
  assert.equal(queued.body.job.status, "queued");
  assert.equal(queued.body.steps[0].status, "pending_approval");
  assert.equal(runner.runs.length, 0);

  const unauthorizedSession = randomUUID();
  await callWorkspace(origin, "session.start", {
    sessionId: unauthorizedSession, agentId: "omni", allowedActions: [],
  });
  const denied = await callWorkspace(origin, "command.run", {
    sessionId: unauthorizedSession, jobId: randomUUID(), command: "echo denied",
  });
  assert.equal(denied.response.status, 409);
  assert.match(denied.body.error, /not authorized/);

  const approved = await callWorkspace(origin, "step.decide", {
    sessionId, jobId, stepId: "cmd", approve: true,
  });
  assert.equal(approved.body.job.status, "running");
  assert.equal(runner.runs.length, 1);
  runner.output(jobId, "stdout", "x".repeat(4096));
  assert.equal(runner.cancellations.includes(jobId), true);
  const saved = runner === launcher.created[0] && (await callWorkspace(origin, "events.poll", { sessionId, jobId }));
  assert.equal(Buffer.byteLength(saved.body.steps.map((step) => step.body).join("")) <= 1100, true);
});

test("global Emergency Stop independently cancels jobs and remains latched", async (t) => {
  const { origin, launcher } = await startApp(t);
  assert.equal((await callControl(origin, "clear")).response.status, 200);
  const sessionId = randomUUID();
  await callWorkspace(origin, "session.start", {
    sessionId, agentId: "omni", allowedActions: ["run_commands"],
  });
  const jobId = randomUUID();
  await callWorkspace(origin, "command.run", { sessionId, jobId, command: "sleep 30" });
  await callWorkspace(origin, "step.decide", { sessionId, jobId, stepId: "cmd", approve: true });

  const stopped = await callControl(origin, "engage");
  assert.equal(stopped.response.status, 200);
  assert.equal(launcher.created[0].cancellations.includes(jobId), true);
  assert.equal((await callWorkspace(origin, "health.check")).body.health.emergencyStop, true);
  const blocked = await callWorkspace(origin, "session.start", {
    sessionId: randomUUID(), agentId: "omni", allowedActions: ["run_commands"],
  });
  assert.equal(blocked.response.status, 409);
  assert.match(blocked.body.error, /Emergency Stop/);
});

test("restart recovery stops queued/running jobs and preserves their status", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "omni-sandbox-recovery-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const sessionId = randomUUID();
  const jobId = randomUUID();
  fs.writeFileSync(path.join(dir, "state.json"), JSON.stringify({
    version: 1,
    emergencyStop: false,
    nonces: {},
    sessions: {
      [sessionId]: {
        id: sessionId, agentId: "omni", sandboxId: "sbx-restart", sandboxName: "OMNI isolated shell",
        allowedActions: ["run_commands"], status: "active", startedAt: Date.now(), lastAt: Date.now(),
        endedAt: null, jobs: {
          [jobId]: {
            id: jobId, status: "running", createdAt: Date.now(), finishedAt: null, exitCode: null,
            cursor: 0, events: [],
          },
        },
      },
    },
  }), { mode: 0o600 });
  const app = await createSandbox(config(dir), { launchSession: fakeLauncher(), probe: goodProbe });
  assert.equal(app.state.sessions[sessionId].status, "ended");
  assert.equal(app.state.sessions[sessionId].jobs[jobId].status, "stopped");
  assert.equal(app.state.emergencyStop, true);
  assert.match(app.state.sessions[sessionId].jobs[jobId].events[0].text, /not resumed/);
  await app.close();
});
