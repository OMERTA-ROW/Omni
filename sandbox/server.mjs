import http from "node:http";
import readline from "node:readline";
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";

export const CONTRACT = "omni.workspace/v1";
export const WORKSPACE_PATH = "/api/public/omni/workspace";
export const CONTROL_PATH = "/api/internal/emergency-stop";
export const CONTROL_CONTRACT = "omni.sandbox-control/v1";
const VERSION = "0.2.0";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const AGENT = /^[a-z][a-z0-9-]{1,31}$/;
const CLIENT = /^[A-Za-z0-9_.:-]{3,80}$/;
const HEX_32 = /^[0-9a-f]{32}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_OUTPUT_BYTES = 262144;
const MAX_EVENTS_PER_REPLY = 12000;
const MAX_JOBS_PER_SESSION = 10;
const MAX_RETAINED_SESSIONS = 10;
const MAX_SESSIONS = 5;
const IDLE_MS = 10 * 60_000;
const SESSION_MS = 60 * 60_000;
const ENV_NAMES = ["HOME", "LANG", "PATH", "TERM"];

function boundedInt(value, fallback, min, max) {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

export function loadConfig(env = process.env) {
  const config = {
    port: boundedInt(env.PORT, 8080, 1, 65535),
    clientId: env.OMNI_SANDBOX_CLIENT_ID ?? "",
    secret: env.OMNI_SANDBOX_HMAC_SECRET ?? "",
    controlSecret: env.OMNI_SANDBOX_CONTROL_SECRET ?? "",
    projectId: env.OMNI_SANDBOX_PROJECT_ID ?? "omni",
    dataDir: env.OMNI_SANDBOX_DATA_DIR ?? "/data",
    enabled: env.OMNI_SANDBOX_ENABLED === "true",
    bwrapPath: env.OMNI_SANDBOX_BWRAP ?? "/usr/bin/bwrap",
    supervisorPath: env.OMNI_SANDBOX_SUPERVISOR ?? "/usr/local/bin/omni-sandbox-supervisor",
    limits: {
      commandTimeoutSec: boundedInt(env.OMNI_SANDBOX_COMMAND_TIMEOUT_SEC, 60, 1, 300),
      cpuSec: boundedInt(env.OMNI_SANDBOX_CPU_SEC, 60, 1, 300),
      memoryMb: boundedInt(env.OMNI_SANDBOX_MEMORY_MB, 1024, 64, 8192),
      maxProcesses: boundedInt(env.OMNI_SANDBOX_MAX_PROCESSES, 128, 8, 512),
      fileSizeMb: boundedInt(env.OMNI_SANDBOX_FILE_MB, 64, 1, 2048),
      outputCapBytes: boundedInt(env.OMNI_SANDBOX_OUTPUT_CAP_BYTES, MAX_OUTPUT_BYTES, 1024, 1048576),
      maxSessions: boundedInt(env.OMNI_SANDBOX_MAX_SESSIONS, 3, 1, MAX_SESSIONS),
      idleMinutes: 10,
      sessionMinutes: 60,
      workspaceMb: boundedInt(env.OMNI_SANDBOX_WORKSPACE_MB, 128, 16, 512),
      workspaceInodes: boundedInt(env.OMNI_SANDBOX_WORKSPACE_INODES, 8192, 256, 32768),
    },
  };
  if (!CLIENT.test(config.clientId)) throw new Error("OMNI_SANDBOX_CLIENT_ID is missing or invalid.");
  if (config.secret.length < 32) throw new Error("OMNI_SANDBOX_HMAC_SECRET must be at least 32 characters.");
  if (config.controlSecret && (config.controlSecret.length < 32 || config.controlSecret === config.secret))
    throw new Error("OMNI_SANDBOX_CONTROL_SECRET must be a distinct secret of at least 32 characters.");
  if (config.enabled && !config.controlSecret)
    throw new Error("Execution requires the separate OMNI_SANDBOX_CONTROL_SECRET for Emergency Stop.");
  if (!path.isAbsolute(config.dataDir)) throw new Error("OMNI_SANDBOX_DATA_DIR must be absolute.");
  return config;
}

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const hmac = (key, value) => createHmac("sha256", key).update(value).digest("hex");

function constantTimeHexEqual(actual, expected) {
  if (!HEX_64.test(actual) || !HEX_64.test(expected)) return false;
  return timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function newState() {
  return { version: 1, emergencyStop: true, nonces: {}, sessions: {} };
}

function privateDataDirectory(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const info = fs.lstatSync(dir);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("sandbox data path must be a real directory.");
  fs.chmodSync(dir, 0o700);
}

function recoverState(state) {
  state.emergencyStop = true;
  state.nonces ??= {};
  state.sessions ??= {};
  for (const session of Object.values(state.sessions)) {
    if (session.status === "active") {
      session.status = "ended";
      session.endedAt = Date.now();
    }
    for (const job of Object.values(session.jobs ?? {})) {
      if (["queued", "awaiting_approval", "running"].includes(job.status)) {
        job.status = "stopped";
        job.exitCode = -1;
        job.events ??= [];
        job.events.push({ stream: "system", text: "Service restarted; the command was not resumed." });
      }
      delete job.pending;
      delete job.command;
    }
  }
  for (const [nonce, timestamp] of Object.entries(state.nonces)) {
    if (!Number.isFinite(timestamp) || Date.now() - timestamp > 5 * 60_000) delete state.nonces[nonce];
  }
  return state;
}

function diskState(state) {
  const sessions = {};
  for (const [id, session] of Object.entries(state.sessions)) {
    const jobs = {};
    for (const [jobId, job] of Object.entries(session.jobs ?? {})) {
      jobs[jobId] = {
        id: job.id,
        status: job.status,
        createdAt: job.createdAt,
        finishedAt: job.finishedAt ?? null,
        exitCode: job.exitCode ?? null,
        cursor: job.cursor ?? 0,
        events: (job.events ?? []).map((event) => ({
          stream: event.stream,
          data: Buffer.from(event.text, "utf8").toString("base64"),
        })),
      };
    }
    sessions[id] = {
      id: session.id,
      agentId: session.agentId,
      allowedActions: session.allowedActions ?? [],
      sandboxId: session.sandboxId,
      sandboxName: session.sandboxName,
      status: session.status,
      startedAt: session.startedAt,
      lastAt: session.lastAt,
      endedAt: session.endedAt ?? null,
      jobs,
    };
  }
  return { version: 1, emergencyStop: state.emergencyStop, nonces: state.nonces, sessions };
}

function parseState(file) {
  const raw = fs.readFileSync(file);
  if (raw.length > 160 * 1024 * 1024) throw new Error("sandbox state exceeds the recovery limit.");
  const parsed = JSON.parse(raw.toString("utf8"));
  if (parsed.version !== 1 || typeof parsed.sessions !== "object" || typeof parsed.nonces !== "object")
    throw new Error("sandbox state is invalid; execution remains unavailable.");
  for (const session of Object.values(parsed.sessions)) {
    for (const job of Object.values(session.jobs ?? {})) {
      job.events = (job.events ?? []).map((event) => ({
        stream: event.stream,
        text: Buffer.from(event.data ?? "", "base64").toString("utf8"),
      }));
    }
  }
  return recoverState(parsed);
}

function createSupervisor(config, onExit) {
  const args = [
    "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
    "--disable-userns", "--die-with-parent", "--new-session",
    "--ro-bind", "/usr", "/usr",
    "--ro-bind", "/bin", "/bin",
    "--ro-bind", "/lib", "/lib",
    "--ro-bind", "/lib64", "/lib64",
    "--dir", "/etc",
    "--ro-bind", "/etc/passwd", "/etc/passwd",
    "--ro-bind", "/etc/group", "/etc/group",
    "--ro-bind", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
    "--proc", "/proc",
    "--dev", "/dev",
    "--tmpfs", "/tmp",
    "--dir", "/workspace",
    "--chdir", "/workspace",
    "--clearenv",
    "--setenv", "HOME", "/workspace",
    "--setenv", "LANG", "C.UTF-8",
    "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
    "--setenv", "TERM", "dumb",
    "--", config.supervisorPath, "--workspace",
    String(config.limits.workspaceMb), String(config.limits.workspaceInodes),
  ];
  const child = spawn(config.bwrapPath, args, {
    env: { PATH: "/usr/bin:/bin" },
    stdio: ["pipe", "pipe", "pipe"],
    detached: true,
  });
  const lines = readline.createInterface({ input: child.stdout });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    if (stderr.length < 2048) stderr += chunk.toString("utf8").slice(0, 2048 - stderr.length);
  });
  const listeners = new Map();
  let readyResolve;
  let readyReject;
  const ready = new Promise((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  let closed = false;
  const exitPromise = new Promise((resolve) => {
    child.once("close", (code, signal) => {
      closed = true;
      lines.close();
      readyReject?.(new Error("sandbox supervisor exited before readiness."));
      for (const listener of listeners.values()) listener({ type: "error", error: "sandbox supervisor exited" });
      listeners.clear();
      onExit?.(code, signal, stderr);
      resolve();
    });
  });
  lines.on("line", (line) => {
    let message;
    try { message = JSON.parse(line); } catch { return; }
    if (message.type === "ready") {
      readyResolve(message);
      readyResolve = null;
      readyReject = null;
      return;
    }
    const listener = listeners.get(message.jobId);
    if (listener) listener(message);
  });

  const send = (value) => {
    if (closed || child.stdin.destroyed) throw new Error("sandbox supervisor is unavailable.");
    child.stdin.write(`${JSON.stringify(value)}\n`);
  };
  return {
    child,
    ready,
    run(jobId, command, limits, listener) {
      listeners.set(jobId, listener);
      send({
        type: "run", jobId, command,
        limits: {
          timeoutSec: limits.commandTimeoutSec,
          cpuSec: limits.cpuSec,
          memoryMb: limits.memoryMb,
          maxProcesses: limits.maxProcesses,
          fileSizeMb: limits.fileSizeMb,
          outputCapBytes: limits.outputCapBytes,
        },
      });
    },
    cancel(jobId) { if (!closed) send({ type: "cancel", jobId }); },
    finish(jobId) { listeners.delete(jobId); },
    async close() {
      if (!closed) {
        try { send({ type: "shutdown" }); } catch {}
        const timer = new Promise((resolve) => setTimeout(resolve, 1500));
        await Promise.race([exitPromise, timer]);
        if (!closed && child.pid) {
          try { process.kill(-child.pid, "SIGKILL"); } catch {}
          await exitPromise;
        }
      }
    },
    async terminate() {
      if (closed) return;
      if (child.pid) {
        try { process.kill(-child.pid, "SIGKILL"); } catch {}
      }
      await exitPromise;
    },
  };
}

async function probeIsolation(config, launcher = createSupervisor) {
  let supervisor;
  let timer;
  try {
    supervisor = launcher(config);
    const ready = await Promise.race([
      supervisor.ready,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("isolation probe timed out")), 5000); }),
    ]);
    const envNames = Array.isArray(ready.envNames) ? ready.envNames : [];
    const allowed = envNames.every((name) => ENV_NAMES.includes(name));
    const valid = ready.uid > 0 && ready.networkIsolated === true && ready.exitCode === 0 && allowed;
    return {
      network: valid ? "isolated" : "open",
      uid: Number.isInteger(ready.uid) ? ready.uid : 0,
      perSessionUser: valid,
      envNames,
      probeExitCode: valid ? 0 : 1,
    };
  } catch {
    return { network: "open", uid: 0, perSessionUser: false, envNames: [], probeExitCode: 1 };
  } finally {
    clearTimeout(timer);
    await supervisor?.close();
  }
}

export async function createSandbox(config, options = {}) {
  privateDataDirectory(config.dataDir);
  const stateFile = path.join(config.dataDir, "state.json");
  let state;
  try {
    state = parseState(stateFile);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    state = newState();
  }
  const sessions = state.sessions;
  const runtime = new Map();
  const launcher = options.launchSession ?? createSupervisor;
  const probe = options.probe ?? await probeIsolation(config, launcher);
  const now = () => Date.now();

  function persist() {
    const temporary = path.join(config.dataDir, `.state-${process.pid}-${randomUUID()}`);
    const file = fs.openSync(temporary, "wx", 0o600);
    try {
      fs.writeFileSync(file, JSON.stringify(diskState(state)));
      fs.fsyncSync(file);
    } finally {
      fs.closeSync(file);
    }
    try { fs.renameSync(temporary, stateFile); } finally {
      try { fs.unlinkSync(temporary); } catch {}
    }
    const directory = fs.openSync(config.dataDir, "r");
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  }

  persist();

  const isolationValid = probe.network === "isolated" && probe.uid > 0 &&
    probe.perSessionUser && probe.probeExitCode === 0 &&
    probe.envNames.every((name) => ENV_NAMES.includes(name));

  function executionGate() {
    if (!config.enabled) throw new Refusal("Sandbox execution is disabled.");
    if (state.emergencyStop) throw new Refusal("Emergency Stop is engaged.");
    if (!isolationValid) throw new Refusal("Host isolation self-test failed; execution is unavailable.");
  }

  function appendEvent(job, stream, text) {
    const data = Buffer.from(String(text), "utf8");
    const used = job.outputBytes ?? 0;
    const remaining = Math.max(0, config.limits.outputCapBytes - used);
    if (remaining === 0) return false;
    const slice = data.subarray(0, remaining);
    job.events.push({ stream, text: slice.toString("utf8") });
    job.outputBytes = used + slice.length;
    if (slice.length < data.length && !job.outputCapped) {
      job.events.push({ stream: "system", text: "Output cap reached; command stopped." });
      job.outputCapped = true;
    }
    persist();
    return slice.length === data.length;
  }

  function currentSession(sessionId, allowEnded = false) {
    const session = sessions[sessionId];
    if (!session || (session.status !== "active" && !allowEnded))
      throw new Refusal("Session not found or already ended.");
    if (session.status === "active") {
      session.lastAt = now();
      persist();
    }
    return session;
  }

  function eventReply(session, job, nonce) {
    const steps = job.steps.splice(0, 200);
    let bytes = 0;
    while (job.cursor < job.events.length && bytes < MAX_EVENTS_PER_REPLY && steps.length < 200) {
      const event = job.events[job.cursor];
      const body = Buffer.from(event.text, "utf8")
        .subarray(0, MAX_EVENTS_PER_REPLY - bytes)
        .toString("utf8");
      bytes += Buffer.byteLength(body);
      steps.push({
        id: `out-${job.cursor}`,
        kind: event.stream === "system" ? "result" : "output",
        title: event.stream === "system" ? "Sandbox" : "",
        body,
        ...(event.stream === "stdout" || event.stream === "stderr" ? { stream: event.stream } : {}),
        status: event.stream === "system" ? "failed" : "done",
      });
      job.cursor++;
    }
    persist();
    const status = job.status === "awaiting_approval" ? "queued" : job.status;
    return {
      contract: CONTRACT,
      requestNonce: nonce,
      session: session ? { sandboxId: session.sandboxId, sandboxName: session.sandboxName, model: null } : undefined,
      job: job ? { status, cursor: String(job.cursor) } : undefined,
      steps,
    };
  }

  function jobReply(session, job, nonce) {
    return eventReply(session, job, nonce);
  }

  function recordJob(session, jobId) {
    const existing = session.jobs[jobId];
    if (existing) return existing;
    const jobs = Object.values(session.jobs);
    if (jobs.length >= MAX_JOBS_PER_SESSION) {
      const oldest = jobs.filter((job) => ["done", "failed", "stopped"].includes(job.status))
        .sort((a, b) => a.createdAt - b.createdAt)[0];
      if (!oldest) throw new Refusal("Session job history is full.");
      delete session.jobs[oldest.id];
    }
    const job = {
      id: jobId, status: "queued", createdAt: now(), finishedAt: null, exitCode: null,
      cursor: 0, outputBytes: 0, events: [], steps: [], pending: null,
    };
    session.jobs[jobId] = job;
    return job;
  }

  async function stopJob(session, job, reason = "owner") {
    if (["done", "failed", "stopped"].includes(job.status)) return;
    const wasRunning = job.status === "running";
    const supervisor = runtime.get(session.id);
    job.pending = null;
    job.status = "stopped";
    job.exitCode = -1;
    job.finishedAt = now();
    job.events.push({ stream: "system", text: `Stopped (${reason}).` });
    let failure;
    try { persist(); } catch (error) { failure = error; }
    if (supervisor && wasRunning) {
      let completed = false;
      const done = new Promise((resolve) => {
        const previous = job.onDone;
        job.onDone = () => { completed = true; previous?.(); resolve(); };
      });
      try { supervisor.cancel(job.id); } catch {}
      const timer = new Promise((resolve) => setTimeout(resolve, 1000));
      await Promise.race([done, timer]);
      if (!completed) {
        try { await supervisor.terminate(); } catch (error) { failure ??= error; }
        runtime.delete(session.id);
        session.status = "ended";
        session.endedAt = now();
        try { persist(); } catch (error) { failure ??= error; }
      }
    }
    if (failure) throw failure;
  }

  async function endSession(session, reason = "owner") {
    if (!["active", "starting"].includes(session.status)) return;
    let failure;
    const jobs = Object.values(session.jobs);
    for (const job of jobs) {
      try { await stopJob(session, job, reason); } catch (error) { failure ??= error; }
    }
    const supervisor = runtime.get(session.id);
    runtime.delete(session.id);
    if (supervisor) {
      try { await supervisor.close(); } catch (error) { failure ??= error; }
    }
    session.status = "ended";
    session.endedAt = now();
    try { persist(); } catch (error) { failure ??= error; }
    if (failure) throw failure;
  }

  async function startSession(body) {
    executionGate();
    const { sessionId, agentId } = body;
    if (!UUID.test(sessionId ?? "") || !AGENT.test(agentId ?? "")) throw new Refusal("Invalid session or agent.");
    if (body.allowedActions !== undefined &&
        (!Array.isArray(body.allowedActions) || body.allowedActions.length > 3 ||
         body.allowedActions.some((action) => !["chat", "edit_files", "run_commands"].includes(action))))
      throw new Refusal("Invalid session permissions.");
    if (body.repository || body.ref) throw new Refusal("Repository checkout is not enabled on this shell-only service.");
    const prior = sessions[sessionId];
    if (prior?.status === "active") {
      prior.lastAt = now();
      persist();
      return { session: { sandboxId: prior.sandboxId, sandboxName: prior.sandboxName, model: null } };
    }
    if (prior) throw new Refusal("Session ended; start a new session.");
    if (Object.values(sessions).filter((item) => item.status === "active" || item.status === "starting").length >= config.limits.maxSessions)
      throw new Refusal(`At most ${config.limits.maxSessions} sessions at once.`);

    const session = {
      id: sessionId,
      agentId,
      allowedActions: Array.isArray(body.allowedActions) ? [...new Set(body.allowedActions)] : [],
      sandboxId: `sbx-${randomUUID().slice(0, 8)}`,
      sandboxName: "OMNI isolated shell",
      status: "starting",
      startedAt: now(),
      lastAt: now(),
      endedAt: null,
      jobs: {},
    };
    sessions[sessionId] = session;
    for (const [id, old] of Object.entries(sessions)) {
      if (Object.keys(sessions).length <= MAX_RETAINED_SESSIONS) break;
      if (old.status === "ended") delete sessions[id];
    }
    persist();

    const supervisor = launcher(config, (code) => {
      for (const job of Object.values(sessions[sessionId]?.jobs ?? {})) {
        if (job.status === "running") {
          job.status = "failed";
          job.exitCode = -1;
          job.finishedAt = now();
          job.events.push({ stream: "system", text: `Sandbox supervisor exited (${code ?? "signal"}).` });
        }
      }
      persist();
    });
    runtime.set(sessionId, supervisor);
    let ready;
    let timer;
    try {
      ready = await Promise.race([
        supervisor.ready,
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("sandbox startup timed out")), 5000); }),
      ]);
    } catch {
      await supervisor.terminate();
      runtime.delete(sessionId);
      session.status = "ended";
      session.endedAt = now();
      persist();
      throw new Refusal("Sandbox supervisor failed to start.");
    } finally {
      clearTimeout(timer);
    }
    if (session.status !== "starting" || state.emergencyStop || !config.enabled) {
      await supervisor.close();
      runtime.delete(sessionId);
      session.status = "ended";
      session.endedAt = now();
      persist();
      throw new Refusal("Sandbox stopped before the session became ready.");
    }
    if (ready.exitCode !== 0 || ready.uid <= 0 || !ready.networkIsolated ||
        !ready.envNames.every((name) => ENV_NAMES.includes(name))) {
      await supervisor.close();
      runtime.delete(sessionId);
      session.status = "ended";
      session.endedAt = now();
      persist();
      throw new Refusal("Sandbox isolation self-test failed.");
    }
    session.status = "active";
    persist();
    return { session: { sandboxId: session.sandboxId, sandboxName: session.sandboxName, model: null } };
  }

  async function workspaceAction(body, nonce) {
    if (!body || typeof body !== "object" || Array.isArray(body) ||
        body.contract !== undefined && body.contract !== CONTRACT ||
        typeof body.projectId !== "string" || body.projectId !== config.projectId ||
        typeof body.action !== "string")
      throw new Refusal("Invalid workspace request.");
    switch (body.action) {
      case "health.check":
        return {
          health: {
            service: "omni-sandbox",
            version: VERSION,
            isolation: probe,
            limits: {
              commandTimeoutSec: config.limits.commandTimeoutSec,
              cpuSec: config.limits.cpuSec,
              memoryMb: config.limits.memoryMb,
              maxProcesses: config.limits.maxProcesses,
              fileSizeMb: config.limits.fileSizeMb,
              outputCapBytes: config.limits.outputCapBytes,
              maxSessions: config.limits.maxSessions,
              idleMinutes: config.limits.idleMinutes,
              sessionMinutes: config.limits.sessionMinutes,
            },
            providers: [],
            github: { configured: false, repositories: [], checkedAt: null },
            autonomy: "off",
            merge: "never",
            executionEnabled: config.enabled,
            emergencyStop: state.emergencyStop,
          },
        };
      case "session.start":
        return startSession(body);
      case "command.run": {
        executionGate();
        const session = currentSession(body.sessionId);
        if (!session.allowedActions?.includes("run_commands"))
          throw new Refusal("This session is not authorized to run commands.");
        if (!UUID.test(body.jobId ?? "") || typeof body.command !== "string" ||
            !body.command.trim() || body.command.length > 2000)
          throw new Refusal("Invalid command or job ID.");
        const existing = session.jobs[body.jobId];
        if (existing) return jobReply(session, existing, nonce);
        const job = recordJob(session, body.jobId);
        job.pending = { kind: "command", command: body.command };
        job.status = "awaiting_approval";
        job.steps.push({
          id: "cmd", kind: "command", title: body.command.slice(0, 200), body: body.command,
          status: "pending_approval",
        });
        persist();
        return jobReply(session, job, nonce);
      }
      case "step.decide": {
        executionGate();
        const session = currentSession(body.sessionId);
        const job = session.jobs[body.jobId];
        if (!job || !job.pending || body.stepId !== "cmd" || typeof body.approve !== "boolean")
          throw new Refusal("Nothing is waiting for that owner decision.");
        if (!body.approve) {
          job.pending = null;
          job.status = "stopped";
          job.exitCode = -1;
          job.finishedAt = now();
          job.steps.push({ id: `rej-${randomUUID().slice(0, 8)}`, kind: "result", title: "Rejected by owner", body: "Nothing was run.", status: "failed" });
          persist();
          return jobReply(session, job, nonce);
        }
        const supervisor = runtime.get(session.id);
        if (!supervisor) throw new Refusal("Sandbox session is unavailable.");
        const command = job.pending.command;
        job.pending = null;
        job.status = "running";
        persist();
        supervisor.run(job.id, command, config.limits, (message) => {
          if (message.type === "output") {
            if (message.stream === "system") {
              job.events.push({ stream: "system", text: message.text });
              persist();
            } else {
              appendEvent(job, message.stream, message.text);
            }
            if ((job.outputBytes ?? 0) >= config.limits.outputCapBytes) {
              try { supervisor.cancel(job.id); } catch {}
            }
          } else if (message.type === "done") {
            job.status = ["cancelled", "stopped"].includes(message.reason) ? "stopped" : message.exitCode === 0 ? "done" : "failed";
            job.exitCode = message.exitCode;
            job.finishedAt = now();
            if (message.reason === "timeout") job.events.push({ stream: "system", text: "Command time limit reached." });
            if (message.reason === "output_cap" && !job.outputCapped) {
              job.events.push({ stream: "system", text: "Output cap reached; command stopped." });
              job.outputCapped = true;
            }
            job.onDone?.();
            persist();
            supervisor.finish(job.id);
          } else if (message.type === "error") {
            job.status = "failed";
            job.exitCode = -1;
            job.finishedAt = now();
            job.events.push({ stream: "system", text: "Command supervisor failed." });
            job.onDone?.();
            persist();
            supervisor.finish(job.id);
          }
        });
        return jobReply(session, job, nonce);
      }
      case "events.poll": {
        const session = currentSession(body.sessionId, true);
        const job = session.jobs[body.jobId];
        if (!job) throw new Refusal("Job not found.");
        return jobReply(session, job, nonce);
      }
      case "job.stop": {
        const session = currentSession(body.sessionId, true);
        const job = session.jobs[body.jobId];
        if (job) await stopJob(session, job, "owner");
        return {};
      }
      case "agent.stop": {
        if (body.agentId !== undefined && !AGENT.test(body.agentId)) throw new Refusal("Invalid agent ID.");
        const matches = Object.values(sessions).filter((session) =>
          ["active", "starting"].includes(session.status) &&
          (!body.agentId || session.agentId === body.agentId));
        await Promise.all(matches.map((session) => endSession(session, "agent stop")));
        return {};
      }
      case "session.end": {
        const session = currentSession(body.sessionId, true);
        await endSession(session, "owner");
        return {};
      }
      case "repo.checkout":
      case "pr.propose":
      case "chat.send":
        throw new Refusal("This service supports only owner-approved shell sessions.");
      default:
        throw new Refusal("Unknown action.");
    }
  }

  function authenticate(req, raw, secret, contract, route, prefix = "") {
    const timestamp = String(req.headers[`${prefix}timestamp`] ?? "");
    const nonce = String(req.headers[`${prefix}nonce`] ?? "");
    const signature = String(req.headers[`${prefix}signature`] ?? "");
    const seconds = Number(timestamp);
    const fresh = /^\d{10}$/.test(timestamp) && Math.abs(Date.now() / 1000 - seconds) <= 60;
    if (!fresh || !HEX_32.test(nonce)) return null;
    if (contract === CONTRACT && req.headers["x-omni-client"] !== config.clientId) return null;
    const key = `${contract}:${nonce}`;
    if (Object.hasOwn(state.nonces, key) || Object.keys(state.nonces).length >= 4096) return null;
    const digest = sha256(raw);
    const message = prefix
      ? `${contract}\nPOST\n${route}\n${timestamp}\n${nonce}\n${digest}`
      : `${contract}\nPOST\n${route}\n${timestamp}\n${nonce}\n${digest}`;
    if (!constantTimeHexEqual(signature, hmac(secret, message))) return null;
    state.nonces[key] = Date.now();
    persist();
    return nonce;
  }

  function signedReply(res, status, nonce, payload, contract, secret) {
    const body = JSON.stringify({ contract, requestNonce: nonce, steps: [], ...payload });
    const proof = hmac(secret, `${contract}\nresponse\n${nonce}\n${status}\n${body}`);
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "x-omni-proof": proof });
    res.end(body);
  }

  async function readBody(req) {
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) throw new Refusal("Request body exceeds the limit.");
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }

  async function route(req, res) {
    if (req.method === "GET" && req.url === "/healthz") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ ok: true, executionEnabled: config.enabled, emergencyStop: state.emergencyStop }));
      return;
    }
    if (req.method !== "POST" || (req.url !== WORKSPACE_PATH && req.url !== CONTROL_PATH)) {
      res.writeHead(404).end();
      return;
    }
    let raw;
    try { raw = await readBody(req); } catch {
      res.writeHead(413).end();
      return;
    }
    if (req.url === CONTROL_PATH) {
      if (!config.controlSecret) { res.writeHead(404).end(); return; }
      const nonce = authenticate(req, raw, config.controlSecret, CONTROL_CONTRACT, CONTROL_PATH, "x-omni-control-");
      if (!nonce) { res.writeHead(401).end(); return; }
      try {
        const body = JSON.parse(raw.toString("utf8"));
        if (body.action === "engage") {
          state.emergencyStop = true;
          let failure;
          try { persist(); } catch (error) { failure = error; }
          const stopped = await Promise.allSettled(
            Object.values(sessions).map((session) => endSession(session, "Emergency Stop")),
          );
          if (stopped.some((result) => result.status === "rejected")) failure ??= new Error("session stop failed");
          if (failure) throw failure;
        } else if (body.action === "clear") {
          state.emergencyStop = false;
          try { persist(); } catch (error) {
            state.emergencyStop = true;
            throw error;
          }
        } else {
          throw new Refusal("Unknown Emergency Stop action.");
        }
        signedReply(res, 200, nonce, { job: undefined, session: undefined }, CONTROL_CONTRACT, config.controlSecret);
      } catch {
        signedReply(res, 409, nonce, { error: "Emergency Stop request refused." }, CONTROL_CONTRACT, config.controlSecret);
      }
      return;
    }
    const nonce = authenticate(req, raw, config.secret, CONTRACT, WORKSPACE_PATH, "x-omni-");
    if (!nonce) { res.writeHead(401).end(); return; }
    try {
      const body = JSON.parse(raw.toString("utf8"));
      if (body.projectId !== config.projectId) throw new Refusal("Wrong project.");
      if (!config.enabled && body.action !== "health.check") throw new Refusal("Sandbox execution is disabled.");
      const payload = await workspaceAction(body, nonce);
      const { contract: _contract, requestNonce: _nonce, ...data } = payload;
      signedReply(res, body.action === "command.run" ? 202 : 200, nonce, data, CONTRACT, config.secret);
    } catch (error) {
      const text = error instanceof Refusal ? error.message : "Request failed.";
      signedReply(res, 409, nonce, { error: text }, CONTRACT, config.secret);
    }
  }

  const server = http.createServer((req, res) => { void route(req, res); });
  const reaper = setInterval(() => {
    const current = now();
    for (const session of Object.values(sessions)) {
      if (session.status === "active" &&
          (current - session.lastAt >= IDLE_MS || current - session.startedAt >= SESSION_MS))
        void endSession(session, "timeout");
    }
    for (const [nonce, timestamp] of Object.entries(state.nonces)) {
      if (current - timestamp > 5 * 60_000) delete state.nonces[nonce];
    }
    persist();
  }, 15_000);
  reaper.unref();

  return {
    server,
    health: probe,
    state,
    async close() {
      clearInterval(reaper);
      for (const session of Object.values(sessions)) await endSession(session, "service shutdown");
      await new Promise((resolve) => server.close(resolve));
      persist();
    },
  };
}

class Refusal extends Error {}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  let config;
  try {
    config = loadConfig();
    const app = await createSandbox(config);
    app.server.listen(config.port, () => {
      console.log(`omni-sandbox ${VERSION}: enabled=${config.enabled} network=${app.health.network}`);
    });
    for (const signal of ["SIGTERM", "SIGINT"]) {
      process.once(signal, () => { void app.close().finally(() => process.exit(0)); });
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : "sandbox startup failed");
    process.exit(1);
  }
}
