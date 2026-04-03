/**
 * Container Runner for NanoClaw
 * Spawns agent execution in containers and handles IPC
 */
import { ChildProcess, exec, spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

import {
  CONTAINER_IMAGE,
  CONTAINER_MAX_OUTPUT_SIZE,
  CONTAINER_TIMEOUT,
  CREDENTIAL_PROXY_PORT,
  DATA_DIR,
  GROUPS_DIR,
  IDLE_TIMEOUT,
  TIMEZONE,
} from './config.js';
import { resolveGroupFolderPath, resolveGroupIpcPath } from './group-folder.js';
import { logger } from './logger.js';
import {
  CONTAINER_HOST_GATEWAY,
  CONTAINER_RUNTIME_BIN,
  hostGatewayArgs,
  readonlyMountArgs,
  stopContainer,
} from './container-runtime.js';
import { detectAuthMode } from './credential-proxy.js';
import { validateAdditionalMounts } from './mount-security.js';
import { RegisteredGroup } from './types.js';
import { readEnvFile } from './env.js';

// Langfuse keys — read at startup from .env (systemd service doesn't source it)
const _lfEnv = readEnvFile([
  'LANGFUSE_HOST',
  'LANGFUSE_PUBLIC_KEY',
  'LANGFUSE_SECRET_KEY',
  'LANGFUSE_NETWORK',
  'ENABLE_MODEL_ROUTING',
  'MODEL_HAIKU',
  'MODEL_SONNET',
  'DISCORD_BOT_TOKEN',
]);
const LF_HOST = process.env.LANGFUSE_HOST || _lfEnv.LANGFUSE_HOST;
const LF_PUBLIC_KEY =
  process.env.LANGFUSE_PUBLIC_KEY || _lfEnv.LANGFUSE_PUBLIC_KEY;
const LF_SECRET_KEY =
  process.env.LANGFUSE_SECRET_KEY || _lfEnv.LANGFUSE_SECRET_KEY;

// Model routing — opt-in via ENABLE_MODEL_ROUTING=true in .env
const ROUTING_ENABLED =
  (process.env.ENABLE_MODEL_ROUTING || _lfEnv.ENABLE_MODEL_ROUTING) === 'true';
const MODEL_HAIKU =
  process.env.MODEL_HAIKU || _lfEnv.MODEL_HAIKU || 'claude-haiku-4-5';
const MODEL_SONNET =
  process.env.MODEL_SONNET || _lfEnv.MODEL_SONNET || 'claude-sonnet-4-5';

// Discord bot token — read from .env for container injection (enables scheduled tasks to post to Discord channels)
const DISCORD_BOT_TOKEN =
  process.env.DISCORD_BOT_TOKEN || _lfEnv.DISCORD_BOT_TOKEN;

// Session freshness — start a new session if idle >1h to avoid paying for stale context windows.
// Per Anthropic recommendation: https://x.com/lydiahallie/status/2039800718371307603
const SESSION_IDLE_THRESHOLD_MS = 60 * 60 * 1000; // 1 hour

// Intent-based phrases that indicate genuine complexity requiring Sonnet.
// These are PHRASES not single words — avoids false positives on conversational messages.
// Rule: if a message is asking me to *do something technical*, it needs Sonnet.
// If it's asking me a question, checking status, or having a conversation → Haiku.
const SONNET_PHRASES = [
  // Code & engineering work
  'write code',
  'write a script',
  'write a function',
  'build a',
  'implement',
  'debug this',
  'debug the',
  'fix the bug',
  'fix this',
  'refactor',
  'deploy ',
  'configure the',
  'patch the',
  'commit to',
  // Deep analysis & research
  'analyze the',
  'analyze this',
  'deep research',
  'investigate the',
  'synthesize',
  'multi-source',
  'run a report',
  'produce a report',
  // Agent orchestration
  'spawn an agent',
  'delegate to',
  'run the agent',
  'launch the agent',
  // Complex creation tasks
  'generate a full',
  'create a plan',
  'design a system',
  'architect',
  'build out',
  'set up a pipeline',
  'wire up',
  'integrate with',
];

/**
 * Select the Claude model for this request.
 * Haiku default — Sonnet only for clearly complex technical work.
 * Scheduled tasks always use Haiku (cost optimization).
 * Only active when ENABLE_MODEL_ROUTING=true — otherwise always returns Sonnet.
 */
function selectModel(input: ContainerInput): string {
  if (!ROUTING_ENABLED) return MODEL_SONNET;

  // Scheduled tasks are always Haiku — summaries, reminders, heartbeats don't need Sonnet
  if (input.isScheduledTask) {
    logger.debug('Model routing: scheduled task → Haiku');
    return MODEL_HAIKU;
  }

  const text = input.prompt.toLowerCase();
  const length = input.prompt.length;

  // Very long prompts with technical content are complex (raised threshold from 400 → 1500)
  if (length > 1500) return MODEL_SONNET;

  // Intent-based phrase match → Sonnet
  if (SONNET_PHRASES.some((phrase) => text.includes(phrase)))
    return MODEL_SONNET;

  // Everything else → Haiku (conversational, status checks, simple questions)
  logger.debug({ promptLength: length }, 'Model routing: selected Haiku');
  return MODEL_HAIKU;
}

/**
 * Generate OpenTelemetry-style trace IDs for request correlation.
 * traceId: Session-level identifier (persists across container operations)
 * spanId: Operation-level identifier (unique per container spawn)
 */
function generateTraceIds(sessionId?: string): {
  traceId: string;
  spanId: string;
} {
  // Use existing sessionId as traceId for correlation, or generate new one
  const traceId = sessionId || crypto.randomUUID();
  const spanId = crypto.randomBytes(8).toString('hex');
  return { traceId, spanId };
}

// Sentinel markers for robust output parsing (must match agent-runner)
const OUTPUT_START_MARKER = '---NANOCLAW_OUTPUT_START---';
const OUTPUT_END_MARKER = '---NANOCLAW_OUTPUT_END---';

export interface ContainerInput {
  prompt: string;
  sessionId?: string;
  groupFolder: string;
  chatJid: string;
  isMain: boolean;
  isScheduledTask?: boolean;
  assistantName?: string;
}

export interface ContainerOutput {
  status: 'success' | 'error';
  result: string | null;
  newSessionId?: string;
  error?: string;
}

interface VolumeMount {
  hostPath: string;
  containerPath: string;
  readonly: boolean;
}

function buildVolumeMounts(
  group: RegisteredGroup,
  isMain: boolean,
): VolumeMount[] {
  const mounts: VolumeMount[] = [];
  const projectRoot = process.cwd();
  const groupDir = resolveGroupFolderPath(group.folder);

  if (isMain) {
    // Main gets the project root read-only. Writable paths the agent needs
    // (group folder, IPC, .claude/) are mounted separately below.
    // Read-only prevents the agent from modifying host application code
    // (src/, dist/, package.json, etc.) which would bypass the sandbox
    // entirely on next restart.
    mounts.push({
      hostPath: projectRoot,
      containerPath: '/workspace/project',
      readonly: true,
    });

    // Shadow .env so the agent cannot read secrets from the mounted project root.
    // Credentials are injected by the credential proxy, never exposed to containers.
    const envFile = path.join(projectRoot, '.env');
    if (fs.existsSync(envFile)) {
      mounts.push({
        hostPath: '/dev/null',
        containerPath: '/workspace/project/.env',
        readonly: true,
      });
    }

    // Main also gets its group folder as the working directory
    mounts.push({
      hostPath: groupDir,
      containerPath: '/workspace/group',
      readonly: false,
    });
  } else {
    // Other groups only get their own folder
    mounts.push({
      hostPath: groupDir,
      containerPath: '/workspace/group',
      readonly: false,
    });
  }

  // Global shared directory — readable and writable for ALL groups (including main).
  // Used for shared memory graph and other cross-group persistent data.
  // Only directory mounts are supported, not file mounts
  const globalDir = path.join(GROUPS_DIR, 'global');
  if (fs.existsSync(globalDir)) {
    mounts.push({
      hostPath: globalDir,
      containerPath: '/workspace/global',
      readonly: false,
    });
  }

  // GSD (get-shit-done) runtime — mount the host's GSD installation at its
  // original absolute path so slash commands that reference
  // @/home/claude-agent/.claude/get-shit-done/... resolve correctly inside containers.
  // GSD slash commands live in the per-group .claude/commands/gsd/ (installed via
  // install-gsd-in-groups.sh), but their workflow files reference this path.
  const gsdRuntimeDir = path.join(
    process.env.HOME || '/home/claude-agent',
    '.claude',
    'get-shit-done',
  );
  if (fs.existsSync(gsdRuntimeDir)) {
    mounts.push({
      hostPath: gsdRuntimeDir,
      containerPath: gsdRuntimeDir, // same path so @-file refs resolve
      readonly: true,
    });
  }

  // Per-group Claude sessions directory (isolated from other groups)
  // Each group gets their own .claude/ to prevent cross-group session access
  const groupSessionsDir = path.join(
    DATA_DIR,
    'sessions',
    group.folder,
    '.claude',
  );
  fs.mkdirSync(groupSessionsDir, { recursive: true });
  const settingsFile = path.join(groupSessionsDir, 'settings.json');
  if (!fs.existsSync(settingsFile)) {
    fs.writeFileSync(
      settingsFile,
      JSON.stringify(
        {
          env: {
            // Enable agent swarms (subagent orchestration)
            // https://code.claude.com/docs/en/agent-teams#orchestrate-teams-of-claude-code-sessions
            CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS: '1',
            // Load CLAUDE.md from additional mounted directories
            // https://code.claude.com/docs/en/memory#load-memory-from-additional-directories
            CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD: '1',
            // Enable Claude's memory feature (persists user preferences between sessions)
            // https://code.claude.com/docs/en/memory#manage-auto-memory
            CLAUDE_CODE_DISABLE_AUTO_MEMORY: '0',
            // Persist RTK token-savings tracking across ephemeral containers
            XDG_DATA_HOME: '/workspace/group/rtk-data',
          },
        },
        null,
        2,
      ) + '\n',
    );
  }

  // Sync skills from container/skills/ into each group's .claude/skills/
  const skillsSrc = path.join(process.cwd(), 'container', 'skills');
  const skillsDst = path.join(groupSessionsDir, 'skills');
  if (fs.existsSync(skillsSrc)) {
    for (const skillDir of fs.readdirSync(skillsSrc)) {
      const srcDir = path.join(skillsSrc, skillDir);
      if (!fs.statSync(srcDir).isDirectory()) continue;
      const dstDir = path.join(skillsDst, skillDir);
      fs.cpSync(srcDir, dstDir, { recursive: true });
    }
  }
  mounts.push({
    hostPath: groupSessionsDir,
    containerPath: '/home/node/.claude',
    readonly: false,
  });

  // Per-group IPC namespace: each group gets its own IPC directory
  // This prevents cross-group privilege escalation via IPC
  const groupIpcDir = resolveGroupIpcPath(group.folder);
  fs.mkdirSync(path.join(groupIpcDir, 'messages'), { recursive: true });
  fs.mkdirSync(path.join(groupIpcDir, 'tasks'), { recursive: true });
  fs.mkdirSync(path.join(groupIpcDir, 'input'), { recursive: true });
  mounts.push({
    hostPath: groupIpcDir,
    containerPath: '/workspace/ipc',
    readonly: false,
  });

  // Copy agent-runner source into a per-group writable location so agents
  // can customize it (add tools, change behavior) without affecting other
  // groups. Recompiled on container startup via entrypoint.sh.
  const agentRunnerSrc = path.join(
    projectRoot,
    'container',
    'agent-runner',
    'src',
  );
  const groupAgentRunnerDir = path.join(
    DATA_DIR,
    'sessions',
    group.folder,
    'agent-runner-src',
  );
  if (!fs.existsSync(groupAgentRunnerDir) && fs.existsSync(agentRunnerSrc)) {
    fs.cpSync(agentRunnerSrc, groupAgentRunnerDir, { recursive: true });
  }
  mounts.push({
    hostPath: groupAgentRunnerDir,
    containerPath: '/app/src',
    readonly: false,
  });

  // Additional mounts validated against external allowlist (tamper-proof from containers)
  if (group.containerConfig?.additionalMounts) {
    const validatedMounts = validateAdditionalMounts(
      group.containerConfig.additionalMounts,
      group.name,
      isMain,
    );
    mounts.push(...validatedMounts);
  }

  return mounts;
}

function buildContainerArgs(
  mounts: VolumeMount[],
  containerName: string,
  model: string,
  traceId: string,
  spanId: string,
  input: ContainerInput,
): string[] {
  const args: string[] = ['run', '-i', '--rm', '--name', containerName];

  // Pass host timezone so container's local time matches the user's
  args.push('-e', `TZ=${TIMEZONE}`);

  // Route API traffic through the credential proxy (containers never see real secrets)
  args.push(
    '-e',
    `ANTHROPIC_BASE_URL=http://${CONTAINER_HOST_GATEWAY}:${CREDENTIAL_PROXY_PORT}`,
  );

  // Mirror the host's auth method with a placeholder value.
  // API key mode: SDK sends x-api-key, proxy replaces with real key.
  // OAuth mode:   SDK exchanges placeholder token for temp API key,
  //               proxy injects real OAuth token on that exchange request.
  const authMode = detectAuthMode();
  if (authMode === 'api-key') {
    args.push('-e', 'ANTHROPIC_API_KEY=placeholder');
  } else {
    args.push('-e', 'CLAUDE_CODE_OAUTH_TOKEN=placeholder');
  }

  // Runtime-specific args for host gateway resolution
  args.push(...hostGatewayArgs());

  // Model routing — tell the agent-runner which Claude model to use.
  // Agent-runner reads this and passes it to query() options.
  args.push('-e', `CLAUDE_MODEL=${model}`);

  // Trace IDs for structured logging correlation
  args.push('-e', `TRACE_ID=${traceId}`);
  args.push('-e', `PARENT_SPAN_ID=${spanId}`);

  // Session and group metadata for structured logging
  args.push('-e', `SESSION_ID=${input.sessionId || 'unknown'}`);
  args.push('-e', `CHAT_JID=${input.chatJid}`);
  args.push('-e', `IS_MAIN=${input.isMain}`);
  args.push('-e', `ASSISTANT_NAME=${input.assistantName || 'DOOM'}`);

  // Langfuse observability — inject keys only (NO --network flag here).
  // Network attachment happens post-spawn via docker network connect so the
  // container stays on the default bridge (keeping host.docker.internal →
  // credential proxy working) AND joins langfuse_default as a second network.
  if (LF_HOST && LF_PUBLIC_KEY && LF_SECRET_KEY) {
    args.push('-e', `LANGFUSE_HOST=${LF_HOST}`);
    args.push('-e', `LANGFUSE_PUBLIC_KEY=${LF_PUBLIC_KEY}`);
    args.push('-e', `LANGFUSE_SECRET_KEY=${LF_SECRET_KEY}`);
  }

  // Discord bot token — inject if configured (enables scheduled tasks to post to dedicated channels via Discord REST API)
  if (DISCORD_BOT_TOKEN) {
    args.push('-e', `DISCORD_BOT_TOKEN=${DISCORD_BOT_TOKEN}`);
  }

  // Run as host user so bind-mounted files are accessible.
  // Skip when running as root (uid 0), as the container's node user (uid 1000),
  // or when getuid is unavailable (native Windows without WSL).
  const hostUid = process.getuid?.();
  const hostGid = process.getgid?.();
  if (hostUid != null && hostUid !== 0 && hostUid !== 1000) {
    args.push('--user', `${hostUid}:${hostGid}`);
    args.push('-e', 'HOME=/home/node');
  }

  for (const mount of mounts) {
    if (mount.readonly) {
      args.push(...readonlyMountArgs(mount.hostPath, mount.containerPath));
    } else {
      args.push('-v', `${mount.hostPath}:${mount.containerPath}`);
    }
  }

  args.push(CONTAINER_IMAGE);

  return args;
}

export async function runContainerAgent(
  group: RegisteredGroup,
  input: ContainerInput,
  onProcess: (proc: ChildProcess, containerName: string) => void,
  onOutput?: (output: ContainerOutput) => Promise<void>,
): Promise<ContainerOutput> {
  const startTime = Date.now();

  const groupDir = resolveGroupFolderPath(group.folder);
  fs.mkdirSync(groupDir, { recursive: true });

  // Session freshness check — clear sessionId if idle >1h to avoid paying for stale context
  const groupIpcDir = resolveGroupIpcPath(group.folder);
  const lastActivityFile = path.join(groupIpcDir, 'last_activity.json');
  let effectiveInput = input;
  if (input.sessionId) {
    try {
      const la = JSON.parse(fs.readFileSync(lastActivityFile, 'utf-8'));
      const idleMs = Date.now() - new Date(la.timestamp).getTime();
      if (idleMs > SESSION_IDLE_THRESHOLD_MS) {
        logger.info(
          {
            group: group.name,
            idleMinutes: Math.round(idleMs / 60000),
            staleSessionId: input.sessionId,
          },
          'Session idle >1h — starting fresh to avoid stale context cost',
        );
        effectiveInput = { ...input, sessionId: undefined };
      }
    } catch {
      /* no file yet or unreadable — keep existing session */
    }
  }
  // Stamp activity time now (message is being processed)
  try {
    fs.mkdirSync(groupIpcDir, { recursive: true });
    fs.writeFileSync(
      lastActivityFile,
      JSON.stringify({ timestamp: new Date().toISOString() }),
    );
  } catch {
    /* non-fatal */
  }

  const mounts = buildVolumeMounts(group, input.isMain);
  const safeName = group.folder.replace(/[^a-zA-Z0-9-]/g, '-');
  const containerName = `nanoclaw-${safeName}-${Date.now()}`;
  const model = selectModel(effectiveInput);
  const { traceId, spanId } = generateTraceIds(effectiveInput.sessionId);

  logger.debug(
    {
      group: group.name,
      model,
      routingEnabled: ROUTING_ENABLED,
      traceId,
      spanId,
      sessionId: effectiveInput.sessionId,
      chatJid: effectiveInput.chatJid,
      isMain: effectiveInput.isMain,
    },
    'Model selected for container',
  );
  const containerArgs = buildContainerArgs(
    mounts,
    containerName,
    model,
    traceId,
    spanId,
    effectiveInput,
  );

  logger.debug(
    {
      group: group.name,
      containerName,
      mounts: mounts.map(
        (m) =>
          `${m.hostPath} -> ${m.containerPath}${m.readonly ? ' (ro)' : ''}`,
      ),
      containerArgs: containerArgs.join(' '),
    },
    'Container mount configuration',
  );

  logger.info(
    {
      group: group.name,
      containerName,
      mountCount: mounts.length,
      isMain: effectiveInput.isMain,
    },
    'Spawning container agent',
  );

  const logsDir = path.join(groupDir, 'logs');
  fs.mkdirSync(logsDir, { recursive: true });

  return new Promise((resolve) => {
    const container = spawn(CONTAINER_RUNTIME_BIN, containerArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    // Post-spawn: join Langfuse network as a SECOND network so the container
    // is on both bridge (credential proxy) and langfuse_default (Langfuse).
    // Fire-and-forget — failure is non-fatal, agent continues without tracing.
    // Delay 800ms: Docker needs time to register the container before network connect works.
    const lfNetwork = process.env.LANGFUSE_NETWORK || _lfEnv.LANGFUSE_NETWORK;
    if (LF_HOST && lfNetwork) {
      setTimeout(() => {
        exec(
          `${CONTAINER_RUNTIME_BIN} network connect ${lfNetwork} ${containerName}`,
          (err) => {
            if (err)
              logger.warn(
                { error: err.message },
                'Langfuse network connect failed (non-fatal)',
              );
          },
        );
      }, 800);
    }

    onProcess(container, containerName);

    let stdout = '';
    let stderr = '';
    let stdoutTruncated = false;
    let stderrTruncated = false;

    container.stdin.write(JSON.stringify(input));
    container.stdin.end();

    // Streaming output: parse OUTPUT_START/END marker pairs as they arrive
    let parseBuffer = '';
    let newSessionId: string | undefined;
    let outputChain = Promise.resolve();

    container.stdout.on('data', (data) => {
      const chunk = data.toString();

      // Always accumulate for logging
      if (!stdoutTruncated) {
        const remaining = CONTAINER_MAX_OUTPUT_SIZE - stdout.length;
        if (chunk.length > remaining) {
          stdout += chunk.slice(0, remaining);
          stdoutTruncated = true;
          logger.warn(
            { group: group.name, size: stdout.length },
            'Container stdout truncated due to size limit',
          );
        } else {
          stdout += chunk;
        }
      }

      // Stream-parse for output markers
      if (onOutput) {
        parseBuffer += chunk;
        let startIdx: number;
        while ((startIdx = parseBuffer.indexOf(OUTPUT_START_MARKER)) !== -1) {
          const endIdx = parseBuffer.indexOf(OUTPUT_END_MARKER, startIdx);
          if (endIdx === -1) break; // Incomplete pair, wait for more data

          const jsonStr = parseBuffer
            .slice(startIdx + OUTPUT_START_MARKER.length, endIdx)
            .trim();
          parseBuffer = parseBuffer.slice(endIdx + OUTPUT_END_MARKER.length);

          try {
            const parsed: ContainerOutput = JSON.parse(jsonStr);
            if (parsed.newSessionId) {
              newSessionId = parsed.newSessionId;
            }
            hadStreamingOutput = true;
            // Activity detected — reset the hard timeout
            resetTimeout();
            // Call onOutput for all markers (including null results)
            // so idle timers start even for "silent" query completions.
            outputChain = outputChain.then(() => onOutput(parsed));
          } catch (err) {
            logger.warn(
              { group: group.name, error: err },
              'Failed to parse streamed output chunk',
            );
          }
        }
      }
    });

    container.stderr.on('data', (data) => {
      const chunk = data.toString();
      const lines = chunk.trim().split('\n');
      for (const line of lines) {
        if (line) logger.debug({ container: group.folder }, line);
      }
      // Don't reset timeout on stderr — SDK writes debug logs continuously.
      // Timeout only resets on actual output (OUTPUT_MARKER in stdout).
      if (stderrTruncated) return;
      const remaining = CONTAINER_MAX_OUTPUT_SIZE - stderr.length;
      if (chunk.length > remaining) {
        stderr += chunk.slice(0, remaining);
        stderrTruncated = true;
        logger.warn(
          { group: group.name, size: stderr.length },
          'Container stderr truncated due to size limit',
        );
      } else {
        stderr += chunk;
      }
    });

    let timedOut = false;
    let hadStreamingOutput = false;
    const configTimeout = group.containerConfig?.timeout || CONTAINER_TIMEOUT;
    // Grace period: hard timeout must be at least IDLE_TIMEOUT + 30s so the
    // graceful _close sentinel has time to trigger before the hard kill fires.
    const timeoutMs = Math.max(configTimeout, IDLE_TIMEOUT + 30_000);

    const killOnTimeout = () => {
      timedOut = true;
      logger.error(
        { group: group.name, containerName },
        'Container timeout, stopping gracefully',
      );
      exec(stopContainer(containerName), { timeout: 15000 }, (err) => {
        if (err) {
          logger.warn(
            { group: group.name, containerName, err },
            'Graceful stop failed, force killing',
          );
          container.kill('SIGKILL');
        }
      });
    };

    let timeout = setTimeout(killOnTimeout, timeoutMs);

    // Reset the timeout whenever there's activity (streaming output)
    const resetTimeout = () => {
      clearTimeout(timeout);
      timeout = setTimeout(killOnTimeout, timeoutMs);
    };

    container.on('close', (code) => {
      clearTimeout(timeout);
      const duration = Date.now() - startTime;

      if (timedOut) {
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const timeoutLog = path.join(logsDir, `container-${ts}.log`);
        fs.writeFileSync(
          timeoutLog,
          [
            `=== Container Run Log (TIMEOUT) ===`,
            `Timestamp: ${new Date().toISOString()}`,
            `Group: ${group.name}`,
            `Container: ${containerName}`,
            `Duration: ${duration}ms`,
            `Exit Code: ${code}`,
            `Had Streaming Output: ${hadStreamingOutput}`,
          ].join('\n'),
        );

        // Timeout after output = idle cleanup, not failure.
        // The agent already sent its response; this is just the
        // container being reaped after the idle period expired.
        if (hadStreamingOutput) {
          logger.info(
            { group: group.name, containerName, duration, code },
            'Container timed out after output (idle cleanup)',
          );
          outputChain.then(() => {
            resolve({
              status: 'success',
              result: null,
              newSessionId,
            });
          });
          return;
        }

        logger.error(
          { group: group.name, containerName, duration, code },
          'Container timed out with no output',
        );

        resolve({
          status: 'error',
          result: null,
          error: `Container timed out after ${configTimeout}ms`,
        });
        return;
      }

      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const logFile = path.join(logsDir, `container-${timestamp}.log`);
      const isVerbose =
        process.env.LOG_LEVEL === 'debug' || process.env.LOG_LEVEL === 'trace';

      const logLines = [
        `=== Container Run Log ===`,
        `Timestamp: ${new Date().toISOString()}`,
        `Group: ${group.name}`,
        `IsMain: ${input.isMain}`,
        `Duration: ${duration}ms`,
        `Exit Code: ${code}`,
        `Stdout Truncated: ${stdoutTruncated}`,
        `Stderr Truncated: ${stderrTruncated}`,
        ``,
      ];

      const isError = code !== 0;

      if (isVerbose || isError) {
        logLines.push(
          `=== Input ===`,
          JSON.stringify(input, null, 2),
          ``,
          `=== Container Args ===`,
          containerArgs.join(' '),
          ``,
          `=== Mounts ===`,
          mounts
            .map(
              (m) =>
                `${m.hostPath} -> ${m.containerPath}${m.readonly ? ' (ro)' : ''}`,
            )
            .join('\n'),
          ``,
          `=== Stderr${stderrTruncated ? ' (TRUNCATED)' : ''} ===`,
          stderr,
          ``,
          `=== Stdout${stdoutTruncated ? ' (TRUNCATED)' : ''} ===`,
          stdout,
        );
      } else {
        logLines.push(
          `=== Input Summary ===`,
          `Prompt length: ${input.prompt.length} chars`,
          `Session ID: ${effectiveInput.sessionId || 'new (idle reset)'}`,
          ``,
          `=== Mounts ===`,
          mounts
            .map((m) => `${m.containerPath}${m.readonly ? ' (ro)' : ''}`)
            .join('\n'),
          ``,
        );
      }

      fs.writeFileSync(logFile, logLines.join('\n'));
      logger.debug({ logFile, verbose: isVerbose }, 'Container log written');

      if (code !== 0) {
        logger.error(
          {
            group: group.name,
            code,
            duration,
            stderr,
            stdout,
            logFile,
          },
          'Container exited with error',
        );

        resolve({
          status: 'error',
          result: null,
          error: `Container exited with code ${code}: ${stderr.slice(-200)}`,
        });
        return;
      }

      // Streaming mode: wait for output chain to settle, return completion marker
      if (onOutput) {
        outputChain.then(() => {
          logger.info(
            { group: group.name, duration, newSessionId },
            'Container completed (streaming mode)',
          );
          resolve({
            status: 'success',
            result: null,
            newSessionId,
          });
        });
        return;
      }

      // Legacy mode: parse the last output marker pair from accumulated stdout
      try {
        // Extract JSON between sentinel markers for robust parsing
        const startIdx = stdout.indexOf(OUTPUT_START_MARKER);
        const endIdx = stdout.indexOf(OUTPUT_END_MARKER);

        let jsonLine: string;
        if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
          jsonLine = stdout
            .slice(startIdx + OUTPUT_START_MARKER.length, endIdx)
            .trim();
        } else {
          // Fallback: last non-empty line (backwards compatibility)
          const lines = stdout.trim().split('\n');
          jsonLine = lines[lines.length - 1];
        }

        const output: ContainerOutput = JSON.parse(jsonLine);

        logger.info(
          {
            group: group.name,
            duration,
            status: output.status,
            hasResult: !!output.result,
          },
          'Container completed',
        );

        resolve(output);
      } catch (err) {
        logger.error(
          {
            group: group.name,
            stdout,
            stderr,
            error: err,
          },
          'Failed to parse container output',
        );

        resolve({
          status: 'error',
          result: null,
          error: `Failed to parse container output: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    });

    container.on('error', (err) => {
      clearTimeout(timeout);
      logger.error(
        { group: group.name, containerName, error: err },
        'Container spawn error',
      );
      resolve({
        status: 'error',
        result: null,
        error: `Container spawn error: ${err.message}`,
      });
    });
  });
}

export function writeTasksSnapshot(
  groupFolder: string,
  isMain: boolean,
  tasks: Array<{
    id: string;
    groupFolder: string;
    prompt: string;
    schedule_type: string;
    schedule_value: string;
    status: string;
    next_run: string | null;
  }>,
): void {
  // Write filtered tasks to the group's IPC directory
  const groupIpcDir = resolveGroupIpcPath(groupFolder);
  fs.mkdirSync(groupIpcDir, { recursive: true });

  // Main sees all tasks, others only see their own
  const filteredTasks = isMain
    ? tasks
    : tasks.filter((t) => t.groupFolder === groupFolder);

  const tasksFile = path.join(groupIpcDir, 'current_tasks.json');
  fs.writeFileSync(tasksFile, JSON.stringify(filteredTasks, null, 2));
}

export interface AvailableGroup {
  jid: string;
  name: string;
  lastActivity: string;
  isRegistered: boolean;
}

/**
 * Write available groups snapshot for the container to read.
 * Only main group can see all available groups (for activation).
 * Non-main groups only see their own registration status.
 */
export function writeGroupsSnapshot(
  groupFolder: string,
  isMain: boolean,
  groups: AvailableGroup[],
  registeredJids: Set<string>,
): void {
  const groupIpcDir = resolveGroupIpcPath(groupFolder);
  fs.mkdirSync(groupIpcDir, { recursive: true });

  // Main sees all groups; others see nothing (they can't activate groups)
  const visibleGroups = isMain ? groups : [];

  const groupsFile = path.join(groupIpcDir, 'available_groups.json');
  fs.writeFileSync(
    groupsFile,
    JSON.stringify(
      {
        groups: visibleGroups,
        lastSync: new Date().toISOString(),
      },
      null,
      2,
    ),
  );
}
