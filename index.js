import { execSync } from 'node:child_process';

export const name = 'coding-agent-audit';
export const inject = ['tools'];

function getProcessInfo(pid) {
  try {
    if (process.platform === 'win32') {
      const out = execSync(
        `powershell -Command "Get-CimInstance Win32_Process -Filter 'ProcessId=${pid}' | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json"`,
        { encoding: 'utf8', timeout: 5000 }
      );
      const j = JSON.parse(out);
      return {
        pid: j.ProcessId,
        name: j.Name ?? '',
        ppid: j.ParentProcessId ?? null,
        cmdline: j.CommandLine ?? null,
        user: null,
      };
    }
    const out = execSync(`ps -o pid=,ppid=,user=,comm=,args= -p ${pid}`, { encoding: 'utf8', timeout: 5000 }).trim();
    const parts = out.split(/\s+/);
    return {
      pid: Number(parts[0]),
      ppid: Number(parts[1]) || null,
      user: parts[2] ?? null,
      name: parts[3] ?? '',
      cmdline: parts.slice(4).join(' ') || null,
    };
  } catch {
    return null;
  }
}

function detectAgent(nodes) {
  const names = nodes.map(n => n.name.toLowerCase()).join(' ');
  if (names.includes('claude')) return 'claude-code';
  if (names.includes('cursor')) return 'cursor';
  if (names.includes('copilot')) return 'copilot';
  return null;
}

function detectSuspiciousFlags(nodes) {
  const flags = [];
  for (const n of nodes) {
    if (!n.cmdline) continue;
    if (n.cmdline.includes('--dangerously-skip-permissions')) flags.push('--dangerously-skip-permissions');
    if (/\bngrok\b|cloudflared|ssh\s+-R/.test(n.cmdline)) flags.push('tunnel-tool-in-commandline');
  }
  return [...new Set(flags)];
}

export function apply(ctx) {
  ctx.tools.register({
    name: 'audit_ping',
    description: 'Ping the coding-agent audit plugin. Used to verify the plugin is loaded.',
    parameters: { type: 'object', properties: {} },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute() {
      return 'coding-agent-audit plugin is alive';
    },
  });

  ctx.tools.register({
    name: 'collect_process_tree',
    description: 'Collect the process ancestry for a given PID as structured evidence. Use this when an alert involves an agent spawning a shell or child process. Returns the process tree and lightweight flags; it does NOT make a verdict.',
    parameters: {
      type: 'object',
      properties: {
        pid: { type: 'number', description: 'The PID to start from (usually the alerting process)' },
        max_depth: { type: 'number', description: 'Maximum ancestors to walk. Default 10.' },
      },
      required: ['pid'],
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          root_pid: { type: 'number' },
          nodes: { type: 'array' },
          parent_agent_detected: { oneOf: [{ type: 'string' }, { type: 'null' }] },
          suspicious_flags: { type: 'array' },
        },
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const maxDepth = args.max_depth ?? 10;
      const nodes = [];
      let current = args.pid;
      for (let i = 0; i < maxDepth && current; i++) {
        const info = getProcessInfo(current);
        if (!info) break;
        nodes.push(info);
        current = info.ppid;
      }
      return {
        root_pid: args.pid,
        nodes,
        parent_agent_detected: detectAgent(nodes),
        suspicious_flags: detectSuspiciousFlags(nodes),
      };
    },
  });

  ctx.tools.register({
    name: 'collect_credential_access',
    description: 'Collect structured evidence about file access that may involve credential stores. Use this when an alert involves reading .aws/.ssh/cookies/etc. Returns path hits and optional session context; does NOT make a verdict.',
    parameters: {
      type: 'object',
      properties: {
        paths: {
          type: 'array',
          items: { type: 'string' },
          description: 'Absolute or relative paths that were accessed',
        },
        session_log_path: {
          type: 'string',
          description: 'Optional absolute path to a Claude Code JSONL session log for scope correlation',
        },
      },
      required: ['paths'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          path_hits: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                path: { type: 'string' },
                sensitive: { type: 'boolean' },
              },
              required: ['path', 'sensitive'],
              additionalProperties: false,
            },
          },
          session_cwd: { type: 'string' },
          recent_commands: { type: 'array', items: { type: 'string' } },
          scope_related: { type: 'boolean' },
        },
        required: ['path_hits', 'session_cwd', 'recent_commands', 'scope_related'],
        additionalProperties: false,
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const SENSITIVE_PATHS = [
        '.aws/credentials', '.aws/config', '.ssh/',
        '.config/gh/hosts.yml', '.git-credentials',
        'cookies.sqlite', 'login data',
      ];
      const isSensitive = (p) => {
        const lower = String(p ?? '').toLowerCase();
        return SENSITIVE_PATHS.some(s => lower.includes(s));
      };

      const pathHits = args.paths.map(p => ({ path: String(p ?? ''), sensitive: isSensitive(p) }));

      let sessionCwd = 'none';
      let recentCommands = [];
      let scopeRelated = true;

      // Normalize Windows/Unix separators before any comparison; on Windows
      // paths are case-insensitive, so fold case there as well.
      const norm = (s) => {
        const v = String(s).replace(/\\/g, '/');
        return process.platform === 'win32' ? v.toLowerCase() : v;
      };

      // Tool calls appear as top-level `type: tool_use` events in Claude Code,
      // but as content blocks nested under message.content[] in qclaw / Cursor
      // / Copilot logs. Collect both shapes.
      const collectToolUses = (obj) => {
        const found = [];
        if (obj.type === 'tool_use') found.push(obj);
        const contents = [
          ...(Array.isArray(obj.content) ? obj.content : []),
          ...(Array.isArray(obj.message?.content) ? obj.message.content : []),
        ];
        for (const block of contents) {
          if (block && (block.type === 'tool_use' || block.type === 'tool_call' || block.type === 'toolCall')) {
            found.push(block);
          }
        }
        return found;
      };

      // Command payloads differ across agents: input.command, input.cmd, a
      // bare input string, or a sibling command/cmd/toolInput field.
      const commandOf = (rec) => {
        const input = rec.input;
        if (typeof input === 'string') return input;
        const cmd = input?.command ?? input?.cmd ?? rec.command ?? rec.cmd ?? rec.toolInput;
        return typeof cmd === 'string' ? cmd : null;
      };

      if (args.session_log_path) {
        try {
          const { readFile } = await import('node:fs/promises');
          const { zstdDecompressSync } = await import('node:zlib');
          const buf = await readFile(args.session_log_path);
          let content;
          if (buf.length >= 4 && buf[0] === 0x28 && buf[1] === 0xB5 && buf[2] === 0x2F && buf[3] === 0xFD) {
            content = zstdDecompressSync(buf).toString('utf8');
          } else {
            content = buf.toString('utf8');
          }
          const lines = content.split('\n').filter(Boolean);
          for (const line of lines) {
            try {
              const obj = JSON.parse(line);
              if (obj.cwd && sessionCwd === 'none') sessionCwd = obj.cwd;
              for (const rec of collectToolUses(obj)) {
                const cmd = commandOf(rec);
                if (cmd) recentCommands.push(cmd);
              }
              if (obj.type === 'tool/call' && obj.data) {
                let cmd = obj.data.name;
                try {
                  const a = JSON.parse(obj.data.arguments);
                  if (a && (a.command || a.cmd)) cmd = a.command || a.cmd;
                } catch { /* arguments 解析失败时退回工具名 */ }
                recentCommands.push(cmd);
              }
            } catch { /* skip malformed line */ }
          }
          recentCommands = recentCommands.slice(-10);
          if (sessionCwd !== 'none') {
            const cwd = norm(sessionCwd).replace(/\/+$/, '');
            scopeRelated = args.paths.some(p => {
              const np = norm(p);
              return np === cwd || np.startsWith(cwd + '/');
            });
          }
        } catch { /* 日志读取失败时保持默认值，不阻断主流程 */ }
      }

      return { path_hits: pathHits, session_cwd: sessionCwd, recent_commands: recentCommands, scope_related: scopeRelated };
    },
  });

  ctx.tools.register({
    name: 'collect_egress_tunnel',
    description: 'Collect structured evidence about network egress or tunneling activity. Use this when an alert involves ngrok/cloudflared/frp, reverse SSH, reverse shells, public binds, or known tunnel endpoints. Returns detected indicators; does NOT make a verdict.',
    parameters: {
      type: 'object',
      properties: {
        commands: {
          type: 'array',
          items: { type: 'string' },
          description: 'Command lines / process args to scan for tunnel tool signatures',
        },
        listeners: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              address: { type: 'string' },
              port: { type: 'number' },
              process: { type: 'string' },
            },
            required: ['address', 'port'],
            additionalProperties: false,
          },
          description: 'Local listening sockets observed (address and port the service binds to)',
        },
        outbound: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              remote: { type: 'string' },
              port: { type: 'number' },
            },
            required: ['remote'],
            additionalProperties: false,
          },
          description: 'Outbound connections observed to remote hosts',
        },
      },
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          tunnel_indicators: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                category: { type: 'string' },
                detail: { type: 'string' },
                signature: { type: 'string' },
              },
              required: ['category', 'detail', 'signature'],
              additionalProperties: false,
            },
          },
          suspected_tunnel: { type: 'boolean' },
          evidence_count: { type: 'number' },
        },
        required: ['tunnel_indicators', 'suspected_tunnel', 'evidence_count'],
        additionalProperties: false,
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const TUNNEL_SIGNATURES = [
        { category: 'tunnel-tool', re: /\bngrok\b/i, label: 'ngrok' },
        { category: 'tunnel-tool', re: /\bcloudflared\b|\bcloudflare\s+tunnel\b/i, label: 'cloudflared' },
        { category: 'tunnel-tool', re: /\bfrpc?\b/i, label: 'frp' },
        { category: 'tunnel-tool', re: /\bservo\b|\bserveo\.net\b/i, label: 'serveo' },
        { category: 'tunnel-tool', re: /\bchisel\b/i, label: 'chisel' },
        { category: 'tunnel-tool', re: /\bgost\b/i, label: 'gost' },
        { category: 'tunnel-tool', re: /\blocaltunnel\b|\blt\b\s+--port\b/i, label: 'localtunnel' },
        { category: 'reverse-ssh', re: /\bssh\b[^\n]*-R\b|\bssh\b[^\n]*\b-R\b\s+\d+:/i, label: 'ssh -R reverse tunnel' },
        { category: 'forward-ssh', re: /\bssh\b[^\n]*-L\b/i, label: 'ssh -L forward tunnel' },
        { category: 'reverse-shell', re: /\bbash\b[^\n]*\/dev\/tcp\b/i, label: 'bash /dev/tcp reverse shell' },
        { category: 'reverse-shell', re: /\b(?:nc|ncat|netcat)\b[^\n]*-e\b/i, label: 'netcat reverse shell' },
        { category: 'reverse-shell', re: /\bNew-Object\b[^\n]*Net\.Socket/i, label: 'powershell socket reverse shell' },
      ];
      const TUNNEL_HOST_RE = /\.ngrok\.io$|\.ngrok-free\.app$|\.trycloudflare\.com$|\.serveo\.net$|\.localtunnel\.me$|tunnel\.|\.frp\.|\.pagekite\.me$/i;
      const isPrivateBind = (addr) => {
        const a = addr.toLowerCase();
        return a === 'localhost' || a === '127.0.0.1' || a === '::1' || a.startsWith('10.') || a.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(a);
      };
      // A bash /dev/tcp connection to a loopback address is a local health/port
      // probe, not a reverse shell. Only suppress this specific signature; all
      // other signatures (nc -e, ssh -R, tunnel tools, public bind) stay intact.
      const LOOPBACK_DEV_TCP = /\/dev\/tcp\/(?:127\.0\.0\.1|localhost|::1|0\.0\.0\.0)(?:\/|$)/i;

      const indicators = [];

      for (const cmd of args.commands ?? []) {
        for (const sig of TUNNEL_SIGNATURES) {
          if (sig.re.test(cmd)) {
            if (sig.label === 'bash /dev/tcp reverse shell' && LOOPBACK_DEV_TCP.test(cmd)) break;
            indicators.push({ category: sig.category, detail: cmd, signature: sig.label });
            break;
          }
        }
      }

      for (const l of args.listeners ?? []) {
        if (!isPrivateBind(l.address)) {
          indicators.push({
            category: 'public-bind',
            detail: `${l.address}:${l.port}${l.process ? ` (${l.process})` : ''}`,
            signature: 'binds to non-loopback interface',
          });
        }
      }

      for (const o of args.outbound ?? []) {
        if (TUNNEL_HOST_RE.test(o.remote)) {
          indicators.push({
            category: 'tunnel-endpoint',
            detail: o.port ? `${o.remote}:${o.port}` : o.remote,
            signature: 'connection to known tunnel endpoint',
          });
        }
      }

      const evidenceCount = (args.commands?.length ?? 0) + (args.listeners?.length ?? 0) + (args.outbound?.length ?? 0);

      return {
        tunnel_indicators: indicators,
        suspected_tunnel: indicators.length > 0,
        evidence_count: evidenceCount,
      };
    },
  });

  ctx.tools.register({
    name: 'audit_coding_agent_alert',
    description: 'Aggregate structured evidence from the three collection tools and return parsed signals for model judgment. Does NOT make a final verdict: the model must decide benign_agent / suspicious / insufficient_evidence from these signals.',
    parameters: {
      type: 'object',
      properties: {
        alert_type: {
          type: 'string',
          description: 'Alert category, e.g. credential, tunnel, process, or combined',
        },
        evidence: {
          type: 'array',
          items: { type: 'string' },
          description: 'Each element MUST be a JSON string (the serialized output of a collection tool), not a JSON object.',
        },
      },
      required: ['alert_type', 'evidence'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          verdict: { type: 'string' },
          alert_type: { type: 'string' },
          parsed_signals: {
            type: 'object',
            properties: {
              credential_sensitive_count: { type: 'number' },
              suspected_tunnel: { type: 'boolean' },
              parent_agent_detected: { oneOf: [{ type: 'string' }, { type: 'null' }] },
              suspicious_flags: { type: 'array', items: { type: 'string' } },
              process_node_count: { type: 'number' },
              tunnel_indicator_count: { type: 'number' },
              scope_related: { type: 'boolean' },
            },
            required: ['credential_sensitive_count', 'suspected_tunnel', 'parent_agent_detected', 'suspicious_flags', 'process_node_count', 'tunnel_indicator_count', 'scope_related'],
            additionalProperties: false,
          },
          scope_mismatch_hint: { type: 'boolean' },
          evidence_refs: { type: 'array', items: { type: 'string' } },
          parse_errors: { type: 'array', items: { type: 'string' } },
        },
        required: ['verdict', 'alert_type', 'parsed_signals', 'scope_mismatch_hint', 'evidence_refs', 'parse_errors'],
        additionalProperties: false,
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const parseErrors = [];
      const parsed = (args.evidence ?? []).map((raw, i) => {
        try {
          return JSON.parse(raw);
        } catch {
          parseErrors.push(`evidence[${i}]: not valid JSON string`);
          return null;
        }
      });

      let credentialSensitiveCount = 0;
      let suspectedTunnel = false;
      let parentAgentDetected = null;
      const suspiciousFlags = [];
      let processNodeCount = 0;
      let tunnelIndicatorCount = 0;
      let scopeRelated = true;

      for (const ev of parsed) {
        if (!ev || typeof ev !== 'object') continue;
        if (Array.isArray(ev.path_hits)) {
          credentialSensitiveCount += ev.path_hits.filter(h => h && h.sensitive === true).length;
          if (typeof ev.scope_related === 'boolean') scopeRelated = ev.scope_related;
        }
        if (typeof ev.suspected_tunnel === 'boolean') suspectedTunnel = suspectedTunnel || ev.suspected_tunnel;
        if (Array.isArray(ev.tunnel_indicators)) tunnelIndicatorCount += ev.tunnel_indicators.length;
        if (Array.isArray(ev.nodes)) processNodeCount += ev.nodes.length;
        if (ev.parent_agent_detected === null || typeof ev.parent_agent_detected === 'string') {
          parentAgentDetected = ev.parent_agent_detected;
        }
        if (Array.isArray(ev.suspicious_flags)) {
          for (const f of ev.suspicious_flags) if (!suspiciousFlags.includes(f)) suspiciousFlags.push(f);
        }
      }

      return {
        verdict: 'pending_model_judgment',
        alert_type: args.alert_type,
        parsed_signals: {
          credential_sensitive_count: credentialSensitiveCount,
          suspected_tunnel: suspectedTunnel,
          parent_agent_detected: parentAgentDetected,
          suspicious_flags: suspiciousFlags,
          process_node_count: processNodeCount,
          tunnel_indicator_count: tunnelIndicatorCount,
          scope_related: scopeRelated,
        },
        scope_mismatch_hint: scopeRelated === false,
        evidence_refs: (args.evidence ?? []).map((_raw, i) => `evidence[${i}]`),
        parse_errors: parseErrors,
      };
    },
  });

  ctx.tools.register({
    name: 'collect_session_facts',
    description: 'Read-only extraction of approval/permission/failure/depth facts from a session log. Does NOT make a verdict, does NOT feed audit_coding_agent_alert, and does NOT scan tool/call argument paths.',
    parameters: {
      type: 'object',
      properties: {
        session_log_path: {
          type: 'string',
          description: 'Absolute path to a DSH .zstd session log (magic 28 B5 2F FD); auto-decompressed',
        },
      },
      required: ['session_log_path'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          session_cwd: { type: 'string' },
          approval_asked_count: { type: 'number' },
          privilege_escalations: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                reason: { type: 'string' },
                outcome: { type: 'string' },
              },
              required: ['reason', 'outcome'],
              additionalProperties: false,
            },
          },
          tool_error_count: { type: 'number' },
          turn_count: { type: 'number' },
          step_count: { type: 'number' },
          parse_errors: { type: 'array', items: { type: 'string' } },
        },
        required: ['session_cwd', 'approval_asked_count', 'privilege_escalations', 'tool_error_count', 'turn_count', 'step_count', 'parse_errors'],
        additionalProperties: false,
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      let sessionCwd = 'none';
      let approvalAskedCount = 0;
      let toolErrorCount = 0;
      let turnCount = 0;
      let stepCount = 0;
      const parseErrors = [];
      const askedById = new Map();
      const decidedById = new Map();
      const privilegeEscalations = [];

      if (args.session_log_path) {
        try {
          const { readFile } = await import('node:fs/promises');
          const { zstdDecompressSync } = await import('node:zlib');
          const buf = await readFile(args.session_log_path);
          let content;
          if (buf.length >= 4 && buf[0] === 0x28 && buf[1] === 0xB5 && buf[2] === 0x2F && buf[3] === 0xFD) {
            content = zstdDecompressSync(buf).toString('utf8');
          } else {
            content = buf.toString('utf8');
          }
          const lines = content.split('\n').filter(Boolean);
          for (let i = 0; i < lines.length; i++) {
            let obj;
            try {
              obj = JSON.parse(lines[i]);
            } catch {
              parseErrors.push(`line[${i}]: not valid JSON`);
              continue;
            }
            if (obj.type === 'session' && sessionCwd === 'none' && obj.cwd) sessionCwd = obj.cwd;
            if (obj.type === 'approval/asked') {
              approvalAskedCount++;
              askedById.set(obj.data?.id, obj.data?.reason ?? '');
            }
            if (obj.type === 'approval/decided') decidedById.set(obj.data?.id, obj.data?.outcome ?? '');
            if (obj.type === 'tool/result' && obj.data?.message?.isError === true) toolErrorCount++;
            if (obj.type === 'turn/start') turnCount++;
            if (obj.type === 'step/start') stepCount++;
          }
          for (const [id, reason] of askedById) {
            if (/escalate|sandbox/i.test(reason)) {
              privilegeEscalations.push({ reason, outcome: decidedById.get(id) ?? '' });
            }
          }
        } catch { /* 读取/解压失败时静默降级，返回默认事实，不抛错 */ }
      }

      return {
        session_cwd: sessionCwd,
        approval_asked_count: approvalAskedCount,
        privilege_escalations: privilegeEscalations,
        tool_error_count: toolErrorCount,
        turn_count: turnCount,
        step_count: stepCount,
        parse_errors: parseErrors,
      };
    },
  });
}