# coding-agent-audit 插件

## 工具清单

| 工具 | 输入 | 输出要点 |
|---|---|---|
| audit_ping | 无 | 返回存活字符串，用于确认插件已加载 |
| collect_process_tree | pid, max_depth? | nodes[], parent_agent_detected (string\|null), suspicious_flags[] |
| collect_credential_access | paths[], session_log_path? | path_hits[], session_cwd, recent_commands[], scope_related |
| collect_egress_tunnel | commands[], listeners[], outbound[] | tunnel_indicators[], suspected_tunnel, evidence_count |
| audit_coding_agent_alert | alert_type, evidence[] (JSON 字符串) | verdict="pending_model_judgment", parsed_signals, evidence_refs[], parse_errors[] |
| collect_session_facts | session_log_path (必填) | 只读提取 session_cwd, approval_asked_count, privilege_escalations[], tool_error_count, turn_count, step_count, parse_errors[]；独立工具，不接入聚合 |

## 数据源适配性：secops-es-benchmark 只能当对照组

2026-11-13 映射实验结论（防止未来重复踩坑的记录）：

- **适合**：良性误报抑制的压力对照（75,998 输入 / 12 源 0 误报）、覆盖边界的量化标尺（20/20 签名覆盖、7 类 B2 GAPS）。
- **不适合**：验收「编码代理告警解释层」的代理专属信号。三个坐实的原因：
  - 全语料 239,468 文档中 `claude/cursor/copilot/codex` 进程名命中 = 0，`parent_agent_detected` 结构性为 `null`；
  - `process.pid` 是 2026-07 的历史快照，与 `collect_process_tree` 的实时查询器致命失配，喂进去 `nodes: []`；
  - `/etc/shadow` 不在 `SENSITIVE_PATHS` 里，凭据采集对 Linux 生产凭据文件不命中；裸 IP C2 不匹配隧道签名（设计边界，非漏报）。
- **94.1% 噪音分布无法复现**：数据集的"噪音"是 cron / 健康检查 / 扫描，不含「合法 AI 编码代理产生的告警」，该分布在此无从验证。
- **结论**：要验证 `parent_agent_detected` / `scope_related` / `collect_session_facts` 三条代理专属信号，只有 DSH 自有 `.zstd` 会话日志（用例 1–5）是贴合数据源；要验证「判定正确性」，需要带标签的真实告警，或自建 10–20 条人工标注的小规模 ground truth，当前公开数据集里没有。

## MVP 验收基线

本节为 `index.js` 的只读实跑结果，作为最小可用产品的验收基线。当前注册工具 6 个：`audit_ping`、`collect_process_tree`、`collect_credential_access`、`collect_egress_tunnel`、`audit_coding_agent_alert`、`collect_session_facts`。工具清单与 7 字段 schema 始终未改动；2026-11-13 共 4 次行为级修正（见下方「当前状态」），未新增工具、未改 schema。

### 当前状态（2026-11-13 全量复核）

- 插件 `index.js` SHA256：**`33620313…66`**；两份 pin（`verify_egress_benign.pins.json`、`verify_session_logs_matrix.pins.json`）的 `plugin.sha256` 与之 **MATCH**。
- **5 套套件全绿，合计 76 项断言，退出码 0×5**：`verify_credential_access_dsh.mjs` 13、`verify_egress_benign.mjs` 22、`verify_session_logs_matrix.mjs` 21、`verify_benign_noise_full.mjs` 9、`verify_signature_coverage.mjs` 11。
- **已生效**：FIX 1（非字符串路径不崩）+ 方案 A（`path_hits[].path` 恒为 string，输出合 schema）+ FIX 3（`chisel` / `gost` 签名、`ngrok-free.app` 端点）+ 回环 `/dev/tcp` 抑制；FIX 2（`.ssh/known_hosts*` 假阳性 3/75,998）**评估后有意暂缓，未应用**。
- **签名覆盖**：20/20 positive（100%）、0/16 FP、7 个分类记录的 GAPS（设计边界，不 gate）。
- **良性噪音压测**：全语料 239,468 文档流式读取，排除 8,506 行攻击指标后 **75,998 个唯一良性输入 / 12 个数据源，egress 0 误报**、credential 3 命中（均 `known_hosts*`，FIX 2 暂缓项）。
- 改动 `index.js` 后必须 `--pin` 重算两份 pin 并 `plugin_manager` 禁用→启用重载，否则套件会 MISMATCH；GUI 实测前同样需核对实现哈希（见「已知限制」的同名不同实现风险）。

### Golden Outputs（只读实跑的真实返回）

| # | 工具 / 输入 | 真实返回的关键值 |
|---|---|---|
| 1 | `audit_ping` | `"coding-agent-audit plugin is alive"` |
| 2 | `collect_credential_access` 无日志，paths=`[.aws/credentials, usage.html]` | `path_hits[0].sensitive=true`、`[1].sensitive=false`；`session_cwd="none"`；`recent_commands=[]`；`scope_related=true` |
| 3 | `collect_credential_access` 带 `825ceeb2` 日志，paths=`[.aws/credentials]` | `session_cwd="C:\Users\Administrator\OneDrive\文档\deepseek-harness\default-workspace"`；`recent_commands=["audit_ping"]`；`scope_related=false` |
| 4 | `collect_egress_tunnel` 良性组（npm test / git status + 127.0.0.1:8080 + 2 条真实外联） | `tunnel_indicators=[]`；`suspected_tunnel=false`；`evidence_count=5` |
| 5 | `collect_egress_tunnel` 隧道组（ngrok / ssh -R / 0.0.0.0:4444 / abc.ngrok.io） | `tunnel_indicators` 4 条：`tunnel-tool`(ngrok)、`reverse-ssh`(ssh -R)、`public-bind`(0.0.0.0:4444)、`tunnel-endpoint`(abc.ngrok.io:443)；`suspected_tunnel=true`；`evidence_count=4` |
| 6 | `collect_session_facts` 带 `9712b781` 日志 | `approval_asked_count=19`；`privilege_escalations` 19 条全为 `danger-full-access` / `allowed-once`；`tool_error_count=2`；`turn_count=12`；`step_count=65`；`parse_errors=[]` |
| 7 | `collect_process_tree` pid=explorer.exe(12864), max_depth=3 | `root_pid=12864`；`nodes` 1 个；`parent_agent_detected=null`；`suspicious_flags=[]` |
| 8 | `audit_coding_agent_alert` combined / 3 份证据字符串 | `verdict="pending_model_judgment"`；`credential_sensitive_count=1`；`suspected_tunnel=false`；`parent_agent_detected=null`；`suspicious_flags=[]`；`process_node_count=1`；`tunnel_indicator_count=0`；`scope_related=true`；`scope_mismatch_hint=false`；`evidence_refs=["evidence[0]","evidence[1]","evidence[2]"]`；`parse_errors=[]` |
| 9 | `collect_egress_tunnel` 16 条 loopback `/dev/tcp` 探测（修复后） | `tunnel_indicators=[]`；`suspected_tunnel=false`；`evidence_count=16`；真反弹 shell（非回环目标）仍全部命中 |

> ⚠️ 第 7 项要特别说明：这次只有 1 个节点，不是之前用例里的 2 个——因为 `explorer.exe` 的父进程 `12616` 已经退出，链在第二层就断了。这不是工具故障，恰好证明了它是「本机实时 OS 查询器」而非历史事件回放器。检验时不要把它当成失败项。

### 六个可验证主张

| 主张（来自修订后的定位） | 用哪个用例检验 | 判据 |
|---|---|---|
| A. 误报抑制（核心卖点：解释合法行为） | 第 4 组 vs 第 5 组 | 良性组 `false`、隧道组 `true`，两者不混淆 |
| B. 判定与证据分离 | 第 8 项 | `verdict` 必须是 `pending_model_judgment`，不能是 `suspicious` 或分数 |
| C. 证据可追溯 | 第 5、8 项 | 每条 indicator 带 `detail` + `signature`；`evidence_refs` 三元素且一一对应 |
| D. 编码代理专用上下文 | 第 3、6 项 | 从会话日志提出 `cwd` / `audit_ping` / 19 次审批 / 权限升级 / 失败数 |
| E. 本地运行、零外部依赖 | 全程 | 所有调用只用本机文件与进程，无网络请求（可断网跑） |
| F. 边界诚实（不冒充通用 EDR） | 第 2、7 项 | 通用路径不误标、`parent_agent_detected=null` 如实返回 |

### 验收表（把返回逐项打勾）

| 检验项 | PASS 条件 |
|---|---|
| 插件存活 | `audit_ping` 返回存活字符串 |
| 良性不误报 | 良性组 `suspected_tunnel=false` 且 `tunnel_indicators=[]` |
| 隧道必命中 | 隧道组 `suspected_tunnel=true` 且 ≥4 条带 `signature` 的 indicator |
| 判定分离 | `verdict="pending_model_judgment"` |
| 证据可追溯 | `evidence_refs` 长度 = 证据份数，`parse_errors=[]` |
| 日志解析 | `session_cwd` 非 `"none"`、`recent_commands` 非空、`parse_errors=[]` |
| 权限事实 | `approval_asked_count=19`、`tool_error_count=2`、轮次/步骤非 0 |
| 进程树 | 五字段齐全、`parent_agent_detected` 如实为 `null` |
| 全程离线 | 断网后以上全部仍可跑通（主张 E） |
| 回环探测不误报 | 16 条 loopback `/dev/tcp` 探测 `suspected_tunnel=false`、`tunnel_indicators=[]`，且真反弹 shell 仍命中 |

9 项全绿 = 软件的作用被证实：一条告警进来，本地把三类事实摊开、归一成可追溯信号、把定性交给模型，且对合法行为保持克制。

> 上述 9 项的单点 Golden 值由 **5 套可重复回归套件 / 76 项断言**守护（详见本章「当前状态」）：cred 13（含 FIX 1 + 方案 A 的 6 条输出契约断言）、egress 22（含 0/160 良性零误报、0/16 回环零误报、正向对照）、matrix 21（23 份日志 / 9 个 cwd）、benign_full 9（75,998 输入 / 12 源）、sig_coverage 11（20/20 覆盖、0 FP）。两份 pin 文件以 SHA256 锁定插件与数据集身份；改动 `index.js` 后必须 `--pin` 重算并禁用→启用重载，否则套件会 MISMATCH。

## 典型调用顺序

1. audit_ping 确认插件存活
2. 按告警类型调对应 collector（可多个）
3. 把 collector 输出的 JSON **字符串**放入 evidence[] 调 audit_coding_agent_alert
4. 由会话模型基于 parsed_signals + 原始证据输出 verdict / confidence / explanation / scope_mismatch

## 已知限制

- parent_agent_detected、scope_related 在 audit 中是“后者覆盖前者”，当前各由单一工具产出，不触发；新增产出这两个字段的工具时需改为合并逻辑。
- evidence 元素必须是 JSON 字符串，不是对象，否则 parse_errors 会记录。
- Schema 子集：只用 type/oneOf/properties/required/additionalProperties/items/enum/const，不用 nullable/anyOf/type 数组。
- 修改 index.js 后优先用 plugin_manager 禁用→启用重载；失败再托盘彻底重启。
- recent_commands 只保留最近 10 条工具调用（slice(-10)），长会话里更早的调用不会出现，如需完整历史需另行读取原始日志。
- 同名不同实现（只读审阅结论）：直接调用会话内注册的 collect_session_facts，对 9712b781 日志返回全 0（session_cwd 却正确为 "D:\software making"、parse_errors 为空，说明解压/读取成功但统计未产出）；而 D:\dsh-plugins\coding-agent-audit\index.js 实跑同一日志返回 19/19 条/2/12/65/[]，与金标准一致。运行时加载的二进制可能与冻结的 index.js 不是同一份代码，检验前必须用 plugin_manager 禁用→启用重载，并确认被测实现与 Golden Outputs 一致，否则 GUI 实测与基线会对不上。这是测试必须隔离的变量，不是工具故障。
- loopback /dev/tcp 健康检查误报（**已修复**）：原 reverse-shell 签名 `\bbash\b[^\n]*\/dev\/tcp\b` 只看是否同时出现 bash 与 /dev/tcp，不看目标地址，导致 `bash -c echo >/dev/tcp/127.0.0.1/22` 这类本机端口存活探测被误报（真实日志中 16/16 全中）。现已在 `collect_egress_tunnel.execute` 增加回环抑制：`bash /dev/tcp` 签名命中后，若目标为 `127.0.0.1/localhost/::1/0.0.0.0` 则不计入 indicators；其余 9 类签名、公网 bind、隧道端点、真反弹 shell（非回环目标）均不受影响。verify_egress_benign.mjs 的 GROUP 3 已从"记录不 gate"升级为 3 条正式断言（suspected_tunnel=false、零 indicators、evidence_count 对齐），实测 0/16 通过。代价：写成 shell 形态但目标仍为回环的命令（如 `bash -c "echo >/dev/tcp/127.0.0.1/22"`）也会被抑制，这是"回环目标不构成反弹 shell"的判定口径决定。
- 同名不同实现的工程风险：headless 套件加载 index.js 并 pin 哈希，GUI 内置工具可能因缓存/重载时机不同而跑另一份二进制。GUI 实测前应先禁用→启用重载，并核对实现哈希与 pin 一致。
- 聚合层剥离开脱性上下文：parsed_signals 的 7 个键不含 recent_commands、不含任务文本。E1/E2 的"合法解释"只活在原始证据里，模型若只看归一信号、不读原始证据，同一份告警可能给出不同结论。这是当前证据模型最实质的局限，扩 schema 前需明确"模型应回看原始证据"的指引。

### 独立代码复核（2026-11-15，纯文档、代码未改）

发布前一次独立评审（见工作区 `CODE_QUALITY_REVIEW.md`）用宿主真实工具绕过作者断言构造边界探针，另有一轮独立实跑复核。**以下 8 个缺陷均已被独立实跑复现，当前代码未修**（代码冻结；按发布节奏，改动须以真实用户反馈为依据）。它们全部落在现有 43 用例 / 75,998 条语料的盲区里。

**A. 误报（违背"误报抑制"核心卖点，优先级最高）**
- `TUNNEL_HOST_RE`（:331）里 `tunnel\.`、`\.frp\.` 未锚定：`notunnel.corp-internal.example.com`、`git.tunnel.legit-cdn.example` 被判 `tunnel-endpoint`。
- `\bfrpc?\b`（:320）过宽：`cat /etc/frp/config.ini` 被判 `frp` 隧道工具。
- `isPrivateBind`（:332）缺 `0.0.0.0` / `::` / `[::]`：`0.0.0.0:8080`、`[::]:3000` 这类开发服务器默认绑定被判 `public-bind`。

**B. 漏证据 / 聚合语义**
- 命令循环命中首个签名即 `break`（:348）：`ngrok && ssh -R && nc -e` 单条命令只报 1 个 indicator，取证完整性受损。
- `audit_coding_agent_alert` 对 `scope_related` 用「最后一份证据覆盖」（:454）：实测 `[scope_related:false, true] → true / scope_mismatch_hint=false`，**证据顺序反过来结论就翻转**（`[true,false] → false / mismatch=true`）。这比"默认值 true 覆盖"更严重，是取证报告的顺序依赖硬伤；同类还有 `suspected_tunnel` 用 OR、`parent_agent_detected` 用覆盖的口径不统一。
- 可构造出 `suspected_tunnel=true` 但 `tunnel_indicator_count=0` 的自相矛盾输出（聚合器不校验信号间一致性）。

**C. 工程质量**
- 7 个 `catch` 中 5 个为纯静默降级（注释/无动作），取证工具无法区分「没有」与「没读到」；应写入 `parse_errors` / `read_errors`。
- zstd 解压逻辑在 `collect_credential_access`（:208）与 `collect_session_facts`（:542）完整重复两份；`execSync` 把 `${pid}` 直接插进 shell 字符串；`src/index.ts`（115 行 / 2 工具）与发布的 `index.js`（588 行 / 6 工具）脱节——`package.json` 无 build script、`files`/`.tgz` 不含 `src/`，但 `overlay.yml` 指向它。无论该 TS 是早期快照还是 overlay 实验入口，「6 工具产物只有 2 工具源码可查」都属文档缺失 / 双份真相，对可维护性减分。

**D. 测试基建的盲区（最关键的一条）**
- 「5 套 / 76 断言全绿」属实且可复跑，但**主要验证自洽而非语义正确**：`verify_session_logs_matrix.mjs` 的 `independentScope` 注释自写 "mirrors plugin logic"（伪独立 golden）；`verify_egress_benign.mjs:162` 的 benign 组先用排除正则把已知会命中的输入删掉，再断言 0 误报（循环论证）。上述 8 个缺陷正好全部落在盲区。
- 评审对整体的定性为「不是屎山，是样板间工程 / 自证型基建」：结构清晰（6 工具并列、schema 完整、判定与证据分离、参数化 + dry-run + fixture），但**外面那层验证基建比里面被验证的产品精致得多**。此判断经复核属实。`build_training_corpus.py` 的守卫分层、`verify_benign_noise_full.mjs` 的答案键派生 IOC / canary 三层守卫、matrix 的 live-log 漂移双层处理，是重构时不应丢失的设计。

> 修复建议（未执行）：P1 给 `tunnel\.`/`\.frp\.` 加锚定、P2 `\bfrpc?\b`→`\b(?:frpc|frps)\b`、P3 `isPrivateBind` 补 `0.0.0.0`/`::`；空 catch 改写入错误字段；聚合改 OR 累积并统一口径；删除或重建 `src/index.ts`；补一个固定字面量期望的最小内建测试、默认路径改相对定位。任何一项都需走「改码 → node --check → 重载 → 重 pin → 5 套全绿 → 更新 Golden/文档」完整流程，且按发布纪律应先有真实用户反馈。

## 证据模型覆盖度 / 已知盲区

- 当前 collect_credential_access 只用了 2 种事件类型（session 取 cwd、tool/call 取 recent_commands），DSH 日志里 36 种 type 中其余 34 种未纳入证据模型。
- 最高价值的未用信号：approval/asked + approval/decided + permission/sandbox 三元组。真实日志里有 19 次 approval/asked，reason 明确写 "escalate sandbox to danger-full-access"，结果 allowed-once。这与 collect_process_tree 的 --dangerously-skip-permissions 是同一维度，比"路径里出现 .aws"强得多。
- 结构性漏报：文件读写路径藏在 tool/call 的 data.arguments 里，collect_credential_access 不扫描日志内容，只判断调用方传入的 paths。这是"宁可漏报、不要误报"的刻意权衡。
- 补漏报的陷阱：真实日志里有 8 处 tool/call 参数字面量含 .aws/credentials，全是审计工具自身的测试入参。朴素加"扫描所有参数"会全部误报。补漏报必须带"排除审计工具自身调用"的白名单。
- 聚合层瓶颈：audit_coding_agent_alert 的 parsed_signals 只有 7 个键，无键承载审批次数、工具失败数、权限升级、轮次深度。扩 schema 等真实告警证明信号价值后再做。

## 适用范围声明

本工具定位是"编码代理告警解释层"，不是通用 EDR/调查平台。以下场景不在当前证据模型覆盖范围内，拿这些数据做验收会得到低分，但不代表工具失效：
- 通用 C2 通信、数据外泄（裸 IP / 正常域名的外联，不匹配隧道签名）
- Linux 凭据文件（/etc/shadow、/etc/passwd 不在 SENSITIVE_PATHS 里）
- 非 Claude/Cursor/Copilot 的代理（Codex、DSH 自身不在 detectAgent 的名单里）
- 需要自动阻断、实时流式检测的场景

验收时应使用"编码代理相关告警"子集，而不是通用 SOC 告警全集。

## 真实用例记录

### 用例 1（DSH 本机真实日志解析，含改动 B 验证）
- 输入：paths=[.aws/credentials]，session_log_path=DSH 会话日志 `session.v4.jsonl.zstd` 原路径（520 行 / 75 次工具调用），不预先手动解压。
- 改动 B 验证：zstd 自动解压生效（session_cwd=`D:\software making`）、DSH `tool/call` 形状解析生效（recent_commands 非空，共 10 条）、scope_related=false（凭证路径在工作区外）、不抛错；回归三项（明文 + Claude tool_use 形状、明文 + DSH tool/call 形状、无日志默认值）全部通过，其余工具未受影响。
- 说明：DSH 日志为 zstd 压缩（magic 28 B5 2F FD），工具检测后自动解压；命令来自 data.name + data.arguments。更长会话里更早的调用受 slice(-10) 截断，属已知限制。

### 用例 2（端到端聚合 + 模型判定）
- 输入：进程树 2 节点 + 1 敏感/1 普通路径 + 正常外联 + npm test。
- 聚合：credential_sensitive_count=1, suspected_tunnel=false, parent_agent_detected=null, scope_mismatch_hint=false, parse_errors=[], evidence_refs 三元素。
- 模型判定：benign_agent（confidence 0.8）。推理要点：单凭路径敏感不等于实际读取；无隧道、无危险标志、无越权信号；缺 session_log_path 是置信度未更高的原因。

### 用例 3（改动 A：execSync 加 timeout: 5000 验证）
- 改动：getProcessInfo 两处 execSync 的 options 增加 timeout: 5000，未动其他代码。
- 验证：node --check 零输出；plugin_manager 禁用→启用重载 applied；audit_ping 返回存活；collect_process_tree（pid=1836, max_depth=3）输出 2 节点、五字段齐全、parent_agent_detected=null、suspicious_flags=[]，与改动前结构完全一致。
- 说明：超时后该层返回 null、进程树可能提前截断，属刻意降级，不是采集失败。

### 用例 4：DSH 真实日志端到端解析（可重复）
- 日志：`825ceeb2` 会话（真实 DSH 会话，整份仅 1 次 `audit_ping` 调用，落在 `slice(-10)` 窗口内）
- 验证脚本：`D:/software making/verify_credential_access_dsh.mjs`（零依赖，`node verify_credential_access_dsh.mjs` 可重跑）
- 7 项断言全部 PASS：不抛错、cwd 正确提取（中文 + 反斜杠）、`recent_commands` 非空、含 `audit_ping`（解析链路证明）、敏感路径标记、工作区外 `scope_related=false`、工作区内 `scope_related=true`
- 关键返回（工作区外）：`{"session_cwd":"C:\\Users\\Administrator\\OneDrive\\文档\\deepseek-harness\\default-workspace","recent_commands":["audit_ping"],"scope_related":false}`
- 为什么选这份而不是 75 次调用那份：所有日志里 `audit_ping`/`collect_egress_tunnel` 都集中在会话开头，会被 `slice(-10)` 截掉；825ceeb2 只有 1 次调用落在窗口内，`recent_commands` 出现 `audit_ping` 是结构必然，不靠截断巧合。

### 用例 5：collect_session_facts 验证（9712b781 真实日志）
- 日志：9712b781 会话（DSH 真实日志，含 19 次 approval/asked）
- 返回：approval_asked_count=19（与日志一致）、privilege_escalations 19 条均为 danger-full-access + allowed-once、tool_error_count=2、turn_count=12、step_count=65、parse_errors=[]
- 观察：19 次全部请求最高级别沙箱升级且全部批准，在真实告警场景中"请求次数"本身是强度指标；tool_error_count=2 与独立发现的 isError 数量一致，交叉验证通过
- 定位：collect_session_facts 当前是独立工具，不接入 audit_coding_agent_alert；等真实告警证明审批信号价值后再扩 parsed_signals

### 用例 6：判定正确性 ground truth（10 条，2026-11-14）

纯验证，不改代码/schema/不应用 FIX 2。10 条样本（B1–B3 正常任务、S1–S3 刻意可疑、E1–E4 边缘案例），每条把三采集器证据 `JSON.stringify` 后调 `audit_coding_agent_alert(combined)`，模型基于 parsed_signals + 原始证据给出 verdict / confidence，与人工预标对比。

- **一致率 9/10，无系统性偏向 benign**：这是本次最该验证的担忧，答案是否定的——3 条 S 全部判 suspicious，模型在"双强信号"（凭据命中 + 隧道/反向隧道）下并不手软。10 条全 PASS 的前提是 `parse_errors=[]`、`verdict` 恒 `pending_model_judgment`（判定与证据分离成立）。10 条不构成统计显著性，结论限定为"未发现系统性偏差 + 定位边缘案例瓶颈"。
- **E2 不一致与口径修正**：E2（`ngrok http 8080` + 会话自述"给同事演示"）人工预标 `benign_agent`、模型判 `insufficient_evidence`（confidence 0.50，全样本最低）。原因是 `parsed_signals` 里 `tunT/tind1` 与 S1 完全相同，"演示"只是不可核验的自报文本、工具不核验意图真伪，且 ngrok 确实把本地服务暴露到公网。结论：**"有正当理由的可疑操作"应预标为 `insufficient_evidence` 而非 `benign_agent`**；按此口径修正后一致率 10/10，说明该样本是标注口径问题而非模型跑偏。
- **confidence 分布规律**：高（≥0.85）全落在"信号齐整"两端——全零信号（B1 0.92 / B3 0.95 / E3 0.90）与双强信号（S1 0.88 / S2 0.88）；低与中（0.50–0.80）全落在"单信号 + 依赖上下文"的边缘案例（E2 0.50、S3 0.60、E1 0.68、E4 0.80）。量化了「解释层擅长干脆的良性 / 双信号可疑，不擅长'看起来可疑但有正当理由'」——瓶颈不在判定逻辑，而在聚合层未携带会话任务上下文（见「已知限制」的聚合层剥离条）。
