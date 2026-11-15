# 安装与交接指南（coding-agent-audit）

> 面向没参与开发的同事：照着做，独立完成「安装 → 打开 usage.html → 贴一条告警 → 看到报告」。
> 本插件是本地零依赖的工具集（6 个工具），不需要联网、不需要 API Key、不改动 EDR/SIEM。

---

## 0. 先知道两件事

1. **它是什么**：编码代理告警解释层。接手一条已被 EDR/SIEM 触发的告警，本地把进程树 / 凭据路径 / 出站隧道三类事实摊开，归一成可追溯信号，把「合法 / 可疑 / 证据不足」的定性交给会话里的模型。**它不做检测、不阻断、不自动判定。**
2. **它不能验证什么**：通用 C2/外泄、Linux `/etc/shadow`、非 Claude/Cursor/Copilot 的代理、实时流式检测都不在覆盖范围内。详见 USAGE.md 开头「适用范围声明」「数据源适配性」「MVP 验收基线」三节。

---

## 1. 安装（两种来源，选其一）

插件目录必须包含运行时文件：`index.js`、`package.json`、`cordis.patch.yml`；文档与页面：`README.md`、`USAGE.md`、`INSTALL.md`、`SECURITY.md`、`LICENSE`、`usage.html`。
`package.json` 里已声明 `"dsh": { "bundle": { "patch": "./cordis.patch.yml" } }`，`cordis.patch.yml` 插入一行 `id: coding-agent-audit`；`files` 白名单已锁定上述 9 个文件，`pnpm pack` 不会把 `node_modules` / `src` / 测试脚本 / 临时文件打进包。

### 方式 A：本地目录（开发 / 演示机，推荐）
把本仓库 clone / 解压到本机任意目录，在桌面版 → 设置 → 插件 → 安装本地 bundle，指向该目录。
profile 里登记为 `link:<插件目录>`，改 `index.js` 后刷新即可生效。

### 方式 B：分发包 `.tgz`
从 GitHub Releases 下载 `dsh-plugin-coding-agent-audit-0.2.0.tgz`，或在源码目录执行 `pnpm pack` 自行生成（`files` 白名单限定内容）。用桌面版插件面板安装该 tgz，或交给插件管理流程导入。

> ⚠️ **tarball 是代码快照，不是 `link:` 实时链接**：安装 `.tgz` 后，改本机 `index.js` 不会生效，必须重新 `pnpm pack` 并重装。
> 如需修改代码做开发，请改用「方式 A」的 `link:` 安装方式——它直接指向源目录，改完刷新即生效。

### ⚠️ 不要手写 profile 配置
**不要**直接编辑 `$DSH_HOME/profiles/*/package.json`、`cordis.patch.yml`，也不要在 profile 目录里跑 `pnpm`。
这些文件由桌面版 / `plugin_manager` 独占管理，手写会报
`profile "desktop" is managed exclusively` 之类的错误并被拒绝。
**安装一律走「插件面板 / plugin_manager install_bundle」**，让工具自己写 profile。

---

## 2. 确认插件活着（每重装 / 改代码后必做）

1. 用 `plugin_manager` 对 `include:coding-agent-audit` **禁用 → 启用**重载（结果应显示 `application: applied`）。
   只重载不彻底重启通常就够；若没生效，从系统托盘**彻底退出桌面版进程再重开**。
2. 在 DSH 对话框里发：
   ```
   请使用 audit_ping 工具，确认插件是否已加载。
   ```
   预期返回：`"coding-agent-audit plugin is alive"`。
3. **核对实现哈希**（防「同名不同实现」）：GUI 内置工具可能因缓存/重载时机跑另一份二进制。
   凡 GUI 实测前，确认禁用→启用重载已完成；需要严格比对时，核对当前 `index.js` 的 SHA256 与
   `USAGE.md`「MVP 验收基线」记录值、`verify_egress_benign.pins.json` 的 `plugin.sha256` 一致。

> 改动 `index.js` 后，若你另有回归套件（pin 文件），需在该套件所在目录执行
> `node verify_egress_benign.mjs --pin` 和 `node verify_session_logs_matrix.mjs --pin` 重算；
> 这些验证脚本不在本发布仓库内，属开发者本地工具链。

---

## 3. 打开 usage.html，贴一条告警

双击 `usage.html`（纯静态页面，浏览器直接打开，无需服务器）。四个卡片：

| 卡片 | 填什么 | 生成什么 |
|---|---|---|
| 场景一：不认识的进程 | 告警里的 PID | `collect_process_tree` 指令 |
| 场景二：读了敏感文件 | 一行一个文件路径 | `collect_credential_access` 指令 |
| 场景三：对外连接 / 隧道 | 一行一个命令行 | `collect_egress_tunnel` 指令 |
| 高级：聚合报告 | 三份工具输出的 JSON 字符串，每行一个 | `audit_coding_agent_alert` 指令 |

点「生成指令」→「复制上面的指令」→ 粘贴到 DSH 对话框 → 发送。
DSH 会调用工具并给出可审计报告骨架（`verdict: "pending_model_judgment"` + `parsed_signals` + `evidence_refs`），最终定性由模型结合证据给出。

> 四个生成器产出的指令已在 2026-11-13 用 headless 实跑验证：参数可解析、对应工具不抛错、聚合器 `parse_errors=[]`。
> 但 **「粘贴到 GUI 后页面正常渲染报告」这一步需要你在本机浏览器里走一遍**（见第 5 节核对清单）。

---

## 4. 新人核对清单（GUI 侧，需人工打勾）

以下动作无法由脚本代做，请安装者在自己桌面逐项确认：

- [ ] 插件面板能看到 `dsh-plugin-coding-agent-audit`，状态 enabled，`include:coding-agent-audit` active
- [ ] 若为手动写入 profile，确认**没有**触发 `managed exclusively` 报错
- [ ] `audit_ping` 返回存活字符串
- [ ] 双击 `usage.html` 能用默认浏览器打开、四个卡片可见
- [ ] 场景一填一个真实 PID，生成指令粘贴到 DSH 后返回进程树（`nodes` 数组）
- [ ] 场景二填一个敏感路径 + 一个普通路径，返回 `path_hits[].sensitive` 一真一假
- [ ] 场景三填 `ngrok http 8080`，返回 `suspected_tunnel: true` 且带 `signature`
- [ ] 高级卡片放三份证据 JSON 字符串，返回 `pending_model_judgment`、`parse_errors=[]`、`evidence_refs` 三元素
- [ ] 全程断网也能跑通（本地零依赖）

---

## 5. 出问题先查这里

| 现象 | 原因 / 处理 |
|---|---|
| `audit_ping` 不出现 | 未重载；对 `include:coding-agent-audit` 禁用→启用，必要时托盘彻底重启 |
| `profile "desktop" is managed exclusively` | 手写了 profile 配置；删掉手写改动，改用插件面板 / `plugin_manager` 安装 |
| GUI 结果与 USAGE.md 基线对不上 | 同名不同实现；先重载并核对 `index.js` SHA256 与 pin 一致 |
| `evidence` 报 `parse_errors` | 元素必须是 **JSON 字符串**不是对象；用 usage.html 高级卡片生成，别手拼 |
| 改了 `index.js` 后回归套件 FAIL | pin MISMATCH；两份 pin 重新 `--pin` |
| 工具判不出通用 C2 / `/etc/shadow` | 设计边界，见 USAGE.md「适用范围声明」，不是缺陷 |

---

## 6. 当前验收基线（只读）

- 插件 `index.js` SHA256：`33620313…66`
- 5 套回归套件 / 76 项断言全绿：`verify_credential_access_dsh.mjs` 13、`verify_egress_benign.mjs` 22、`verify_session_logs_matrix.mjs` 21、`verify_benign_noise_full.mjs` 9、`verify_signature_coverage.mjs` 11
- 误报抑制：75,998 个唯一良性输入 / 12 源，egress 0 误报；签名覆盖 20/20、0 FP

详细口径见 `USAGE.md`「MVP 验收基线」。本文件与代码冻结无关，仅描述安装与交接流程。
