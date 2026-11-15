# 编码代理审计助手（coding-agent-audit）

> 当 Cursor / Claude Code 触发安全告警时，帮你快速判断是正常开发还是入侵信号。

一个架在现有 EDR/SIEM 之上的**编码代理告警解释层**。它不重新检测，只接手已经触发的告警，用编码代理的上下文把它解释成一份分析师几十秒就能决定「值不值得看」的可审计报告。

- 本地运行、零第三方依赖、无回调、可离线审计
- 判定与证据分离：工具只陈述事实，定性交给会话里的模型
- 主动误报抑制：正常开发连接不被当成隧道

---

## 它怎么工作

```
采集证据  →  聚合信号  →  模型判定
进程树 / 凭据路径 / 出站隧道     归一成可追溯信号      合法代理行为 / 可疑 / 证据不足
（三个 collector，只陈述事实）   （含 evidence_refs）  （模型基于证据，不由工具打分）
```

六个工具：`audit_ping` · `collect_process_tree` · `collect_credential_access` · `collect_egress_tunnel` · `audit_coding_agent_alert` · `collect_session_facts`。

---

## 它不做什么（先读这个）

主动交代边界，比任何性能数字都重要。**以下场景不在当前证据模型覆盖范围内，拿这些数据验收会得到低分，但不代表工具失效：**

- 通用 C2 通信、数据外泄（裸 IP / 正常域名的外联，不匹配隧道签名）
- Linux 凭据文件（`/etc/shadow`、`/etc/passwd` 不在敏感清单里）
- 非 Claude / Cursor / Copilot 的代理（Codex、DSH 自身不在进程名识别名单里）
- 需要自动阻断、实时流式检测的场景

它也不是新的 EDR/SIEM、不自动阻断任何进程或连接、不替代人工复核。
完整边界见 [USAGE.md](USAGE.md) 的「适用范围声明」「数据源适配性」。

---

## 怎么跑起来

**最简单**：下载分发包 `dsh-plugin-coding-agent-audit-0.2.0.tgz`，用 DSH 桌面版 → 设置 → 插件 → 安装本地插件导入 → 禁用→启用重载 → 在对话框发「请使用 audit_ping 工具，确认插件是否已加载」。看到 `coding-agent-audit plugin is alive` 就成了。

详细步骤（图形界面 / 命令行 / 自检 / 故障排查）见 **[INSTALL.md](INSTALL.md)**；双击包内 **`usage.html`** 可用四个卡片生成指令，无需记工具名、无需拼 JSON。

开发或改代码请用 `link:` 安装方式——`.tgz` 是代码快照，改本机 `index.js` 不会生效。

---

## 兼容性与版本

- **仅在 DeepSeek Harness `0.2.2-rc.1` 上验证**（`package.json` 的 `engines.dsh` 精确锁定该版本）。
- DSH 官方当前处于 **developer preview**，插件 API 可能发生破坏性变更。**升级 DSH 后请重新验证本插件**；一个 DSH 升级导致的挂起，问题在生态早期阶段而非本工具，但这会影响第一印象，所以这里显式声明。
- 版本 `0.2.0`。技术基线（哈希 `33620313…66`、5 套回归套件 76 断言、误报抑制 75,998 输入 0 误报、签名覆盖 20/20、10 条 ground truth 一致率 9/10）见 [USAGE.md](USAGE.md)「MVP 验收基线」。

---

## 文档

| 文件 | 内容 |
|---|---|
| [INSTALL.md](INSTALL.md) | 安装 / 重载 / 自检 / 故障排查 |
| [USAGE.md](USAGE.md) | 工具清单、适用范围声明、数据源适配性、验收基线、真实用例 |
| [SECURITY.md](SECURITY.md) | 漏洞报告方式 |
| `usage.html` | 告警指令生成器（双击即用） |

---

## 和通用 SOC / 通用 DSH 插件的区别

通用 UEBA 看「行为是否偏离历史基线」，但编码代理的异常往往是从第一次动作起就偏离声明角色；本工具在证据里专门保留「被访问路径是否落在会话工作目录内」这一维度，处理「合法但越权」的边缘案例。它是**垂直的编码代理 SOC 告警解释层**，不是通用检测引擎，也不是通用插件。

---

## 许可

[Apache-2.0](LICENSE)。Copyright 2026 The coding-agent-audit authors。

## 安全问题

请勿在公开 Issue 里提交漏洞，见 [SECURITY.md](SECURITY.md)。
