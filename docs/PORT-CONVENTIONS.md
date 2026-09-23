# DSH 插件 → Pi extension 移植约定（所有移植件必须遵守）

源仓库（只读，禁止修改）：`~/.pi/agent/redteam-model/`
- 每个插件的**已编译实现**在 `plugins/<name>/lib/*.js`（无 .ts 源码，dsh-mcp-studio 除外）
- 行为说明看 `plugins/<name>/README.md` 与 `plugins/<name>/cordis.patch.yml`
- 模式定义（含门禁 schema）在 `modes/<mode>/agent.cordis.yml`、`modes/<mode>/skills/*-/SKILL.md`

目标：输出 Pi extension，落 `~/.pi/agent/extensions/redteam/<dsh-name>.ts`（多文件用目录 + `index.ts`）

## 硬性约定
1. 头部：`import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";`，`export default function (pi: ExtensionAPI) { ... }`。Pi 用 jiti 直跑 TS，**不要**编译步骤、不要引入新 npm 依赖（Node 内置模块 + 已存在的 node_modules 可用）。
2. **保留原模型可见的工具名**（playbook 技能正文按这些名字调用）：如 `stage_gate`、`gates_list`、`trace_search`、`campaign_memory_write`、`nuclei_scan`。参数语义与返回文本结构尽量对齐原实现，让 playbook 文本无需改写。
3. Pi 事件映射（Cordis → Pi）：
   - 工具调用拦截/改写 → `pi.on("tool_call", ...)`（可 mutate input 或 block；返回 `{ block: true, reason }` 语义以 docs/extensions.md 为准）
   - 逐轮上下文注入 → `pi.on("before_agent_start", ...)`（改 prompt sections / guidelines，别整段替换 systemPrompt）
   - 结果加工 → `pi.on("tool_result", ...)` / `pi.on("message_end", ...)`
   - 会话生命周期 → `session_start` / `session_shutdown`（幂等清理）
   - 收尾提醒/自动推进 → `turn_end` 或 `agent_before_settle`（可 `continue: true` 一次，必须有循环护栏）
   - 长驻资源（DB/定时器/子进程）只在 `session_start` 或对应 tool/command 里创建
4. 状态目录：一律 `~/.pi/redteam/<plugin-name>/`（**不要**用 `~/.dsh/`，避免和 dsh 运行时抢文件）。工作区产物（gate-log.md、evidence-index.md 等）仍落在当前工作目录/任务工作区，与原设计一致。
5. 工具必须返回 `{ content: [{ type: "text", text }], details }`；大输出截断并告知全文路径。错误用 throw。
6. UI 降级：面板/图表类只做三件事——`ctx.ui.notify()` 摘要、`ctx.ui.setWidget()`/状态文本、`pi.registerCommand()` 打印表格或写 markdown 文件。**禁止**假设 web 前端；终端专有行为用 `ctx.mode === "tui"` 守卫，保证 `--print`/JSON 模式不报错。
7. 检测制：外部二进制（nuclei/semgrep/ffuf…）缺失时**不得自动安装**，工具返回明确的"未检测到 + 三级兜底建议"，与原包一致。本机现状：有 `nmap`、`httpx`、`codex`；无 `claude`、`semgrep`、`nuclei`、`ffuf`、`sqlmap`、`subfinder`。
8. 安全护栏（用户已同意的唯一 persona 条款）：删除/`DROP`/`TRUNCATE`、资金类接口、服务重启、改配置等不可逆操作**禁止自动执行**，只生成执行计划呈报；目标侧资产零破坏。这条由 dsh-sec-enforce 移植件实现。

## 交付与自测（每个移植件都要做）
- 写完后跑：`cd ~ && pi --extension ~/.pi/agent/extensions/redteam/<name>.ts --print "reply ok" </dev/null` —— 必须无加载错误（stderr 无 extension 报错）
- 再跑一次功能冒烟：用 `pi --extension ... --print "<让模型调用你注册的那个工具>"`，或直接 `node --input-type=module -e` 走纯函数路径
- 若依赖工作区文件（gate-log.md 等），在 /tmp 下建临时目录测
- 报告：文件路径、注册的工具/命令清单、与原实现的差异、实测命令与输出摘要、未完成项
