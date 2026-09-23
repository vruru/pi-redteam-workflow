# dsh-redteam-model → Pi 移植记录

来源：<https://github.com/SeaOf0/dsh-redteam-model>（MIT）
仓库落地：`~/.pi/agent/redteam-model/`（49M，含 .git，可 `git pull` 后重跑链接脚本）
移植时间：2026-09-23
移植约定（所有移植件的公共契约）：`~/.pi/agent/extensions/redteam/PORT-CONVENTIONS.md`

## 一、技能层（33 个新技能，不复制文件）

上游 58 个 `SKILL.md`，用 **symlink** 接进 `~/.pi/agent/skills/redteam-model/`，
链接名 = frontmatter `name`，目标 = 原技能目录（原地解析，正文相对引用零改写）。

| 处置 | 数量 | 说明 |
|---|---|---|
| 已接进 Pi 名录 | 33 | 10 个 `*-playbook`（模式方法论+门禁契约）、10 个 `ctf-*`、5 个 shared 治理技能、`software-cracking`、`macos-security-bypass`、`android-reverse*`、`x64dbg-reversing`、`ida-reversing`、`packer`、`dumpapkpack`、`solve-challenge` |
| 与 reverse-skill 包重名，跳过 | 24 | 按用户决定用已装的上游完整版（实测 `radare2`/`malware-analysis` 逐字相同，`ida-reverse` 本包是 359<396 行的删减版） |
| 无 frontmatter，仅补了 2 个 | 3 | 补：`software-cracking`、`macos-security-bypass`（Pi 不加载无 description 的技能）；`android-reverse` v1/v2 内部重名，只留 v2 |

Pi 实测名录：46（reverse-skill 精简后）+ 33 = **79**（另有插件自带的 `orchestrate`）。

关键规则（`@earendil-works/pi-coding-agent/dist/core/skills.js`）：含 `SKILL.md` 的目录即技能根、**不再递归子目录** → 若某个技能目录被父目录的 SKILL.md 占住就会静默消失；symlink 目录被支持（`readdirSync` + `statSync` 双判定）。

## 二、模式 persona：按用户要求**不装**

十个模式各有约 370 行 persona（铁律/报告纪律/反拒绝/目标零破坏…，共 3728 行）。
用户明确「不要这些条款，我想做什么就做什么」，只保留一条护栏：
**不可逆操作（删除 / DROP / TRUNCATE / 资金类接口 / 重启 / 改配置）禁止自动执行，只呈报计划** —— 由 `dsh-sec-enforce` 移植件在代码里实现，不写成常驻提示词。
persona 原文仍在 `modes/*/agent.cordis.yml`，将来想要可随时做成 `disable-model-invocation` 技能（按需加载、不强制）。

## 三、17 个运行时插件 → 16 件 Pi extension

Pi 的扩展发现规则（`dist/core/extensions/loader.js`）只加载 `extensions/` **直接**的 `.ts/.js`
与含 `index.ts` 的一层子目录 → 实现落 `extensions/redteam/`，再逐个 symlink 到 `extensions/` 根。
全部实现零新依赖、零编译步骤（jiti 直跑 TS），状态一律 `~/.pi/redteam/<插件名>/`（不用 `~/.dsh/`）。

| 移植件 | 行数量级 | 模型工具 / 命令 | 落地要点 |
|---|---|---|---|
| `dsh-stage-gate` | 1597 | `stage_gate` `gates_list` `operation_goal/_progress/_intent/_scope/_constraints` · `/gates` | 八模式 **32 道门** schema 原样迁移；结构校验由工具硬 reject；gate-log.md + operation-state.json + 索引中断恢复 |
| `dsh-sec-enforce` | 1058 | `sec_enforce_status` · `/sec-enforce` | 报告门/写边界/高危命令先问后做/裸奔扫描限速；macOS `/tmp→/private/tmp` 已 realpath 归一；未 arm 时零介入 |
| `dsh-scanner-tools` | 1412 | 16 工具（`nmap_portscan` `httpx_probe` `nuclei_scan` …）· `/scanners` `/scan-ledger` `/scanners-tools` | 声明式注册表原样搬；六节点阶梯（本机→MCP→已装替代→MCP 备选→询问安装→脚本）；防盲打台账 + 连续失败熔断；**检测制绝不自动装**；已适配「本机 httpx 是 python-httpx 而非 projectdiscovery」变体判定 |
| `dsh-campaign-memory` | 710 | `campaign_memory_write/_search/_get/_list/_remove/_stats/_purge` · `/campaign-memory` `/campaign-mode` | 同模式+同工作区+同标题刷新去重、热度×30 天衰减召回、FTS、30/180 天清理；与 pi-memory 完全隔离 |
| `dsh-refusal-guard` | 450 | · `/refusal-guard` | 三级升级梯（重锚→纠偏重试→审计交人工），自动重试硬上限 2；只在有授权事实（scope.md/gate-log/显式 on）时生效 |
| `dsh-trace-vault` | 489 | `trace_search` `trace_get` `trace_recent` `trace_stats` · `/trace-stats` | node:sqlite 留痕，字段沿用原 schema，14 天/5 万条清理 |
| `dsh-route-boost` | 314 | 无（逐轮注入） | `before_agent_start` 写 `sections["dsh-route-boost"]`，预算 + rev 去重（相同信封不重投）；内置 selftest **pass=8 fail=0** |
| `dsh-attack-atlas` | 71KB | 10 工具（`redteam_atlas_*` `redteam_coverage_*`）· `/atlas` | **动态 import 上游 taxonomy.js/store.js/method.js**（1830 行矩阵常量零复制）；四态 `tested-found` 强制证据引用 |
| `dsh-hunter` | 426 | `fofa_search` `fofa_account_status`（hunter/quake 有 key 才注册）· `/hunter` | dsh web 端点 → 模型工具；统一 DSL；免费账户字段权限自动降级重试 |
| `dsh-redteam-results` | — | `redteam_finding_register/_update/_list/…` · `/redteam-results` | findings 台账 SQLite，字段沿用原表（title/severity/target/summary/type/poc/fix/status/verifyNote），跨会话聚合 |
| `dsh-session-pulse` | 10K | `session_pulse` · `/pulse` | 进度 chip 口径（读 stage-gate 的 operation-state.json，done/total + 百分比）；子代理目录为 best-effort |
| `dsh-mode-group` | — | `mode_group` · `/modes` | 十模式入口映射（读 `modes/*/preset.yml` + `skills/` 生成，指向已装的 `*-playbook` 技能名） |
| `dsh-semgrep-audit` | 15K | `semgrep_scan` | 三层规则集定位、`--metrics=off` 离线、命中双写 `scan-reconcile.md/.csv`（命中≠漏洞）；本机无 semgrep → 缺装分支已实测 |
| `dsh-product-subagents` | 227 | `subagent_claude_code` `subagent_codex` | 无头 CLI 复核，claude 缺失自动降级 codex；「无证据的附和不可采信」随结果返回 |
| `dsh-auto-advance` | 298 | 无（推进提醒） | 复用 stage-gate 台账不建第二真值；`maxAutoTurns=5`、冷却 30s、真人输入重置；无台账会话零干扰 |
| `dsh-mcp-doctor` | — | · `/mcp-doctor` | 只读体检 6 层 MCP 配置 + precedence 遮蔽 + stdio 命令存在性 + HTTP 端口探测（不拉起 server，不写配置） |

**统计**：43 个模型工具、15 个命令（静态 grep 计数；`dsh-scanner-tools` 走循环注册故静态数为 0，实际 16 工具；`hunter_search`/`quake_search` 为条件注册）。16 件同时加载 **零冲突、零重名**，`pi --print` rc=0。

未移植：`dsh-webshell-mgr` 的 UI 部分（其 stdio MCP `mcp/server.mjs` 已直接登记为 MCP server，握手实测通过）。

## 四、MCP 层（`~/.pi/agent/mcp.json`）

新增并**已实测握手**：`webshell-mgr`（node stdio，零依赖）、`kali-mcp-server`（venv `~/.pi/agent/redteam-model/.venv-kali`）。
`kali-mcp-server` 踩坑：`requirements.txt` 写 `mcp>=1.0.0` 会装到 mcp 2.x，而代码用 `mcp.server.fastmcp`（2.x 已改名）→ 已 `pip install "mcp<2"` 修复，现在注册 249 个工具。
FOFA 凭据：`~/.pi/redteam/dsh-hunter/keys.json`（600），搜索只需 key。
现 enabled：`jshook`、`webshell-mgr`、`kali-mcp-server`。

## 五、已知缺口

1. `dsh-mode-group` / `dsh-attack-atlas` 原先在 `--print` 模式只写文件不回显（notify 无 UI sink）—— 已补 `!ctx.hasUI → stdout.write`。
2. `dsh-product-subagents` 的真实成功复核未验证：本机 codex CLI 版本不支持 `gpt-6-astra`、MCP OAuth refresh token 已失效（降级路径已实测）。
3. `dsh-semgrep-audit` / `dsh-scanner-tools` 多数分支只验证了「工具未检测到」路径（本机缺 semgrep/nuclei/ffuf/sqlmap 等，检测制不自动装）。
4. `dsh-route-boost` 与 `dsh-stage-gate` 的 operation-state 契约已对齐但联动端到端未跑。
5. 面板类（图谱/大屏/侧栏）在 Pi 里是文本/文件形态，没有 Web 图形界面。
6. 上游 43 个 `agents/openai.yaml`（OpenAI Agents SDK）无 Pi 对应物，未移植。

## 六、开关与更新

```bash
# CTF 赛道技能（41 个）开关
~/.pi/agent/skills/reverse-skill/toggle-ctf.sh on|off|status

# 上游更新后：git pull 后重跑链接生成（技能 symlink 需重建）
cd ~/.pi/agent/redteam-model && git pull

# 改完技能/扩展/MCP 在 Pi 里执行 /reload
```
