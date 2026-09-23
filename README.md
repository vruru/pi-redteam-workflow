# pi-redteam-workflow

给 [Pi](https://pi.dev) 的**逆向工程 / 渗透测试 / 红队安全工作流合集**：
**79 个技能 + 16 个 Pi 扩展 + 13 个常用安全 MCP 登记**，装上就能用，不需要 DeepSeek Harness。

它把两套上游内容适配成 Pi 原生资源：

| 上游 | 内容 | 本包形态 |
|---|---|---|
| [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)（经 [dhicoc/dsh-reverse-skill](https://github.com/dhicoc/dsh-reverse-skill)） | 87 个逆向 / 渗透 / CTF 技能 | 46 个启用 + 41 个 CTF 赛道技能默认停用（可开关） |
| [SeaOf0/dsh-redteam-model](https://github.com/SeaOf0/dsh-redteam-model) | 十个工作模式 + 58 个技能 + 17 个 DSH 运行时插件 | 33 个新技能 + **16 个重写为 Pi extension** |

> 上游是 DSH（DeepSeek Harness）插件，依赖 Cordis 运行时与 dsh web 前端，**无法直接跑在 Pi 上**。本包重写为 Pi extension API（jiti 直跑 TS、零编译、零新增 npm 依赖），并逐件实测。

---

## 安装（三步）

```bash
# 1) 装包
pi install git:github.com/vruru/pi-redteam-workflow

# 2) 建立仓库链接 + 合并 MCP 配置（幂等，可反复跑）
node ~/.pi/agent/git/github.com/vruru/pi-redteam-workflow/scripts/setup.mjs
#    Pi 把 git 包装在 <agentDir>/git/<host>/<owner>/<repo>；不确定落点就跑 `pi list` 查看。
#    想顺便为 kali-mcp-server 建 Python venv：加 --with-kali-mcp
#    只想看不写：加 --check

# 3) 在 Pi 里执行
/reload
```

第 2 步做两件事：把 `~/.pi/agent/redteam-model` 符号链接到包内 `data/redteam-model`（14 个扩展按此路径读模式门禁 schema、refs 知识库与规则集）；把 `mcp/recommended.json` 合并进你的 `~/.pi/agent/mcp.json`（**同名 server 默认保留你已有的条目**，要覆盖加 `--overwrite-mcp`，覆盖前自动备份）。

验证：

```
/modes          十个安全模式入口与对应 playbook 技能
/gates          八模式 32 道阶段门 schema
/mcp-doctor     13 个 MCP server 逐个体检（命令存在性 / 端口可达 / 配置遮蔽关系）
/skill:reverse-skill-router   让路由器替你选方向
/skill:apk-reverse            或直接点名某个技能
```

---

## 你会得到什么

### 技能（79 个进入 Pi 名录）

- **通用逆向**：`reverse-engineering`、`ida-reverse`、`ghidra-reverse`、`radare2`、`x64dbg-reversing`、`dotnet-reverse`、`go-rust-reverse`、`macos-reverse`、`android-reverse`、`apk-reverse`、`mobile-reverse`、`browser-extension-reverse`、`thick-client`、`protocol-reverse`、`dsl-vm-reverse`
- **破解 / 免杀 / 加固**：`software-cracking`（注册算法还原 → keygen → 补丁 → 联网验证绕过）、`packer`、`edr-bypass-re`、`macos-security-bypass`
- **利用与固件**：`pwn-chain`、`firmware-pentest`、`binary-diff`、`patch-diff-exploit`、`malware-analysis`
- **渗透 / 专项安全**：`pentest-tools`、`src-hunter`、`api-security`、`cloud-k8s`、`database-security`、`windows-ad`、`identity-federation`、`llm-security`、`supply-chain-security`、`threat-hunting`、`digital-forensics`、`ot-ics`、`wifi-wireless`、`radio-sdr`、`hardware-security`、`email-security`、`threat-intelligence`
- **模式 playbook（方法论 + 门禁契约）**：`router-playbook`、`pentest-playbook`、`re-playbook`、`ad-playbook`、`av-playbook`、`audit-playbook`、`ir-playbook`、`cloud-playbook`、`ctf-playbook`、`asset-mapping-playbook`
- **CTF 分类手册**：`ctf-web` / `ctf-pwn` / `ctf-reverse` / `ctf-crypto` / `ctf-misc` / `ctf-forensics` / `ctf-osint` / `ctf-malware` / `ctf-ai-ml` / `ctf-writeup`
- **治理与协作**：`independent-review`（独立复核员）、`ecosystem-cooperation`、`red-team-command-doctrine`、`redteam-boundary-policy`、`case-review`、`docs-generator`、`diagram-generator`
- 另含上游 **refs 知识库约 21M**（渗透/代码审计/CTF/应急手册级原文），技能正文按需 read，不占常驻上下文

停用未装载：41 个 `competition-*` CTF 赛道技能 + 24 个与上游重名的技能（都在 `skills/**/.disabled/`，Pi 不扫点开头目录）。开关 CTF 赛道：

```bash
~/.pi/agent/skills/reverse-skill/toggle-ctf.sh on|off|status
```

### 扩展（16 件，约 43 个模型工具 + 15 个命令，实测零重名零冲突）

| 扩展 | 干什么 |
|---|---|
| `dsh-stage-gate` | `stage_gate` / `gates_list` + `operation_goal/_progress/_intent/_scope/_constraints`：八模式 **32 道门**结构校验，判定写 `gate-log.md`，中断可恢复。结构校验由工具硬 reject，模型不能自评过关 |
| `dsh-sec-enforce` | 确定性拦截：报告门、写边界、**高危/不可逆操作先问后做**、裸奔扫描限速；留痕 `enforce-log.md`；未 arm 时零介入 |
| `dsh-scanner-tools` | 16 个扫描工具封装（nmap/masscan/nuclei/httpx/ffuf/subfinder/gau/whatweb/wafw00f/dirsearch/sqlmap/nikto/hydra/impacket/netexec/crackmapexec）：声明式注册表 + 保守默认参数 + 六节点兜底阶梯（本机→MCP→已装替代→MCP 备选→询问安装→脚本）+ 防盲打台账 + 连续失败熔断。**检测制，绝不自动装工具** |
| `dsh-semgrep-audit` | `semgrep_scan`：三层离线规则集定位、`--metrics=off`、命中双写 `scan-reconcile.md/.csv`（命中≠漏洞，复核后才升格） |
| `dsh-hunter` | `fofa_search` / `fofa_account_status`：被动资产测绘，游标分页，免费账户字段权限自动降级重试 |
| `dsh-attack-atlas` | 攻击面矩阵四态点亮、阶段带、**按目标分账**、链路拓扑、自定义工作方法论、能力库；直接 `import` 上游 1830 行矩阵定义（零常量复制） |
| `dsh-campaign-memory` | 战役记忆：同模式+同工作区+同标题刷新去重、热度×30 天衰减召回、30/180 天清理，与通用记忆完全隔离 |
| `dsh-refusal-guard` | 反拒绝三级升级梯（重锚→纠偏重试→审计交人工），仅在存在授权事实时生效，自动重试硬上限 2 |
| `dsh-route-boost` | 逐轮治理信封：阶段/门禁/边界/证据等级/refs 指针/工具就绪/operation 恢复行；**信封没变就不重复投递**，有注入量记账 |
| `dsh-auto-advance` | 子代理返回且台账有未收口方向时注入一次推进提醒（封顶 5 轮、30s 冷却、真人输入重置） |
| `dsh-trace-vault` | 工具调用全量留痕 SQLite + `trace_search/_get/_recent/_stats` 检索与画像 |
| `dsh-redteam-results` | 成果台账：`redteam_finding_register/_update/_list` 等，字段沿用上游（title/severity/target/summary/type/poc/fix/status/verifyNote），跨会话聚合 |
| `dsh-session-pulse` | 会话进度（done/total + 百分比，读 stage-gate 状态）与子代理目录 |
| `dsh-product-subagents` | `subagent_review`：用 **Pi 自身模型**做独立复核（`streamSimple`，usage 记账、同源性如实标注），claude/codex CLI 是可选增强、检测不到就静默 |
| `dsh-mode-group` | `/modes` 十个模式入口与 playbook 映射 |
| `dsh-mcp-doctor` | `/mcp-doctor`：只读体检 6 层 MCP 配置（遮蔽关系、stdio 命令存在性、HTTP 端口探测），不拉起 server、不写配置 |

### MCP（13 个登记，默认启用 3 个实测通过的）

- 默认可用：`jshook`（JS 逆向 Hook/CDP/AST）、`webshell-mgr`（webshell 管理）、`kali-mcp-server`（249 个安全工具封装）
- 依赖外部软件，默认停用：`idapro`(13337)、`ghidra`(8765)、`burpsuite`(9876)、`anything-analyzer`(23816)、`pentest`(8080)、`reqable-mcp`、`kali-server`、`metasploit-mcp`、`pentestswarm`、`stitch`
- 启用：`/mcp enable <名字>` 然后 `/reload`；先跑 `/mcp-doctor` 看谁真的通

---

## 设计取舍（会影响你的使用体验，请读）

1. **模式 persona 没有装。** 上游十个模式各带约 370 行 persona（铁律、报告字段纪律、反拒绝条款、目标零破坏…）。它们会持续约束模型行为，本包默认**不注入**；你随时可以 `/skill:pentest-playbook` 主动取用方法论。唯一被保留的硬性护栏是「**删除 / DROP / TRUNCATE / 资金类接口 / 服务重启 / 改配置等不可逆操作禁止自动执行，只呈报计划**」，由 `dsh-sec-enforce` 用代码实现，而不是写成提示词。
2. **面板类是文本/文件形态。** 攻击面图谱、成果大屏、会话侧栏在 Pi 里没有 web 容器，因此输出为 markdown 台账 + 文本表格 + 状态行；`--print` / JSON 模式完全可用。
3. **缺工具不代装。** scanner / semgrep 走检测制，缺了会给你三级兜底建议（含可复制的脚本替代），不会擅自 `brew/pip install`。
4. **AttackAtlas 覆盖态已改为工作区级跨会话延续**（上游原本是 session-scoped）：同一工作区里新会话直接接着上次的矩阵与锚定目标，旧库自动迁移（迁移前备份 `atlas.db`）。

## 已知限制

- `dsh-semgrep-audit` / `dsh-scanner-tools` 的部分分支只验证过「工具未检测到」路径（取决于你本机装了什么）。
- `dsh-product-subagents` 的 claude/codex 可选路径需要相应 CLI 版本较新；默认 Pi 模型复核路径已实测通过。
- 上游 43 个 `agents/openai.yaml`（OpenAI Agents SDK 定义）无 Pi 对应物，未移植。
- `kali-mcp-server` 的上游 `requirements.txt` 写着 `mcp>=1.0.0`，但代码使用 `mcp.server.fastmcp`（mcp 2.x 已改名）→ 必须钉 `mcp<2`；`setup.mjs --with-kali-mcp` 已代为处理。

## 凭据

资产测绘 key 放 `~/.pi/redteam/dsh-hunter/keys.json`（权限 600）：

```json
{ "fofa": "<你的 FOFA key>", "fofa_email": "", "fofa_username": "", "hunter": "", "quake": "" }
```

FOFA 搜索只需 key。免费账户（`fcoin: 0`）不支持 `lastupdatetime` / `product` 输出字段，工具会自动去字段重试；`hunter` / `quake` 有 key 才会注册对应工具。

## 目录结构

```
pi-redteam-workflow/
├── package.json            # pi manifest（skills / extensions 显式声明）
├── extensions/             # 16 件移植件 + upstream/attack-atlas-lib（上游矩阵与 store，只读复用）
├── skills/
│   ├── reverse-skill/      # 87 技能（41 赛道在 .disabled/）+ toggle-ctf.sh
│   └── redteam-model/      # 33 个技能目录（符号链接 → ../data/redteam-model/…）
├── data/redteam-model/     # 上游仓库全量：modes persona/playbook、refs 知识库、kali-mcp-server、webshell 载荷
├── mcp/recommended.json    # 13 个 server 模板（{{HOME}} 占位）
├── scripts/setup.mjs       # 幂等安装：仓库链接 + MCP 合并 + 可选 venv
└── docs/                   # 移植约定、两份移植记录、侦察简报
```

## 许可与来源

MIT（见 `LICENSE`）。技能与知识库内容版权归上游作者：
`zhaoxuya520/reverse-skill`（MIT）、`SeaOf0/dsh-redteam-model`（MIT），随包保留其 `LICENSE` 与致谢。
本包只做适配（目录重排、DSH 插件→Pi extension、MCP 登记、字段权限修正），未修改上游仓库文件。

⚠️ 仅用于**已获授权**的逆向、渗透测试、CTF、漏洞赏金与安全研究。
