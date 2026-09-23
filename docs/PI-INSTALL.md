# reverse-skill → Pi 移植安装记录

来源：<https://github.com/dhicoc/dsh-reverse-skill>（上游 `zhaoxuya520/reverse-skill`，MIT）
安装时间：2026-09-23
安装位置：`~/.pi/agent/skills/reverse-skill/`
技能总数：**87 个**（名称唯一、命名合规，全部验证可被 Pi 发现）
当前精简状态：**只启用 46 个**（45 个通用逆向/渗透 + `ctf-sandbox-orchestrator` 入口），41 个 `competition-*` 赛道技能在 `.disabled/`，见下方「精简开关」。

## 与原 DSH 插件的差异（为 Pi 做的改动）

Pi 的技能发现规则是「含 `SKILL.md` 的目录即技能根，不再向下递归」
（`@earendil-works/pi-coding-agent/dist/core/skills.js` → `loadSkillsFromDirInternal`），
与 DSH 自带的递归 scanner 不同，因此做了目录重排：

| 原路径 | Pi 安装路径 | 原因 |
|---|---|---|
| `skills/SKILL.md`（路由器） | `skills/reverse-skill-router/SKILL.md` | 路由器占住 `skills/` 会让 41 个模块全部消失 |
| `skills/pentest-tools/src-hunter/` | `skills/src-hunter/` | 嵌套在含 SKILL.md 的父目录下不可见 |
| `skills/reverse-engineering/dsl-vm-reverse/` | `skills/dsl-vm-reverse/` | 同上 |
| `CTF-Sandbox-Orchestrator/competition-*/` | `.disabled/competition-*/` | 精简开关，见下 |

随之重写的相对路径引用（已全部同步，无悬空引用）：
`skills/reverse-skill-router/SKILL.md`、`skills/routing.md`、`skills/routing_zh.md`、
`skills/INDEX.md`、`skills/MASTER-ROUTING.md`、`skills/config/routing.json`、
`skills/references/domain-coverage-map.md`、`skills/pentest-tools/references/recon-pipeline.md`、
`skills/pentest-tools/SKILL.md`（指向 `../src-hunter/`）。
路由器正文顶部新增「路径约定（Pi 安装版）」说明；
`CTF-Sandbox-Orchestrator/ctf-sandbox-orchestrator/SKILL.md` 顶部新增赛道技能停用状态说明。

未移植：`CTF-Sandbox-Orchestrator/*/agents/openai.yaml`（43 个 OpenAI Agents SDK 定义，Pi 无对应映射，保留在仓库内不加载）。

## MCP（写入 `~/.pi/agent/mcp.json`，Pi 全局层）

| server | 传输 | 状态 | 前置条件 |
|---|---|---|---|
| `jshook` | stdio `npx -y @jshookmcp/jshook@0.3.4` | **唯一启用项**，握手实测通过（v0.3.4，tools/prompts/resources） | 无 |
| `idapro` | http `127.0.0.1:13337/mcp` | 已登记 · 停用 | IDA Pro + `ida-pro-mcp` 插件，打开二进制后自动监听 |
| `ghidra` | http `localhost:8765/mcp` | 已登记 · 停用 | `ghidraRun` 启动 GUI + 安装 GhidraMCP 扩展 |
| `burpsuite` | http `localhost:9876/mcp` | 已登记 · 停用 | Burp Suite + `burp-mcp-full` 扩展 |
| `anything-analyzer` | http `localhost:23816/mcp` | 已登记 · 停用 | 该项目仓库 `pnpm dev` |
| `reqable-mcp` | stdio `npx -y reqable-mcp-server@1.0.1 --scope minimal` | 已登记 · 停用 | Reqable 桌面客户端（npm 包已验证存在） |
| `pentest` | http `localhost:8080/mcp` | 已登记 · 停用 | `docker run -d -p 8080:8080 ramkansal/pentestmcp`（本机 docker 在跑，镜像未拉） |
| `kali-server` | stdio `kali-server-mcp --port 5000` | 已登记 · 停用 | Kali 环境 |
| `metasploit-mcp` | stdio `metasploitmcp --transport stdio` | 已登记 · 停用 | Metasploit |
| `pentestswarm` | stdio `pentestswarm mcp serve` | 已登记 · 停用 | Go |

`xquik`（remote `https://xquik.com/mcp`）已按需移除：端点需 OAuth 且为收费服务，未登记。
唯一受影响的是 `threat-intelligence` 里「用 Xquik 搜 X/Twitter」那条路径，会回退到本机 `web_search` / `source_check`。

启用方式：`/mcp enable <server>` 后 `/reload`。

## 顺带装好的命令行工具（brew）

`radare2`（r2 / rabin2）、`apktool`、`nmap`、`ghidra`（`ghidraRun`）
本机原有：`frida`、`jadx`、`java`、`docker`、`node/npx`、`python3/pipx/uv`。

## 精简开关（已生效）

87 个技能的 name+description 会常驻系统提示（约 1 万 token）。因此默认把 CTF 赛道技能移出扫描范围：

```bash
cd ~/.pi/agent/skills/reverse-skill
./toggle-ctf.sh status   # 扫描范围内 0 | .disabled/ 41
./toggle-ctf.sh on       # 打比赛前打开 41 个赛道技能
./toggle-ctf.sh off      # 平时停用，省约 5k 常驻 token
```

原理：Pi 的扫描器跳过以 `.` 开头的目录，所以 `.disabled/` 里的 SKILL.md 不进名录；
文件仍在仓库内，`ctf-sandbox-orchestrator` 可按需 `read ../../.disabled/<track>/SKILL.md` 取全文。
改完执行 `/reload` 生效。

## 验证方式

```bash
cd ~/.pi/agent/skills/reverse-skill/skills && bash scripts/master-route.sh "分析这个 APK"   # macOS 可用
/skill:reverse-skill-router                                                                  # 强制路由
/skill:ida-reverse                                                                           # 直接点名
```
