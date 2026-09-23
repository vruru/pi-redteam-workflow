/**
 * dsh-scanner-tools (Pi extension port) — 本机扫描器封装为模型工具
 * 源（只读）：~/.pi/agent/redteam-model/plugins/dsh-scanner-tools/{README.md,lib/index.js,lib/registry.js}
 *
 * 纪律内置（与原实现一致）：
 *   1) 速率纪律参数化：保守默认（nuclei -rl 15 / httpx -rl 25 / ffuf -rate 50 / nmap --max-rate 1000 /
 *      masscan --rate 1000 / whatweb -a 1 / hydra -t 4 / dirsearch·netexec·cme -t 10 / sqlmap level·risk·threads 1），
 *      显式提速进证据留痕（「默认 X → Y，留痕」）；保守上限 max 直接拒绝超限值。
 *   2) 声明式注册表：THIRTEEN 个 def（nmap/masscan/subfinder/gau/whatweb/wafw00f/dirsearch/sqlmap/
 *      nikto/hydra/impacket/netexec/crackmapexec）+ 三个手写工具（nuclei_scan/httpx_probe/ffuf_fuzz）= 16 个模型可见工具，
 *      工具名沿用原实现（playbook 正文无需改写）。新增工具 = 在 TOOL_DEFS 加一条数据。
 *   3) 产物落证据：JSON/JSONL 写 <workspace>/artifacts/scans/；注册表工具全文写
 *      <workspace>/artifacts/tool-output/（返回体是封顶预览 + 全文路径）；均回 <workspace>/evidence-index.md 一行；
 *      nuclei 命中回 scan-reconcile.md 待处置行（命中 ≠ 漏洞）。
 *   4) 防盲打：主动扫描（guard.active）要求目标已登记 assets.md / cloud-assets.md；轻探测
 *      （httpx/whatweb/wafw00f + 被动枚举 subfinder/gau）允许未登记但提示回填。
 *      另加本机台账 ~/.pi/redteam/dsh-scanner-tools/ledger.jsonl：**每次调用（含被拒绝的）都登记**，
 *      同 tool+target 重复扫描在返回体里给出「第 N 次（首次 ts / 最近 ts）」——重复可查。
 *   5) 输出治理：预览封顶（头 3600 + 尾 2000，中间省略量标注）+ 全文永落盘；每工具连续失败 3 次
 *      熔断 60s（防死磕，提示改走阶梯下级通道）；机器压力闸门（load/内存）防把本机打死。
 *   6) 检测制：二进制缺失**绝不自动安装**（本文件无 brew/pip 调用），只指路。
 *
 * 六节点工具调用阶梯在 Pi 里的落点（每节点的实现位置）：
 *   N1 本机工具      → 工具本体执行（runGoverned / runScanCore 命中 hasBinAsync 即真跑）。
 *   N2 MCP 通道      → 【返回值指路】缺装时 mcpGuidance() 列出 ~/.pi/agent/mcp.json 中已启用的 MCP
 *                       服务名 + `mcp({search:"…"}/{mcp enable})` 的具体动作；不在本件里调 MCP。
 *   N3 已装替代      → 【真实探测 + 返回值指路】def.altBins 逐个 which，命中就点名「已检测到 X」并给出
 *                       本插件对应工具名（def.altTool）或裸命令；不做自动切换（切换由模型/用户决定）。
 *   N4 MCP 备选      → 【返回值指路】同 N2 文案的第二条（/mcp enable <server> 后重试）。
 *   N5 询问安装      → 【ctx.hasUI 时 ctx.ui.confirm】；批准也**不自动装**：回 installCmd 让用户在会话外执行，
 *                       并把「已询问/用户选择」写进台账（stage=ask_install）。无 UI（print/json）跳过询问，
 *                       直接在返回值里给安装命令。
 *   N6 脚本兜底      → 【返回值指路】def.script 给可复制的 python3 / shell 片段（curl crt.sh、CDX API、
 *                       /dev/tcp 端口探测等），并提示把「脚本代替 X」记进 tool-plane 台账。
 *
 * 与原实现的差异（详见移植报告）：
 *   - workspace 参数由必填改为可选（缺省取 ctx.cwd）；其余参数语义与返回文本结构对齐原实现。
 *   - 缺装/防盲打/熔断/超时等「拒绝」分支返回**正常文本**而不是 throw：阶梯文案必须进模型上下文
 *     （Pi 里 throw = isError，且约定 #2 要求返回文本结构对齐）。真正的内部异常才 throw。
 *   - 新增 def.altBins/altTool/install/script 四个数据字段与 ~/.pi/redteam 台账（原实现只有工作区 evidence-index.md）。
 *   - 原 cordis 的 ctx.tools.register/defineTool → pi.registerTool/defineTool；spawnSync 阻塞问题在 Pi 里同样
 *     用异步 spawn 规避；跨轮限速不在本件（属 dsh-sec-enforce 移植件）。
 */

import type { ExtensionAPI, ExtensionContext, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { Type, type TSchema } from "typebox";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

export const RATE_DEFAULTS = { nuclei: 15, httpx: 25, ffuf: 50 } as const;
const BIN_HINT =
	"三级兜底：本机未装该工具——先查已连接 MCP（如 kali MCP），仍无则按 pentest-playbook 安装请求流程征得用户批准后安装；本工具绝不自动安装。";
const NO_SHELL_META = /[;&|`$><\n]/;

const STATE_DIR = path.join(os.homedir(), ".pi", "redteam", "dsh-scanner-tools");
const LEDGER_FILE = path.join(STATE_DIR, "ledger.jsonl");

type ParamSpec = {
	type: "string" | "integer" | "boolean";
	required?: boolean;
	description?: string;
	enum?: string[];
};

type ToolDef = {
	id: string;
	bin: string;
	bins?: string[];
	name: string;
	kind: string;
	positional: string | null;
	prefixParam?: string;
	moduleParam?: string;
	summary: string;
	hint: string;
	params: Record<string, ParamSpec>;
	tiers: string[];
	/** N3 已装替代：候选二进制（探测后指路，不自动切换） */
	altBins?: string[];
	/** N3 指路到本插件已封装的替代工具名（优先于裸命令） */
	altTool?: string;
	/** N5 安装命令（只呈现，绝不由本件执行） */
	install: string;
	/** N6 脚本兜底：可复制片段 */
	script: string;
	args: {
		flags?: Record<string, { flag: string; type?: string; required?: boolean; desc?: string }>;
		combined?: Record<string, { flag: string; type?: string; def?: number; max?: number; audited?: boolean }>;
		switches?: Record<string, string>;
	};
	defaults: string[];
	limits: { timeoutMs: number; previewChars: number };
	guard: { active: boolean; targetParam?: string };
};

//#region 声明式注册表（十三工具）：def 即工具面 + 命令模板 + 保守默认 + 超时 + 产物落点

export const TOOL_DEFS: Record<string, ToolDef> = {
	nmap: {
		id: "nmap", bin: "nmap", name: "nmap_portscan", kind: "portscan", positional: "target",
		summary: "Port/service scan (local nmap, conservative: -sT connect scan no-root + -sV, --max-rate 1000 by default; explicit rate override is audit-logged). Requires the target registered in the asset baseline (防盲打).",
		hint: "端口/服务扫描：-sT 连接扫描（免 root）+ -sV 服务版本，默认 --max-rate 1000 保守限速",
		params: {
			target: { type: "string", required: true, description: "Target host/IP (must be registered in the asset baseline)" },
			ports: { type: "string", description: "Port range, e.g. 80,443,1000-2000 (default top 1000)" },
			scripts: { type: "string", description: "NSE script set (caution: heavy; off by default)" },
			rate: { type: "integer", description: "max-rate override (default 1000 conservative; override is audit-logged)" }
		},
		tiers: [
			"本机 nmap（本工具）",
			"MCP 通道：已连接 MCP 内的 nmap/端口扫描类工具（如 kali MCP）",
			"已装可代替工具：masscan 顶端口扫 / rustscan（+ 手动服务指纹）",
			"MCP 备选通道：其他已连接 MCP 内等价探测工具",
			"询问用户是否安装 nmap（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：bash /dev/tcp 端口探测、nc 循环等实现同等探测（登记 tool-plane「脚本代替 nmap」）"
		],
		altBins: ["masscan", "rustscan"], altTool: "masscan_portscan",
		install: "brew install nmap",
		script: "# N6 脚本兜底（bash /dev/tcp 端口探测）\nfor p in 21 22 23 25 80 443 445 3389 8080; do (echo > /dev/tcp/TARGET/$p) 2>/dev/null && echo \"$p open\"; done",
		args: {
			flags: { ports: { flag: "-p", type: "string" }, scripts: { flag: "--script", type: "string" } },
			combined: { rate: { flag: "--max-rate", type: "number", def: 1000, max: 10000, audited: true } },
			switches: {}
		},
		defaults: ["-Pn", "-sT", "-sV"],
		limits: { timeoutMs: 300_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	},
	masscan: {
		id: "masscan", bin: "masscan", name: "masscan_portscan", kind: "portscan", positional: "target",
		summary: "High-speed port scan (local masscan; conservative --rate 1000 by default, hard-capped; requires raw-socket privileges — falls back to nmap -sT without them). Requires the target registered in the asset baseline (防盲打).",
		hint: "高速端口扫（全网段快筛用）：默认 --rate 1000 保守；需 raw socket 权限（sudo），无权限直接降级 nmap -sT",
		params: {
			target: { type: "string", required: true, description: "Target IP/CIDR, e.g. 10.0.0.0/24 (must be registered)" },
			ports: { type: "string", required: true, description: "Ports, e.g. 80,443,8080 or 1-65535" },
			rate: { type: "integer", description: "packets/sec override (default 1000 conservative, hard cap 5000; override is audit-logged)" }
		},
		tiers: [
			"本机 masscan（本工具，需 sudo/raw socket）",
			"MCP 通道：已连接 MCP 内的端口扫描类工具（如 kali MCP nmap/masscan）",
			"已装可代替工具：nmap -sT（免 root，速度慢但同效）/ rustscan",
			"MCP 备选通道：其他已连接 MCP 内等价探测工具",
			"询问用户是否安装 masscan（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：bash /dev/tcp 并行探测脚本（登记 tool-plane「脚本代替 masscan」）"
		],
		altBins: ["nmap", "rustscan"], altTool: "nmap_portscan",
		install: "brew install masscan",
		script: "# N6 脚本兜底（bash 并行 /dev/tcp 快筛，替换 PORTS）\nfor p in $(seq 1 1024); do (echo > /dev/tcp/TARGET/$p) 2>/dev/null && echo \"$p open\" & done; wait",
		args: {
			flags: { ports: { flag: "-p", type: "string", required: true } },
			combined: { rate: { flag: "--rate", type: "number", def: 1000, max: 5000, audited: true } },
			switches: {}
		},
		defaults: [],
		limits: { timeoutMs: 600_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	},
	subfinder: {
		id: "subfinder", bin: "subfinder", name: "subfinder_enum", kind: "subdomain", positional: null,
		summary: "Passive subdomain enumeration (local subfinder — passive sources only, does not touch the target; no asset registration required). Backfill the asset baseline with results.",
		hint: "被动子域枚举（多被动源聚合，不触达目标）",
		params: { domain: { type: "string", required: true, description: "Base domain, e.g. example.com" } },
		tiers: [
			"本机 subfinder（本工具）",
			"MCP 通道：已连接 MCP 内的子域枚举类工具",
			"已装可代替工具：amass enum -passive / assetfinder / dig NS+AXFR 探查",
			"MCP 备选通道：其他已连接 MCP 内等价枚举工具",
			"询问用户是否安装 subfinder（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：证书透明日志查询（crt.sh API curl 脚本）等被动枚举（登记 tool-plane「脚本代替 subfinder」）"
		],
		altBins: ["amass", "assetfinder", "findomain"],
		install: "brew install subfinder",
		script: "# N6 脚本兜底（证书透明日志被动枚举）\ncurl -s \"https://crt.sh/?q=%25example.com&output=json\" | python3 -c 'import sys,json;[print(x) for x in sorted({v for r in json.load(sys.stdin) for v in r[\"name_value\"].splitlines()})]' | grep -v ' \\*'",
		args: { flags: { domain: { flag: "-d", type: "string", required: true } }, combined: {}, switches: {} },
		defaults: ["-silent", "-timeout", "60"],
		limits: { timeoutMs: 300_000, previewChars: 6000 },
		guard: { active: false }
	},
	gau: {
		id: "gau", bin: "gau", name: "gau_urls", kind: "passive-urls", positional: "domain",
		summary: "Passive URL/history collection (local gau — fetches known URLs from public archives; never touches the target). Ideal for the passive-recon stage and JS/API surface building.",
		hint: "被动 URL 历史收集（wayback/otx/commoncrawl 公开档案；入口面盘点与 JS 专线的弹药库）",
		params: {
			domain: { type: "string", required: true, description: "Domain, e.g. example.com" },
			providers: { type: "string", description: "Archive providers, e.g. wayback,otx,commoncrawl" },
			threads: { type: "integer", description: "fetch threads (default 5 conservative, cap 20; override is audit-logged)" }
		},
		tiers: [
			"本机 gau（本工具）",
			"MCP 通道：已连接 MCP 内的 URL 历史类工具",
			"已装可代替工具：waybackurls / hakrawler 被动档",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 gau（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：web.archive.org CDX API curl 脚本（登记 tool-plane「脚本代替 gau」）"
		],
		altBins: ["waybackurls", "hakrawler", "uro"],
		install: "go install github.com/lc/gau/v2/cmd/gau@latest",
		script: "# N6 脚本兜底（Wayback CDX 历史 URL）\ncurl -s \"http://web.archive.org/cdx/search/cdx?url=example.com*&output=text&fl=original&collapse=urlkey&limit=5000\"",
		args: {
			flags: { providers: { flag: "--providers", type: "string" } },
			combined: { threads: { flag: "--threads", type: "number", def: 5, max: 20, audited: true } },
			switches: {}
		},
		defaults: [],
		limits: { timeoutMs: 300_000, previewChars: 6000 },
		guard: { active: false }
	},
	whatweb: {
		id: "whatweb", bin: "whatweb", name: "whatweb_fingerprint", kind: "fingerprint", positional: "target",
		summary: "Light web fingerprint (local whatweb, -a 1 conservative by default; aggression capped at 3). Unregistered targets allowed (like httpx_probe); backfill the asset baseline.",
		hint: "轻量 Web 指纹（默认 -a 1 保守；回填资产基线）",
		params: {
			target: { type: "string", required: true, description: "Target URL/host" },
			aggression: { type: "integer", description: "1-3 (default 1 conservative; 3 = more active, may trigger alerts; override is audit-logged)" }
		},
		tiers: [
			"本机 whatweb（本工具）",
			"MCP 通道：已连接 MCP 内的指纹识别类工具",
			"已装可代替工具：httpx_probe -tech-detect（本插件已封装）/ wappalyzer CLI",
			"MCP 备选通道：其他已连接 MCP 内等价指纹工具",
			"询问用户是否安装 whatweb（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：curl 抓响应头/指纹特征 + 手工比对（登记 tool-plane「脚本代替 whatweb」）"
		],
		altBins: ["httpx"], altTool: "httpx_probe",
		install: "brew install whatweb",
		script: "# N6 脚本兜底（响应头/标题指纹采集）\ncurl -skI \"$TARGET\" | tr -d '\\r'; curl -sk \"$TARGET\" | head -c 2000 | grep -Eio '<(title|meta[^>]*(generator|server))[^>]*>'",
		args: {
			flags: {},
			combined: { aggression: { flag: "-a", type: "number", def: 1, max: 3, audited: true } },
			switches: {}
		},
		defaults: ["--no-errors", "--color=never"],
		limits: { timeoutMs: 180_000, previewChars: 6000 },
		guard: { active: false }
	},
	wafw00f: {
		id: "wafw00f", bin: "wafw00f", name: "wafw00f_detect", kind: "waf", positional: "target",
		summary: "WAF detection (local wafw00f, -a probes all known WAF signatures). Feeds the protection-profile stage BEFORE any active testing — rate budget and technique selection depend on it. Backfill the protection profile.",
		hint: "WAF 识别：防护画像阶段先判 WAF（速率预算与打法据此定——playbook 防护画像前置 doctrine 的工具落地）",
		params: { target: { type: "string", required: true, description: "Target URL/host" } },
		tiers: [
			"本机 wafw00f（本工具）",
			"MCP 通道：已连接 MCP 内的 WAF 识别类工具",
			"已装可代替工具：whatweb -a 3（部分识别）/ httpx 安全头侧判 + 手工 payload 探测（最小化）",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 wafw00f（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：发送典型触发 payload 观察拦截页特征（最小次数，登记 tool-plane「脚本代替 wafw00f」）"
		],
		altBins: ["whatweb", "httpx"], altTool: "whatweb_fingerprint",
		install: "pipx install wafw00f",
		script: "# N6 脚本兜底（最小次数触发 payload 看拦截特征）\ncurl -sk -o /dev/null -w '%{http_code}\\n' \"$TARGET/?=%27%22%3Cscript%3Ealert(1)%3C%2Fscript%3E\"; curl -skI \"$TARGET\" | grep -Ei 'set-cookie:.*(acw_|cf_|wafer)|^(server|x-vpn|bigip)'",
		args: { flags: {}, combined: {}, switches: {} },
		defaults: ["-a"],
		limits: { timeoutMs: 120_000, previewChars: 6000 },
		guard: { active: false }
	},
	dirsearch: {
		id: "dirsearch", bin: "dirsearch", name: "dirsearch_dirs", kind: "content-discovery", positional: null,
		summary: "Dir/path discovery (local dirsearch; conservative -t 10 threads by default). Requires the target registered in the asset baseline (防盲打). Rate budget follows the WAF profile.",
		hint: "目录/路径发现（与 ffuf 同域：dirsearch=自带字典上手快，ffuf=可配性更强；速率在 WAF 画像之后定）",
		params: {
			url: { type: "string", required: true, description: "Target base URL (must be registered)" },
			extensions: { type: "string", description: "e.g. php,html,js" },
			wordlist: { type: "string", description: "Custom wordlist path (absolute or SecLists)" },
			threads: { type: "integer", description: "threads (default 10 conservative, cap 30; override is audit-logged)" }
		},
		tiers: [
			"本机 dirsearch（本工具）",
			"MCP 通道：已连接 MCP 内的目录枚举类工具",
			"已装可代替工具：ffuf_fuzz（本插件已封装，-w 自选字典）/ gobuster / wfuzz",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 dirsearch（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：python 字典循环 requests 探测（登记 tool-plane「脚本代替 dirsearch」）"
		],
		altBins: ["ffuf", "gobuster", "wfuzz"], altTool: "ffuf_fuzz",
		install: "pipx install dirsearch",
		script: "# N6 脚本兜底（python3 标准库字典循环，限速 10 rps）\npython3 - \"$TARGET\" \"$WORDLIST\" <<'PY'\nimport sys,time,urllib.request\nbase,wl=sys.argv[1].rstrip('/'),sys.argv[2]\nfor w in open(wl):\n    w=w.strip()\n    if not w: continue\n    try:\n        r=urllib.request.urlopen(base+'/'+w,timeout=8)\n        print(r.status,base+'/'+w)\n    except Exception as e:\n        c=getattr(e,'code',None)\n        if c in (401,403,404): pass\n        else: print('ERR',w,e)\n    time.sleep(0.1)\nPY",
		args: {
			flags: {
				url: { flag: "-u", type: "string", required: true },
				extensions: { flag: "-e", type: "string" },
				wordlist: { flag: "-w", type: "string" }
			},
			combined: { threads: { flag: "-t", type: "number", def: 10, max: 30, audited: true } },
			switches: { recursive: "-r" }
		},
		defaults: [],
		limits: { timeoutMs: 600_000, previewChars: 6000 },
		guard: { active: true, targetParam: "url" }
	},
	sqlmap: {
		id: "sqlmap", bin: "sqlmap", name: "sqlmap_inject", kind: "sqli", positional: null,
		summary: "SQL injection verification (local sqlmap, always --batch non-interactive; conservative --level 1 --risk 1 --threads 1 by default). Data-minimization discipline: prefer --banner/--dbs/--count escalation; --dump or OS-level actions (--os-shell etc.) only on explicit user request, via the audited extra escape hatch. Requires the target registered in the asset baseline.",
		hint: "注入验证：--batch 非交互、level/risk/threads 默认 1 最小强度；**数据最小化分级**——banner→dbs→count 逐级证明，--dump/--os-shell 仅用户明示后经 extra 留痕执行（playbook 敏感数据最小化纪律）",
		params: {
			url: { type: "string", required: true, description: "Target URL with the injectable parameter, e.g. http://host/page?id=1 (must be registered)" },
			data: { type: "string", description: "POST body (if any)" },
			cookie: { type: "string", description: "Session cookie for authenticated testing" },
			level: { type: "integer", description: "1-3 (default 1; higher = more injection points tested; override is audit-logged)" },
			risk: { type: "integer", description: "1-3 (default 1; 2-3 include OR/time-based which are heavier; override is audit-logged)" },
			threads: { type: "integer", description: "concurrency (default 1 conservative, cap 5; override is audit-logged)" },
			dbs: { type: "boolean", description: "--dbs enumerate databases (escalation step)" },
			tables: { type: "boolean", description: "--tables enumerate tables (with --dbs or -D)" },
			count: { type: "boolean", description: "--counts row counts (minimal-impact proof of depth)" },
			banner: { type: "boolean", description: "--banner DBMS banner (minimal proof)" },
			forms: { type: "boolean", description: "--forms parse & test forms on the page" }
		},
		tiers: [
			"本机 sqlmap（本工具）",
			"MCP 通道：已连接 MCP 内的注入验证类工具",
			"已装可代替工具：nuclei sqli 模板（本插件 nuclei_scan -severity 可筛）+ 手工 payload 验证（sqlmap 定位后手工最小化复现）",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 sqlmap（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：python requests 手工注入验证脚本（时间盲注延迟判据等，登记 tool-plane「脚本代替 sqlmap」）"
		],
		altBins: ["nuclei"], altTool: "nuclei_scan",
		install: "pipx install sqlmap",
		script: "# N6 脚本兜底（时间盲注最小判据：对比基线延迟）\npython3 - \"$URL\" <<'PY'\nimport sys,time,urllib.request\nu=sys.argv[1]\ndef t(x):\n    s=time.time()\n    try: urllib.request.urlopen(x,timeout=20).read()\n    except Exception: pass\n    return time.time()-s\nbase=t(u); print('baseline %.2fs'%base)\nfor pay in (\"' AND SLEEP(5)-- -\",\"' WAITFOR DELAY '0:0:5'-- -\"): \n    d=t(u+pay); print('%.2fs %s'%(d,pay),'-> 延迟显著' if d>base+3 else '')\nPY",
		args: {
			flags: {
				url: { flag: "-u", type: "string", required: true },
				data: { flag: "--data", type: "string" },
				cookie: { flag: "--cookie", type: "string" }
			},
			combined: {
				level: { flag: "--level", type: "number", def: 1, max: 3, audited: true },
				risk: { flag: "--risk", type: "number", def: 1, max: 3, audited: true },
				threads: { flag: "--threads", type: "number", def: 1, max: 5, audited: true }
			},
			switches: { dbs: "--dbs", tables: "--tables", count: "--count", banner: "--banner", forms: "--forms" }
		},
		defaults: ["--batch"],
		limits: { timeoutMs: 900_000, previewChars: 6000 },
		guard: { active: true, targetParam: "url" }
	},
	nikto: {
		id: "nikto", bin: "nikto", name: "nikto_scan", kind: "webserver-scan", positional: null,
		summary: "Web-server config/misconfig scan (local nikto, non-interactive; complementary to nuclei: nikto = server config & known issues, nuclei = template vulns). Noisy — expect IDS visibility; rate/discipline note applies. Requires the target registered in the asset baseline.",
		hint: "Web 服务器配置类扫描（与 nuclei 分工：nikto=服务器配置/已知问题，nuclei=模板漏洞；噪声大，授权与速率纪律适用）",
		params: {
			host: { type: "string", required: true, description: "Target URL/host (must be registered)" },
			tuning: { type: "string", description: "Scan tuning, e.g. 1,2,3 (info/file/default) — narrower = less noisy" },
			ssl: { type: "boolean", description: "force SSL" }
		},
		tiers: [
			"本机 nikto（本工具）",
			"MCP 通道：已连接 MCP 内的 Web 扫描类工具",
			"已装可代替工具：nuclei_scan（本插件已封装——模板覆盖大量同域检查，噪声更低）",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 nikto（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：curl 探测已知配置路径/响应头核查脚本（登记 tool-plane「脚本代替 nikto」）"
		],
		altBins: ["nuclei"], altTool: "nuclei_scan",
		install: "brew install nikto",
		script: "# N6 脚本兜底（已知配置路径核查）\nfor p in .git/config webmail admin/ server-status phpinfo.php backup.sql; do printf '%-16s %s\\n' \"$p\" \"$(curl -sk -o /dev/null -w '%{http_code}' \"$TARGET/$p\")\"; done",
		args: {
			flags: { host: { flag: "-h", type: "string", required: true }, tuning: { flag: "-Tuning", type: "string" } },
			combined: {},
			switches: { ssl: "-ssl" }
		},
		defaults: ["-nointeractive"],
		limits: { timeoutMs: 900_000, previewChars: 6000 },
		guard: { active: true, targetParam: "host" }
	},
	hydra: {
		id: "hydra", bin: "hydra", name: "hydra_brute", kind: "brute", positional: "target",
		summary: "Login brute-force (local hydra; conservative -t 4 threads by default, stop-on-first-valid). Requires the target registered in the asset baseline; hard-coded-credential-first doctrine applies — brute only after cred reuse/dictionary candidates, with rate discipline and lockout awareness.",
		hint: "登录爆破（默认 -t 4 保守+首中即停）：**硬编码凭据优先**——先走 JS/配置中的已获凭据与字典候选，爆破是后位手段；锁定策略与速率纪律适用",
		params: {
			target: { type: "string", required: true, description: "Target host + service, e.g. '10.0.0.5 ssh' / '10.0.0.5 rdp' / 'http-post-form 填模块串'（组合位置参数）" },
			login: { type: "string", description: "single username (-l)" },
			loginFile: { type: "string", description: "username list file (-L)" },
			passFile: { type: "string", description: "password list file (-P, absolute path)" },
			port: { type: "string", description: "port if non-default (-s)" },
			threads: { type: "integer", description: "parallel tasks (default 4 conservative, cap 16; override is audit-logged)" }
		},
		tiers: [
			"本机 hydra（本工具）",
			"MCP 通道：已连接 MCP 内的爆破类工具（如 kali MCP）",
			"已装可代替工具：medusa / ncrack",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 hydra（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：python 小字典循环 + 锁定感知（失败 N 次即停，登记 tool-plane「脚本代替 hydra」）"
		],
		altBins: ["medusa", "ncrack"],
		install: "brew install hydra",
		script: "# N6 脚本兜底（ssh 线小字典 + 失败即停：sshpass 有则用，无则改 python paramiko）\nfor pw in $(cat \"$PASSWORDS\"); do sshpass -p \"$pw\" ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 user@TARGET true 2>/dev/null && { echo \"HIT $pw\"; break; }; done",
		args: {
			flags: {
				login: { flag: "-l", type: "string" },
				loginFile: { flag: "-L", type: "string" },
				passFile: { flag: "-P", type: "string" },
				port: { flag: "-s", type: "string" }
			},
			combined: { threads: { flag: "-t", type: "number", def: 4, max: 16, audited: true } },
			switches: {}
		},
		defaults: ["-f"],
		limits: { timeoutMs: 900_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	},
	impacket: {
		id: "impacket", bin: "impacket", bins: ["impacket-{module}", "{module}.py"], name: "impacket_suite", kind: "ad-exec", positional: "target", moduleParam: "module",
		summary: "Impacket AD toolkit (local; module selectable: secretsdump / psexec / wmiexec / smbexec / atexec / GetUserSPNs / GetNPUsers; binary auto-resolves between 'impacket-<module>' and '<module>.py' install layouts). Credential-first doctrine: use obtained creds/hashes, DCSync single-request over bulk logins; lateral-execution modules leave traces — op-trace ledger applies. Requires the target registered in the asset baseline.",
		hint: "AD 重兵器套件：secretsdump 凭据直取（DCSync 单请求优于批量登录）、psexec/wmiexec/smbexec/atexec 横向执行（痕迹管理纪律适用）、GetUserSPNs/GetNPUsers Roasting 线起点；双安装名自动解析",
		params: {
			module: { type: "string", required: true, enum: ["secretsdump", "psexec", "wmiexec", "smbexec", "atexec", "GetUserSPNs", "GetNPUsers"], description: "Impacket module to run" },
			target: { type: "string", required: true, description: "Module target, e.g. 'DOMAIN/user@10.0.0.5'（secretsdump/exec 线）或 'DC.DOMAIN/user -dc-ip 由 dcIp 参数给'（Roasting 线）" },
			hashes: { type: "string", description: "NTLM hash auth ':NTLMHASH' or 'LM:NT'（pass-the-hash）" },
			dcIp: { type: "string", description: "domain controller IP (-dc-ip，Roasting/域线用)" }
		},
		tiers: [
			"本机 impacket（本工具——impacket-<module> / <module>.py 双名自动解析）",
			"MCP 通道：kali MCP（impacket 全家）",
			"已装可代替工具：netexec/crackmapexec（--sam 凭据线）；secretsdump→reg save 三件套离线解",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 impacket（pip 装于工作区 venv，征得批准后——本工具绝不自动安装）",
			"不批准则脚本编写：python impacket 库直接调用（venv 内）或手工协议（登记 tool-plane「脚本代替 impacket」）"
		],
		altBins: ["netexec", "nxc", "crackmapexec", "cme"], altTool: "netexec_scan",
		install: "pipx install impacket   # 或 python3 -m pip install impacket（工作区 venv 内，需用户批准）",
		script: "# N6 脚本兜底（venv 内直接调 impacket 库；或离线 reg save 三件套）\npython3 -c \"import sys;sys.path.insert(0,'venv/lib/site-packages');from impacket.secretsdump import RemoteOperations\" 2>/dev/null || echo 'impacket 库不可导入：走 netexec --sam 或 reg save HKLM\\SYSTEM SAM 离线解'",
		args: {
			flags: { hashes: { flag: "-hashes", type: "string" }, dcIp: { flag: "-dc-ip", type: "string" } },
			combined: {},
			switches: {}
		},
		defaults: [],
		limits: { timeoutMs: 900_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	},
	netexec: {
		id: "netexec", bin: "netexec", bins: ["netexec", "nxc"], name: "netexec_scan", kind: "ad-recon", positional: "target", prefixParam: "protocol",
		summary: "Network/AD protocol validation spray (local netexec, the maintained successor lineage; conservative -t 10 threads by default). Protocols: smb / winrm / ldap / ssh / mssql. Credential validation + situational enumeration (--sam/--shares/--users/--sessions/--pass-pol). Requires the target registered in the asset baseline; lockout awareness applies — spray with obtained cred candidates, not bulk.",
		hint: "AD 协议验证喷洒：凭据候选有效性批量验证 + 态势枚举（SAM/共享/会话/密码策略）；**锁定意识**——用已获凭据候选定向验证而非 bulk；与 crackmapexec 同语法互为替代",
		params: {
			protocol: { type: "string", required: true, enum: ["smb", "winrm", "ldap", "ssh", "mssql"], description: "Target protocol" },
			target: { type: "string", required: true, description: "Host or CIDR, e.g. 10.0.0.0/24（must be registered）" },
			user: { type: "string", description: "username (-u)" },
			pass: { type: "string", description: "password (-p)" },
			hashes: { type: "string", description: "NTLM hash auth (--hashes ':NTLMHASH')" },
			threads: { type: "integer", description: "threads (default 10 conservative, cap 50; override is audit-logged)" },
			sam: { type: "boolean", description: "--sam dump SAM hashes (admin required)" },
			shares: { type: "boolean", description: "--shares enumerate shares" },
			users: { type: "boolean", description: "--users enumerate domain users" },
			sessions: { type: "boolean", description: "--sessions active sessions" },
			passPol: { type: "boolean", description: "--pass-pol password policy（锁定阈值侦察——爆破前置）" }
		},
		tiers: [
			"本机 netexec / nxc（本工具）",
			"MCP 通道：kali MCP（netexec/重武器库）",
			"已装可代替工具：crackmapexec（原版同语法）/ evil-winrm（winrm 线）",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 netexec（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：python 定向凭据验证循环 + 锁定感知（登记 tool-plane「脚本代替 netexec」）"
		],
		altBins: ["crackmapexec", "cme", "evil-winrm"], altTool: "crackmapexec_scan",
		install: "pipx install netexec",
		script: "# N6 脚本兜底（smb 单凭据定向验证 + 锁定感知：连续 3 次失败即停）\nsmbclient -L //TARGET -U 'DOMAIN%user%pass' -N 2>&1 | head -20",
		args: {
			flags: { user: { flag: "-u", type: "string" }, pass: { flag: "-p", type: "string" }, hashes: { flag: "--hashes", type: "string" } },
			combined: { threads: { flag: "-t", type: "number", def: 10, max: 50, audited: true } },
			switches: { sam: "--sam", shares: "--shares", users: "--users", sessions: "--sessions", passPol: "--pass-pol" }
		},
		defaults: [],
		limits: { timeoutMs: 600_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	},
	crackmapexec: {
		id: "crackmapexec", bin: "crackmapexec", bins: ["crackmapexec", "cme"], name: "crackmapexec_scan", kind: "ad-recon", positional: "target", prefixParam: "protocol",
		summary: "Network/AD protocol validation spray (local CrackMapExec, the original tool; same CLI grammar as its successor netexec; conservative -t 10 threads by default). Protocols: smb / winrm / ldap / ssh / mssql; --sam/--shares/--users/--sessions/--pass-pol enumeration. Requires the target registered in the asset baseline; lockout awareness applies.",
		hint: "AD 协议验证喷洒（原版，与 netexec 同语法互为替代；原版已停更——优先 netexec，本件为已装环境兼容）",
		params: {
			protocol: { type: "string", required: true, enum: ["smb", "winrm", "ldap", "ssh", "mssql"], description: "Target protocol" },
			target: { type: "string", required: true, description: "Host or CIDR（must be registered）" },
			user: { type: "string", description: "username (-u)" },
			pass: { type: "string", description: "password (-p)" },
			hashes: { type: "string", description: "NTLM hash auth (--hashes ':NTLMHASH')" },
			threads: { type: "integer", description: "threads (default 10 conservative, cap 50; override is audit-logged)" },
			sam: { type: "boolean", description: "--sam dump SAM hashes (admin required)" },
			shares: { type: "boolean", description: "--shares enumerate shares" },
			users: { type: "boolean", description: "--users enumerate domain users" },
			sessions: { type: "boolean", description: "--sessions active sessions" },
			passPol: { type: "boolean", description: "--pass-pol password policy（锁定阈值侦察——爆破前置）" }
		},
		tiers: [
			"本机 crackmapexec / cme（本工具）",
			"MCP 通道：kali MCP（重武器库）",
			"已装可代替工具：netexec（维护中的同语法继任者，优先）",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 crackmapexec（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：python 定向凭据验证循环 + 锁定感知（登记 tool-plane「脚本代替 crackmapexec」）"
		],
		altBins: ["netexec", "nxc"], altTool: "netexec_scan",
		install: "pipx install crackmapexec",
		script: "# N6 脚本兜底（同 netexec 出口：smbclient 定向验证 + 锁定感知）\nsmbclient -L //TARGET -U 'DOMAIN%user%pass' -N 2>&1 | head -20",
		args: {
			flags: { user: { flag: "-u", type: "string" }, pass: { flag: "-p", type: "string" }, hashes: { flag: "--hashes", type: "string" } },
			combined: { threads: { flag: "-t", type: "number", def: 10, max: 50, audited: true } },
			switches: { sam: "--sam", shares: "--shares", users: "--users", sessions: "--sessions", passPol: "--pass-pol" }
		},
		defaults: [],
		limits: { timeoutMs: 600_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	}
};

/** 三个手写工具的阶梯/替代/安装/脚本元数据（原实现只有 BIN_HINT，无 def 结构——本件补齐六节点，
 *  让 nuclei/httpx/ffuf 与注册表工具走同一套指路文案）。 */
type CoreMeta = { id: string; bin: string; tiers: string[]; altBins: string[]; altTool?: string; install: string; script: string; previewChars: number; timeoutMs: number };

export const CORE_META: Record<"nuclei" | "httpx" | "ffuf", CoreMeta> = {
	nuclei: {
		id: "nuclei", bin: "nuclei", previewChars: 6000, timeoutMs: 900_000,
		tiers: [
			"本机 nuclei（本工具）",
			"MCP 通道：已连接 MCP 内的模板漏洞扫描类工具",
			"已装可代替工具：nikto_scan（服务器配置线，本插件已封装）/ sqlmap_inject（注入线）+ 手工 payload",
			"MCP 备选通道：其他已连接 MCP 内等价扫描工具",
			"询问用户是否安装 nuclei（brew install nuclei；模板库另需一次性 nuclei -update-templates——数据非工具，仍须批准）",
			"不批准则脚本编写：curl 打已知漏洞路径/参数 + 响应特征判定（登记 tool-plane「脚本代替 nuclei」）"
		],
		altBins: ["nikto", "sqlmap"], altTool: "nikto_scan",
		install: "brew install nuclei   # 首次使用再执行 nuclei -update-templates（下载模板库，需用户批准）",
		script: "# N6 脚本兜底（已知暴露面 curl 特征判定）\nfor p in .env .git/HEAD actuator/health druid/websql.html; do printf '%-22s %s\\n' \"$p\" \"$(curl -sk -o /dev/null -w '%{http_code}' -m 8 \"$TARGET/$p\")\"; done"
	},
	httpx: {
		id: "httpx", bin: "httpx", previewChars: 6000, timeoutMs: 300_000,
		tiers: [
			"本机 httpx（本工具）",
			"MCP 通道：已连接 MCP 内的存活/指纹类工具",
			"已装可代替工具：whatweb_fingerprint / nmap_portscan -sV（本插件已封装）/ curl -I 循环",
			"MCP 备选通道：其他已连接 MCP 内等价探测工具",
			"询问用户是否安装 httpx（projectdiscovery 工具族，征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：curl 批处理取状态码/标题/技术头（登记 tool-plane「脚本代替 httpx」）"
		],
		altBins: ["whatweb", "nmap", "curl"], altTool: "whatweb_fingerprint",
		install: "brew install httpx",
		script: "# N6 脚本兜底（curl 存活+标题+关键头）\nwhile read -r u; do printf '%s ' \"$(curl -sk -o /dev/null -w '%{http_code}' -m 8 \"$u\")\"; curl -sk -m 8 \"$u\" | grep -Eio '<title>[^<]*' | head -1; echo \" <- $u\"; done < urls.txt"
	},
	ffuf: {
		id: "ffuf", bin: "ffuf", previewChars: 6000, timeoutMs: 300_000,
		tiers: [
			"本机 ffuf（本工具）",
			"MCP 通道：已连接 MCP 内的目录/参数模糊测试类工具",
			"已装可代替工具：dirsearch_dirs（本插件已封装，自带字典）/ gobuster / wfuzz",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 ffuf（brew install ffuf；字典不代装——须显式 wordlist 参数）",
			"不批准则脚本编写：python3 标准库字典循环（限速+锁定感知，登记 tool-plane「脚本代替 ffuf」）"
		],
		altBins: ["dirsearch", "gobuster", "wfuzz"], altTool: "dirsearch_dirs",
		install: "brew install ffuf   # 字典需自备（SecLists 等），本工具不代装",
		script: "# N6 脚本兜底（python3 字典循环，-rate≈10）\npython3 - \"$URL\" \"$WORDLIST\" <<'PY'\nimport sys,time,urllib.request\nu,wl=sys.argv[1],sys.argv[2]\nfor w in open(wl):\n    w=w.strip()\n    if not w: continue\n    try:\n        r=urllib.request.urlopen(u.replace('FUZZ',w),timeout=8)\n        print(r.status,len(r.read()),u.replace('FUZZ',w))\n    except Exception as e:\n        print(getattr(e,'code','ERR'),u.replace('FUZZ',w))\n    time.sleep(0.1)\nPY"
	}
};

//#region 构参：defaults → combined（上限/留痕）→ flags（元字符拒绝）→ switches → positional → extra

/** 由 def + 参数构建 argv。返回 { argv, audit }——audit 为留痕行数组（保守默认时为空）。
 *  未知参数直接拒绝并列已知名；shell 元字符拒绝；combined 超保守上限拒绝。 */
export function buildArgs(def: ToolDef, params: Record<string, any> = {}): { argv: string[]; audit: string[] } {
	const argv: string[] = [...def.defaults];
	const audit: string[] = [];
	const known = new Set<string>([
		"workspace", "extra",
		...(def.positional ? [def.positional] : []),
		...(def.prefixParam ? [def.prefixParam] : []),
		...(def.moduleParam ? [def.moduleParam] : []),
		...Object.keys(def.args?.flags ?? {}),
		...Object.keys(def.args?.combined ?? {}),
		...Object.keys(def.args?.switches ?? {})
	]);
	for (const k of Object.keys(params)) {
		if (params[k] === undefined || params[k] === "") continue;
		if (!known.has(k)) throw new Error(`未知参数 ${k}（已知：${[...known].filter((x) => x !== "workspace" && x !== "extra").join("/")} / workspace / extra）`);
	}
	if (def.moduleParam) {
		const mv = params[def.moduleParam];
		if (mv === undefined || mv === "") throw new Error(`参数 ${def.moduleParam} 必填`);
		const allowed = def.params?.[def.moduleParam]?.enum;
		if (allowed && !allowed.includes(String(mv))) throw new Error(`未知 ${def.moduleParam}：${mv}（合法：${allowed.join("/")}）`);
	}
	for (const [k, spec] of Object.entries(def.args?.combined ?? {})) {
		let v: any = params[k];
		if (v === undefined || v === "") v = spec.def;
		if (v === undefined) continue;
		const n = Number(v);
		if (!Number.isFinite(n) || n < 0) throw new Error(`参数 ${k} 须为非负数值`);
		if (spec.max !== undefined && n > spec.max) throw new Error(`参数 ${k}=${n} 超保守上限 ${spec.max}`);
		argv.push(spec.flag, String(n));
		if (spec.audited && String(v) !== String(spec.def)) audit.push(`${spec.flag} ${v}（默认 ${spec.def}，显式覆盖留痕）`);
	}
	for (const [k, spec] of Object.entries(def.args?.flags ?? {})) {
		const v = params[k];
		if (v === undefined || v === "") {
			if (spec.required) throw new Error(`参数 ${k} 必填`);
			continue;
		}
		const s = String(v);
		if (NO_SHELL_META.test(s)) throw new Error(`参数 ${k} 含 shell 元字符，拒绝`);
		argv.push(spec.flag, s);
	}
	for (const [k, flag] of Object.entries(def.args?.switches ?? {})) {
		if (params[k] === true) argv.push(flag);
	}
	if (def.positional) {
		const t = params[def.positional];
		if (t === undefined || t === "") throw new Error(`参数 ${def.positional} 必填（扫描目标）`);
		if (NO_SHELL_META.test(String(t))) throw new Error("目标含 shell 元字符，拒绝");
		argv.push(String(t));
	}
	if (params.extra) {
		const s = String(params.extra);
		if (NO_SHELL_META.test(s)) throw new Error("extra 含 shell 元字符，拒绝");
		argv.push(...s.split(/\s+/).filter(Boolean));
		audit.push(`extra: ${s}（显式附加参数留痕）`);
	}
	if (def.prefixParam) {
		const pv = params[def.prefixParam];
		if (pv === undefined || pv === "") throw new Error(`参数 ${def.prefixParam} 必填`);
		argv.unshift(String(pv)); // 协议名打头（nxc smb <target> 语法）
	}
	return { argv, audit };
}

/** 六节点阶梯文案（工具描述与缺装提示共用）。 */
export function tiersLine(tiers: string[]): string {
	return "工具调用阶梯（缺失逐级降，每级有出口）：\n" + tiers.map((t, i) => `  ${i + 1}. ${t}`).join("\n");
}

//#region 异步执行器（不阻塞事件循环）+ 串行闸门 + 机器压力闸门

const KILL_GRACE_MS = 5_000;

function killTree(child: ReturnType<typeof spawn>) {
	if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return;
	if (process.platform === "win32") {
		try { spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore", windowsHide: true }); return; } catch { /* 退到 child.kill */ }
	}
	try { child.kill("SIGTERM"); } catch { /* 已退出 */ }
	setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* 已退出 */ } }, KILL_GRACE_MS).unref?.();
}

export type ProcResult = { status: number | null; stdout: string; stderr: string; error?: Error & { code?: string; killed?: boolean } };

/** 异步执行子进程：事件循环全程可调度；超时杀进程树；输出超 maxBuffer 截断并记账（不整体丢结果）。 */
export function runProcess(bin: string, args: string[], { timeoutMs = 300_000, maxBuffer = 32 * 1024 * 1024, inspectEveryMs = 60_000, signal }:
	{ timeoutMs?: number; maxBuffer?: number; inspectEveryMs?: number; signal?: AbortSignal } = {}): Promise<ProcResult> {
	return new Promise((resolve) => {
		let child: ReturnType<typeof spawn>;
		try {
			child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
		} catch (e: any) {
			resolve({ status: null, stdout: "", stderr: "", error: Object.assign(new Error(e?.message ?? "spawn failed"), { code: "SPAWN-FAILED" }) });
			return;
		}
		let stdout = "", stderr = "", dropped = 0, settled = false, timedOut = false, aborted = false;
		let timer: NodeJS.Timeout | null = null, killTimer: NodeJS.Timeout | null = null, watch: NodeJS.Timeout | null = null;
		let lastActivity = Date.now(), beats = 0;
		const finish = (r: ProcResult) => {
			if (settled) return;
			settled = true;
			if (timer) clearTimeout(timer);
			if (killTimer) clearTimeout(killTimer);
			if (watch) clearInterval(watch);
			if (signal) signal.removeEventListener("abort", onAbort);
			resolve(r);
		};
		const take = (chunk: Buffer, into: "out" | "err") => {
			const text = chunk.toString();
			lastActivity = Date.now();
			const room = maxBuffer - (into === "out" ? stdout.length : stderr.length);
			if (room <= 0) { dropped += text.length; return; }
			const kept = text.length > room ? text.slice(0, room) : text;
			dropped += text.length - kept.length;
			if (into === "out") stdout += kept; else stderr += kept;
		};
		function onAbort() { aborted = true; killTree(child); }
		child.stdout?.on("data", (c: Buffer) => take(c, "out"));
		child.stderr?.on("data", (c: Buffer) => take(c, "err"));
		child.on("error", (e: Error & { code?: string }) => finish({ status: null, stdout, stderr, error: e }));
		child.on("close", (status) => finish({
			status,
			stdout,
			stderr: (dropped > 0 ? `${stderr}\n[输出超限：maxBuffer ${maxBuffer} 字节，另丢弃 ${dropped} 字节——需全文时让工具自带 -o 落盘]` : stderr),
			error: timedOut
				? Object.assign(new Error(`执行超时 ${Math.round(timeoutMs / 1000)}s`), { code: "ETIMEDOUT", killed: true })
				: aborted ? Object.assign(new Error("已取消（abort）"), { code: "ABORTED" }) : undefined
		}));
		if (signal) { if (signal.aborted) onAbort(); else signal.addEventListener("abort", onAbort, { once: true }); }
		if (timeoutMs > 0) {
			timer = setTimeout(() => {
				timedOut = true;
				killTree(child);
				killTimer = setTimeout(() => finish({ status: null, stdout, stderr, error: Object.assign(new Error(`执行超时 ${Math.round(timeoutMs / 1000)}s（子进程未退，放弃等待）`), { code: "ETIMEDOUT", killed: true }) }), KILL_GRACE_MS + 3_000);
				killTimer.unref?.();
			}, timeoutMs);
		}
		if (inspectEveryMs > 0) {
			watch = setInterval(() => {
				if (settled) return;
				const idleMs = Date.now() - lastActivity;
				if (idleMs >= inspectEveryMs && beats < 5 && stderr.length < maxBuffer) {
					beats += 1;
					stderr += `\n[巡检 ${new Date().toISOString().slice(11, 19)}：子进程存活，已静默 ${Math.round(idleMs / 1000)}s（超时兜底 ${Math.round(timeoutMs / 1000)}s）]`;
				}
			}, inspectEveryMs);
			watch.unref?.();
		}
	});
}

/** which-style binary check（同步，毫秒量级）。 */
export function hasBin(bin: string): boolean {
	const probe = process.platform === "win32" ? spawnSync("where", [bin]) : spawnSync("/usr/bin/which", [bin]);
	return probe.status === 0;
}

export async function hasBinAsync(bin: string): Promise<boolean> {
	const probe = process.platform === "win32" ? "where" : "/usr/bin/which";
	const p = await runProcess(probe, [bin], { timeoutMs: 10_000, maxBuffer: 64 * 1024, inspectEveryMs: 0 });
	return p.status === 0;
}

/** 串行闸门：扫描类调用不并发叠加（速率纪律不因异步化松动）。 */
let scanChain: Promise<any> = Promise.resolve();
function serialized<T>(fn: () => Promise<T>): Promise<T> {
	const next = scanChain.then(fn, fn);
	scanChain = next.then(() => { }, () => { });
	return next;
}

export function machinePressure(osMod: typeof os = os): { level: "ok" | "high" | "critical"; detail: string } {
	const cores = osMod.cpus().length || 1;
	const load1 = osMod.loadavg()[0] ?? 0;
	const freeMb = osMod.freemem() / (1024 * 1024);
	if (freeMb < 512) return { level: "critical", detail: `空闲内存 ${Math.round(freeMb)}MB < 512MB` };
	if (load1 >= cores * 4) return { level: "critical", detail: `load1 ${load1.toFixed(1)} ≥ ${cores} 核 ×4` };
	if (load1 >= cores * 2) return { level: "high", detail: `load1 ${load1.toFixed(1)} ≥ ${cores} 核 ×2` };
	return { level: "ok", detail: "" };
}

export async function machineGate({ waitMs = 120_000, pollMs = 5_000, osMod = os }: { waitMs?: number; pollMs?: number; osMod?: typeof os } = {}) {
	for (let i = 0; ; i += 1) {
		const p = machinePressure(osMod);
		if (p.level === "ok") return { ok: true, note: i === 0 ? "" : `机器高载已等待 ${Math.round((i * pollMs) / 1000)}s 回落后放行` };
		if (p.level === "critical" || (i + 1) * pollMs >= waitMs) {
			return { ok: false, note: `机器压力未回落（${p.detail}${i > 0 ? `，已等待 ${Math.round((i * pollMs) / 1000)}s` : ""}）——防过载拒执行：稍后重试，或改走工具调用阶梯下级通道（MCP/替代/脚本），或在本机会话外错峰执行` };
		}
		await new Promise((r) => setTimeout(r, pollMs));
	}
}

//#endregion

//#region 防盲打登记 / 输出治理 / 熔断 / 本机台账

/** 目标须出现在资产基线（仅主动扫描）。基线双候选：cloud-assets.md（云）或 assets.md（渗透/攻防）。 */
export function checkRegistered(fsMod: typeof fs, workspace: string, target: string): { ok: boolean; hint: string; baseline: string } {
	const baselines = ["cloud-assets.md", "assets.md"];
	let text = "", used = "";
	for (const f of baselines) {
		try { text = fsMod.readFileSync(path.join(workspace, f), "utf8"); } catch { text = ""; }
		if (text) { used = f; break; }
	}
	if (!text) return { ok: false, hint: "工作区无 assets.md / cloud-assets.md 资产基线——先完成测绘阶段（pentest Gate P1 / cloud Gate C1）再主动扫描", baseline: "" };
	const host = String(target).replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
	return text.includes(host)
		? { ok: true, hint: "", baseline: used }
		: { ok: false, hint: `目标 ${host} 未登记在 ${used}——防盲打：先登记资产（测绘组回填基线文件）再主动扫描`, baseline: used };
}

function ensureDirs(workspace: string) {
	fs.mkdirSync(path.join(workspace, "artifacts", "scans"), { recursive: true });
}

const PREVIEW_HEAD = 3600, PREVIEW_TAIL = 2000;

/** 预览封顶（纯函数）：短输出原样；长输出头尾拼接 + 中间省略量标注。 */
export function governPreview(raw: string): { preview: string; truncated: boolean; bytes: number } {
	const s = String(raw ?? "");
	if (s.length <= PREVIEW_HEAD + PREVIEW_TAIL + 200) return { preview: s, truncated: false, bytes: s.length };
	const mid = s.length - PREVIEW_HEAD - PREVIEW_TAIL;
	return { preview: s.slice(0, PREVIEW_HEAD) + `\n…（中间省略 ${mid} 字符——全文已落盘，按需读取）…\n` + s.slice(-PREVIEW_TAIL), truncated: true, bytes: s.length };
}

/** 全文落盘（证据原件）：artifacts/tool-output/<tool>-<ts>.txt，返回工作区相对路径。 */
export function spillOutput(fsMod: typeof fs, workspace: string, tool: string, raw: string): string {
	const dir = path.join(workspace, "artifacts", "tool-output");
	fsMod.mkdirSync(dir, { recursive: true });
	const ts = new Date().toISOString().replace(/[-:T.]/g, "").slice(0, 14);
	const file = path.join(dir, `${tool}-${ts}.txt`);
	fsMod.writeFileSync(file, String(raw ?? ""));
	return path.relative(workspace, file);
}

const BREAKER_THRESHOLD = 3, BREAKER_COOLDOWN_MS = 60_000;
const breakerMap = new Map<string, { fails: number; until: number }>();

export function breakerCheck(tool: string, nowMs = Date.now()): number {
	const b = breakerMap.get(tool);
	return b && b.until > nowMs ? Math.ceil((b.until - nowMs) / 1000) : 0;
}

/** 熔断记账：成功清零；连续失败达 3 次进 60s 冷却（防死磕同一工具——提示走阶梯下级）。 */
export function breakerRecord(tool: string, ok: boolean, nowMs = Date.now()): void {
	const b = breakerMap.get(tool) ?? { fails: 0, until: 0 };
	if (ok) { b.fails = 0; b.until = 0; }
	else { b.fails += 1; if (b.fails >= BREAKER_THRESHOLD) { b.until = nowMs + BREAKER_COOLDOWN_MS; b.fails = 0; } }
	breakerMap.set(tool, b);
}

export type LedgerRecord = {
	ts: string; tool: string; target: string; cmd: string; workspace: string;
	stage: string; ok: boolean; exit: number | null; bytes: number; truncated: boolean;
	evidenceId: string; output: string; error: string; audit: string[]; repeatOfPrior: number; extra?: Record<string, unknown>;
};

/** 本机台账：每次调用（含被拒绝）都登记，供「同目标同工具重复扫」回查。 */
export function ledgerAppend(rec: LedgerRecord, dir = STATE_DIR, fsMod: typeof fs = fs): void {
	try {
		fsMod.mkdirSync(dir, { recursive: true });
		fsMod.appendFileSync(path.join(dir, "ledger.jsonl"), JSON.stringify(rec) + "\n");
	} catch { /* 台账写失败不阻断扫描结果返回 */ }
}

/** 同 tool+target 的历史调用统计（防盲打：重复扫描可查）。 */
export function ledgerPrior(tool: string, target: string, fsMod: typeof fs = fs, dir = STATE_DIR): { count: number; firstTs: string; lastTs: string } {
	let text = "";
	try { text = fsMod.readFileSync(path.join(dir, "ledger.jsonl"), "utf8"); } catch { return { count: 0, firstTs: "", lastTs: "" }; }
	let count = 0; let firstTs = "", lastTs = "";
	const host = String(target).replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
	for (const line of text.split("\n")) {
		if (!line.trim()) continue;
		let r: any; try { r = JSON.parse(line); } catch { continue; }
		const h = String(r.target ?? "").replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
		if (r.tool === tool && h === host) {
			count += 1;
			if (!firstTs) firstTs = r.ts;
			lastTs = r.ts;
		}
	}
	return { count, firstTs, lastTs };
}

function appendEvidence(workspace: string, evidenceId: string, cmd: string, file: string) {
	const p = path.join(workspace, "evidence-index.md");
	let head = "";
	try { head = fs.readFileSync(p, "utf8"); } catch {
		head = "# 证据索引\n\n| 编号 | 时间 | 证据 | 产生方式 | 交接/消费 |\n|---|---|---|---|---|\n";
	}
	fs.writeFileSync(p, head + `| ${evidenceId} | ${new Date().toISOString()} | ${file} | ${cmd} | 扫描产物 |\n`);
}

function appendReconcile(workspace: string, rows: { source: string; hit: string }[]): number {
	if (!rows || rows.length === 0) return 0;
	const p = path.join(workspace, "scan-reconcile.md");
	let head = "";
	try { head = fs.readFileSync(p, "utf8"); } catch {
		head = "# 扫描命中对账（scan-reconcile）\n\n| 来源 | 命中 | 终态 |\n|---|---|---|\n";
	}
	const lines = rows.map((r) => `| ${r.source} | ${r.hit} | 待处置（命中≠漏洞，须复核+对照三件套） |`).join("\n");
	fs.writeFileSync(p, head + lines + "\n");
	return rows.length;
}

function nextEvidenceId(workspace: string): string {
	let n = 0;
	try {
		const text = fs.readFileSync(path.join(workspace, "evidence-index.md"), "utf8");
		for (const m of text.matchAll(/\| E(\d+) \|/g)) n = Math.max(n, Number(m[1]));
	} catch { /* 尚无索引 */ }
	return `E${n + 1}`;
}

/** 已启用 MCP 服务清单（N2/N4 指路用；只读 ~/.pi/agent/mcp.json，不连线、不安装）。 */
export function enabledMcpServers(fsMod: typeof fs = fs): string[] {
	try {
		const j = JSON.parse(fsMod.readFileSync(path.join(os.homedir(), ".pi", "agent", "mcp.json"), "utf8"));
		const servers = j?.mcpServers ?? {};
		return Object.keys(servers).filter((k) => servers[k]?.disabled !== true);
	} catch { return []; }
}

//#endregion
//#region 缺装阶梯（N2/N3/N4/N5/N6 的落点）+ 注册表工具执行器

/** execute 传入的 Pi ctx 子集（测试可注入 {hasUI:false} 桩）。 */
export type ExecCtx = { hasUI?: boolean; ui?: ExtensionContext["ui"]; cwd?: string };

type LadderSubject = { id: string; bin: string; bins?: string[]; altBins?: string[]; altTool?: string; install: string; script: string; tiers: string[]; kind?: string; toolName?: string };

/** 缺装/不可用时的六节点阶梯指引（N3 真探测已装替代，N5 有 UI 则询问、批准也不自动装，N6 给可复制片段）。 */
export async function ladderOnMissing(sub: LadderSubject, ctxObj: ExecCtx | undefined, fsMod: typeof fs = fs): Promise<string> {
	const cands = sub.bins ?? [sub.bin];
	const foundAlt: string[] = [];
	for (const a of sub.altBins ?? []) if (await hasBinAsync(a)) foundAlt.push(a);
	const servers = enabledMcpServers(fsMod);
	const mcpLine = servers.length
		? `已启用 MCP：${servers.join(", ")}——用 mcp 工具 search 关键词（如 "${sub.kind ?? sub.id}"）找等价工具`
		: "当前无已启用 MCP（Pi 里执行 /mcp enable <server> 后重试）";
	const altLine = foundAlt.length
		? `已检测到 ${foundAlt.join(", ")} → 优先改用${sub.altTool ? ` 本插件工具 ${sub.altTool}` : ` 裸命令 ${foundAlt[0]}`}`
		: `未检测到已装替代（候选：${(sub.altBins ?? []).join("/") || "无"}）`;
	const lines = [
		`${cands.join(" / ")} 未检测到——本工具绝不自动安装。`,
		tiersLine(sub.tiers),
		`落点说明：N1 本机（未装）；N2 MCP：${mcpLine}；N3 已装替代：${altLine}；N4 MCP 备选：${mcpLine}；N5 安装：${sub.install}（请在会话外执行，本件不代跑 brew/pip）；N6 脚本兜底见下。`,
		`N6 脚本片段（可直接复制执行；结果请登记 tool-plane「脚本代替 ${sub.id}」）：`,
		sub.script
	];
	// N5：有 UI 就询问用户是否安装（批准≠安装：只把安装命令呈报给用户，绝不代跑）
	let asked = "无 UI（print/json 模式）跳过询问";
	if (ctxObj?.hasUI && ctxObj.ui) {
		try {
			const yes = await ctxObj.ui.confirm(`未检测到 ${sub.bin}：是否安装？`, `${sub.install}\n（本工具绝不自动安装——确认后仍需你在会话外执行；也可先走阶梯 N2/N3/N6）`);
			asked = yes ? "用户已同意安装（安装命令仍需在会话外执行，本件不代跑）" : "用户拒绝安装 → 改走阶梯 N2/N3/N6";
		} catch { asked = "询问失败（对话框不可用）"; }
	}
	lines.splice(3, 0, `N5 询问安装：${asked}`);
	try {
		ledgerAppend({
			ts: new Date().toISOString(), tool: sub.toolName ?? sub.id, target: "(missing-bin)", cmd: cands.join("/"), workspace: ctxObj?.cwd ?? "",
			stage: "ask_install", ok: false, exit: null, bytes: 0, truncated: false, evidenceId: "", output: "", error: asked, audit: []
		}, STATE_DIR, fsMod);
	} catch { /* 台账失败不影响返回 */ }
	return lines.join("\n");
}

export type GovResult = {
	ok: boolean; id: string; toolName: string; stage: string; error?: string;
	evidenceId?: string; persisted?: string; bytes?: number; truncated?: boolean; preview?: string;
	summaryText?: string; cmd?: string; exit?: number | null; tiers?: string; repeat?: { count: number; firstTs: string; lastTs: string };
};

/** 按注册表 def 执行一个工具：熔断 → 防盲打 → 缺装阶梯 → 构参 → 机器闸门 → 串行执行 →
 *  全文落盘 + 封顶预览 + 证据索引 + 台账（每次调用都登记）。 */
export async function runGoverned(o: { def: ToolDef; params: Record<string, any>; workspace?: string; ctx?: ExecCtx; signal?: AbortSignal; fsMod?: typeof fs }): Promise<GovResult> {
	const fsMod = o.fsMod ?? fs;
	const def = o.def;
	const ws = path.resolve(o.workspace || o.ctx?.cwd || process.cwd());
	const toolName = def.name;
	const targetForLedger = String(
		def.guard?.targetParam ? (o.params[def.guard.targetParam] ?? o.params.target ?? o.params.domain ?? o.params.url ?? o.params.host ?? "")
			: (o.params.target ?? o.params.domain ?? o.params.url ?? o.params.host ?? "")
	);

	const settle = (r: GovResult): GovResult => {
		const prior = ledgerPrior(toolName, targetForLedger, fsMod);
		r.repeat = prior;
		ledgerAppend({
			ts: new Date().toISOString(), tool: toolName, target: targetForLedger, cmd: r.cmd ?? "", workspace: ws,
			stage: r.stage, ok: r.ok, exit: r.exit ?? null, bytes: r.bytes ?? 0, truncated: !!r.truncated,
			evidenceId: r.evidenceId ?? "", output: r.persisted ?? "", error: r.error ?? "", audit: []
		}, STATE_DIR, fsMod);
		return r;
	};

	const cooldown = breakerCheck(def.id);
	if (cooldown > 0) return settle({
		ok: false, id: def.id, toolName, stage: "breaker",
		error: `熔断中：${def.id} 连续失败 3 次进入 60s 冷却（剩 ${cooldown}s）——改走工具调用阶梯下级通道（MCP/替代/脚本）或稍后重试`,
		tiers: tiersLine(def.tiers)
	});

	if (def.guard?.active) {
		const tp = def.guard.targetParam ?? "target";
		const reg = checkRegistered(fsMod, ws, String(o.params[tp] ?? o.params.target ?? o.params.domain ?? ""));
		if (!reg.ok) return settle({ ok: false, id: def.id, toolName, stage: "unregistered", error: reg.hint });
	}

	const cands = (def.bins ?? [def.bin]).map((c) => c.replace("{module}", String(o.params[def.moduleParam ?? ""] ?? def.bin)));
	let bin = "";
	for (const cand of cands) if (await hasBinAsync(cand)) { bin = cand; break; }
	if (!bin) {
		const guidance = await ladderOnMissing({ ...def, bins: cands, toolName }, o.ctx, fsMod);
		return settle({ ok: false, id: def.id, toolName, stage: "missing-bin", error: guidance, tiers: tiersLine(def.tiers) });
	}

	let built: { argv: string[]; audit: string[] };
	try { built = buildArgs(def, o.params); } catch (e: any) {
		return settle({ ok: false, id: def.id, toolName, stage: "args", error: `参数拒绝：${e.message}` });
	}
	const cmdStr = `${bin} ${built.argv.join(" ")}`;

	const gate = await machineGate();
	if (!gate.ok) return settle({ ok: false, id: def.id, toolName, stage: "machine", error: `机器过载拒绝执行：${gate.note}`, cmd: cmdStr, tiers: tiersLine(def.tiers) });

	const proc = await serialized(() => runProcess(bin, built.argv, { timeoutMs: def.limits.timeoutMs, maxBuffer: 32 * 1024 * 1024, signal: o.signal }));
	if (proc.error) {
		breakerRecord(def.id, false);
		return settle({
			ok: false, id: def.id, toolName, stage: "exec", cmd: cmdStr,
			error: `执行失败：${proc.error.message}${proc.error.code === "ETIMEDOUT" ? `（超时 ${def.limits.timeoutMs / 1000}s）` : ""}\n${tiersLine(def.tiers)}`,
			tiers: tiersLine(def.tiers)
		});
	}
	breakerRecord(def.id, proc.status === 0);

	const errText = proc.stderr && proc.stderr.trim() ? `\n[stderr]\n${proc.stderr}` : "";
	const raw = (proc.stdout ?? "") + errText;
	const gov = governPreview(raw);
	const persisted = spillOutput(fsMod, ws, def.id, raw);
	const evidenceId = nextEvidenceId(ws);
	appendEvidence(ws, evidenceId, cmdStr + (built.audit.length ? `（${built.audit.join("；")}）` : "（保守默认参数）"), persisted);
	return settle({
		ok: proc.status === 0, id: def.id, toolName, stage: proc.status === 0 ? "executed" : "nonzero-exit",
		exit: proc.status, cmd: cmdStr, evidenceId, persisted, bytes: gov.bytes, truncated: gov.truncated, preview: gov.preview,
		summaryText: `${def.id} 完成（exit ${proc.status}，输出 ${gov.bytes} 字符${gov.truncated ? "，预览已封顶" : ""}；全文 ${persisted}；证据 ${evidenceId}）`,
		tiers: tiersLine(def.tiers)
	});
}

//#region 三个手写工具（nuclei/httpx/ffuf）执行核：速率留痕 + 产物 JSON + 证据 + 对账 + 治理 + 台账

export type ParsedRes = { writeRaw?: string | null; hits: { source: string; hit: string }[]; summary: Record<string, unknown>; summaryText: string };
export type ScanCoreResult = {
	ok: boolean; tool: string; toolName: string; stage: string; error?: string;
	evidenceId?: string; file?: string; bytes?: number; truncated?: boolean; preview?: string;
	summaryText?: string; hits?: number; reconciled?: number; cmd?: string; exit?: number | null;
	repeat?: { count: number; firstTs: string; lastTs: string };
};

const nucleiTemplateDirs = () => [
	path.join(process.env.HOME ?? "", "nuclei-templates"),
	path.join(process.env.HOME ?? "", "Library", "Application Support", "nuclei", "templates"),
	path.join(process.env.HOME ?? "", ".config", "nuclei", "templates")
];

export async function runScanCore(o: {
	core: CoreMeta; toolName: string; args: string[]; workspace?: string; target: string;
	rate?: number; defaultRate: number; active: boolean; parse: (raw: string, proc: ProcResult) => ParsedRes;
	outFile?: string; ctx?: ExecCtx; signal?: AbortSignal; fsMod?: typeof fs;
	/** 覆盖速率参（同名不同物的变体无 -rl 时用）*/
	rateArgs?: string[];
	/** 附加注记（进证据行与 summaryText，例如变体判定结果）*/
	variantNote?: string;
}): Promise<ScanCoreResult> {
	const fsMod = o.fsMod ?? fs;
	const core = o.core;
	const ws = path.resolve(o.workspace || o.ctx?.cwd || process.cwd());
	const settle = (r: ScanCoreResult): ScanCoreResult => {
		r.repeat = ledgerPrior(o.toolName, o.target, fsMod);
		ledgerAppend({
			ts: new Date().toISOString(), tool: o.toolName, target: o.target, cmd: r.cmd ?? "", workspace: ws,
			stage: r.stage, ok: r.ok, exit: r.exit ?? null, bytes: r.bytes ?? 0, truncated: !!r.truncated,
			evidenceId: r.evidenceId ?? "", output: r.file ?? "", error: r.error ?? "", audit: []
		}, STATE_DIR, fsMod);
		return r;
	};

	const cooldown = breakerCheck(core.id);
	if (cooldown > 0) return settle({
		ok: false, tool: core.id, toolName: o.toolName, stage: "breaker",
		error: `熔断中：${core.id} 连续失败 3 次进入 60s 冷却（剩 ${cooldown}s）——改走工具调用阶梯下级通道（MCP/替代/脚本）或稍后重试`
	});
	if (!(await hasBinAsync(core.bin))) {
		const guidance = await ladderOnMissing({ ...core, toolName: o.toolName }, o.ctx, fsMod);
		return settle({ ok: false, tool: core.id, toolName: o.toolName, stage: "missing-bin", error: `${BIN_HINT}\n${guidance}` });
	}
	if (o.active) {
		const reg = checkRegistered(fsMod, ws, o.target);
		if (!reg.ok) return settle({ ok: false, tool: core.id, toolName: o.toolName, stage: "unregistered", error: reg.hint });
	}
	ensureDirs(ws);
	if (core.bin === "nuclei" && !nucleiTemplateDirs().some((d) => fsMod.existsSync(d))) {
		return settle({
			ok: false, tool: core.id, toolName: o.toolName, stage: "no-templates",
			error: "nuclei 模板库不存在——首次使用需一次性下载（nuclei -update-templates，数据非工具安装）。按用户基准需批准：请在会话外自行执行，或明确批准后由模型执行。"
		});
	}

	const ts = new Date().toISOString().replace(/[-:T.]/g, "").slice(0, 14);
	const outFile = o.outFile ?? path.join(ws, "artifacts", "scans", `${core.id}-${ts}.json`);
	const rate = o.rate ?? o.defaultRate;
	// 同名不同物防护：本机 httpx 若是 python-httpx CLI，命令模板整条换掉（不把 -u/-json/-rl 打到错的 CLI 上）
	let args = o.args, parse = o.parse, rateArgs = o.rateArgs, variantNote = o.variantNote;
	if (core.bin === "httpx" && (await httpxVariant()) === "cli") {
		const first = String(o.target).split(",")[0].trim();
		args = [first];
		rateArgs = ["--timeout", "8"];
		parse = httpxCliParse;
		variantNote = `变体判定：本机 httpx 是 python-httpx CLI（非 projectdiscovery/httpx）——无 -u/-json/-rl 参，已改用位置参 URL + --timeout 8 保守超时`
			+ (o.rate ? `；显式 rate=${o.rate} 在此变体无对应参，已忽略` : "")
			+ (String(o.target).includes(",") ? `；多目标仅打第一个 ${first}（需 projectdiscovery 版：brew install projectdiscovery/tap/httpx，须用户批准，本件不自动装）` : "");
	}
	const full = [...args, ...(rateArgs ?? (core.bin === "ffuf" ? ["-rate", String(rate)] : ["-rl", String(rate)]))];
	const cmdStr = `${core.bin} ${full.join(" ")}`;

	const gate = await machineGate();
	if (!gate.ok) return settle({ ok: false, tool: core.id, toolName: o.toolName, stage: "machine", error: `机器过载拒绝执行：${gate.note}`, cmd: cmdStr });

	const proc = await serialized(() => runProcess(core.bin, full, { timeoutMs: core.timeoutMs, maxBuffer: 64 * 1024 * 1024, signal: o.signal }));
	if (proc.error) {
		breakerRecord(core.id, false);
		return settle({
			ok: false, tool: core.id, toolName: o.toolName, stage: "exec", cmd: cmdStr,
			error: `执行失败：${proc.error.message}${proc.error.code === "ETIMEDOUT" ? `（超时 ${core.timeoutMs / 1000}s${core.bin === "nuclei" ? "——模板库缺失时首次会尝试拉取导致超时" : ""}）` : ""}\n${tiersLine(core.tiers)}`
		});
	}
	breakerRecord(core.id, proc.status === 0);

	const raw = proc.stdout ?? "";
	const parsed = parse(raw, proc);
	if (parsed.writeRaw !== null && parsed.writeRaw !== undefined) fsMod.writeFileSync(outFile, parsed.writeRaw);
	else if (!o.outFile) fsMod.writeFileSync(outFile, JSON.stringify({ raw }, null, 2));
	const evidenceId = nextEvidenceId(ws);
	appendEvidence(ws, evidenceId, cmdStr + (rate !== o.defaultRate ? `（速率显式覆盖：默认 ${o.defaultRate} → ${rate}，留痕）` : `（保守默认速率 ${o.defaultRate}）`) + (variantNote ? `（${variantNote}）` : ""), path.relative(ws, outFile));
	const reconciled = appendReconcile(ws, parsed.hits);
	const gov = governPreview(raw + (proc.stderr && proc.stderr.trim() ? `\n[stderr]\n${proc.stderr}` : ""));
	return settle({
		ok: proc.status === 0, tool: core.id, toolName: o.toolName, stage: proc.status === 0 ? "executed" : "nonzero-exit",
		exit: proc.status, cmd: cmdStr, evidenceId, file: path.relative(ws, outFile),
		bytes: gov.bytes, truncated: gov.truncated, preview: gov.preview,
		summaryText: `${parsed.summaryText}${variantNote ? `[${variantNote}]` : ""}（证据 ${evidenceId}；全文 ${path.relative(ws, outFile)}${gov.truncated ? "，返回体已封顶" : ""}）`,
		hits: parsed.hits.length, reconciled
	});
}

export const nucleiParse = (raw: string): ParsedRes => {
	const hits: { source: string; hit: string }[] = [];
	const out: any[] = [];
	for (const line of raw.split("\n")) {
		if (!line.trim().startsWith("{")) continue;
		try {
			const j = JSON.parse(line);
			hits.push({ source: "nuclei", hit: `${j.templateID ?? j["template-id"]} @ ${j.host ?? j.url} [${j.info?.severity ?? "?"}]` });
			out.push(j);
		} catch { /* 非 JSONL 行忽略 */ }
	}
	return { writeRaw: JSON.stringify(out, null, 2), hits, summary: { total: out.length }, summaryText: `nuclei 命中 ${out.length} 条（已写对账待处置）` };
};

export const httpxParse = (raw: string): ParsedRes => {
	const out: any[] = [];
	for (const line of raw.split("\n")) {
		if (!line.trim().startsWith("{")) continue;
		try { out.push(JSON.parse(line)); } catch { /* 忽略 */ }
	}
	return {
		writeRaw: JSON.stringify(out, null, 2), hits: [], summary: { alive: out.length },
		summaryText: `存活 ${out.length}；探测未登记资产属测绘行为，结果请回填资产基线（assets.md / cloud-assets.md）`
	};
};

export const ffufParse = (_raw: string, proc: ProcResult): ParsedRes => ({
	writeRaw: null, hits: [], summary: { note: "结果见 -o 输出文件（已由 ffuf 写入）" },
	summaryText: `ffuf 完成（exit ${proc.status}），结果见产物文件`
});

/** 本机 httpx 变体判定（同名不同物，只探测不安装）：
 *  projectdiscovery/httpx（Go：-u/-json/-rl 限速）vs python-httpx CLI（URL 位置参 + --timeout，无 -rl）。
 *  结果进程级缓存；命令模板据此选择，避免把 -u/-rl 打到错误的 CLI 上（防错打）。 */
let httpxVariantCache: "pd" | "cli" | "" = "";
export async function httpxVariant(): Promise<"pd" | "cli"> {
	if (httpxVariantCache) return httpxVariantCache;
	const p = await runProcess("httpx", ["--help"], { timeoutMs: 15_000, maxBuffer: 512 * 1024, inspectEveryMs: 0 });
	const out = `${p.stdout}${p.stderr}`;
	httpxVariantCache = /projectdiscovery|(^|\s)-rl(\s|$)/m.test(out) ? "pd" : "cli";
	return httpxVariantCache;
}

/** python-httpx CLI 变体的产物解析（单目标文本输出，非 -json 逐行）。 */
export const httpxCliParse = (raw: string): ParsedRes => {
	const hit = /HTTP\/[\d.]+ ([1-5]\d\d)/.exec(raw);
	const alive = hit ? 1 : 0;
	return {
		writeRaw: JSON.stringify({ statusLine: hit ? hit[0] : null, raw }, null, 2),
		hits: [], summary: { alive },
		summaryText: `存活 ${alive}（python-httpx CLI 变体：单目标文本输出）；探测未登记资产属测绘行为，结果请回填资产基线（assets.md / cloud-assets.md）`
	};
};

//#endregion

//#region 参数 schema：注册表 ParamSpec → TypeBox

function specToType(spec: ParamSpec): TSchema {
	if (spec.enum) return Type.Union(spec.enum.map((v) => Type.Literal(v)), { description: spec.description ?? "" });
	if (spec.type === "integer") return Type.Number({ description: spec.description ?? "" });
	if (spec.type === "boolean") return Type.Boolean({ description: spec.description ?? "" });
	return Type.String({ description: spec.description ?? "" });
}

export function buildParams(def: ToolDef): TSchema {
	const props: Record<string, TSchema> = {
		workspace: Type.Optional(Type.String({ description: "Task workspace root（缺省=当前工作目录）；产物与证据落 <workspace>/artifacts/" })),
		extra: Type.Optional(Type.String({ description: "Explicit extra args (audit-logged escape hatch; shell metacharacters rejected)" }))
	};
	for (const [k, spec] of Object.entries(def.params)) {
		const t = specToType(spec);
		props[k] = spec.required ? t : Type.Optional(t);
	}
	return Type.Object(props);
}

function targetFrom(def: ToolDef, p: Record<string, any>): string {
	const tp = def.guard?.targetParam ?? "target";
	return String(p[tp] ?? p.target ?? p.domain ?? p.url ?? p.host ?? "");
}

//#endregion
//#region 扩展装配：16 个模型可见工具 + 台账/清单命令 + 工具面开关

export const EXTENSION_NAME = "dsh-scanner-tools";

const GUIDELINE_UNREGISTERED = "防盲打：主动扫描类工具要求目标已登记 assets.md / cloud-assets.md；轻探测与被动枚举允许未登记但需回填基线。";
const GUIDELINE_LADDER = "工具缺失时按六节点阶梯降级（本机→MCP→已装替代→MCP 备选→问装→脚本），本扩展绝不自动安装二进制。";

function txt(text: string, details: unknown) {
	return { content: [{ type: "text" as const, text }], details };
}

function repeatNote(r: { repeat?: { count: number; firstTs: string; lastTs: string } }, toolName: string, target: string): string {
	const rep = r.repeat;
	if (!rep || rep.count === 0) return "";
	return `\n[防盲打台账] ${toolName} 对 ${target || "(无目标)"} 已是第 ${rep.count + 1} 次调用（首次 ${rep.firstTs}，上一次 ${rep.lastTs}）——台账 ${LEDGER_FILE}`;
}

export default function (pi: ExtensionAPI) {
	const toolNames: string[] = [];
	const allBins: Array<{ tool: string; bin: string; label: string }> = [];

	// ── 三个手写工具（沿用原工具名与参数语义）──
	const coreDefs = [
		{
			core: CORE_META.nuclei, toolName: "nuclei_scan",
			description: "Template-based vuln scan (local nuclei). Conservative rate by default (-rl 15); explicit `rate` override is audit-logged. Requires the target registered in the workspace assets.md (防盲打). Hits append to scan-reconcile.md as 待处置 (hit ≠ vuln — verify with 对照三件套 before reporting). Full output always persisted to artifacts/scans/ with a capped preview returned.",
			params: {
				target: Type.String({ description: "Target URL/host (must be registered in assets.md)" }),
				workspace: Type.Optional(Type.String({ description: "Task workspace root（缺省=当前工作目录）" })),
				severity: Type.Optional(Type.String({ description: "e.g. medium,high,critical (default high,critical)" })),
				rate: Type.Optional(Type.Number({ description: `requests/sec override (default ${RATE_DEFAULTS.nuclei}; override is audit-logged)` }))
			},
			run: (p: Record<string, any>, ctx: ExecCtx, signal?: AbortSignal) => runScanCore({
				core: CORE_META.nuclei, toolName: "nuclei_scan", workspace: p.workspace, target: p.target, rate: p.rate, defaultRate: RATE_DEFAULTS.nuclei,
				active: true, ctx, signal, parse: nucleiParse,
				args: ["-u", String(p.target), "-severity", String(p.severity ?? "high,critical"), "-jsonl", "-silent", "-nc"]
			})
		},
		{
			core: CORE_META.httpx, toolName: "httpx_probe",
			description: "Alive/tech-fingerprint probe (local httpx). Light recon: unregistered targets allowed, but backfill assets.md with the results. Conservative rate by default (-rl 25). Full output always persisted to artifacts/scans/ with a capped preview returned.",
			params: {
				targets: Type.String({ description: "One URL/host, or comma-separated list" }),
				workspace: Type.Optional(Type.String({ description: "Task workspace root（缺省=当前工作目录）" })),
				rate: Type.Optional(Type.Number({ description: `requests/sec override (default ${RATE_DEFAULTS.httpx}; audit-logged)` }))
			},
			run: (p: Record<string, any>, ctx: ExecCtx, signal?: AbortSignal) => runScanCore({
				core: CORE_META.httpx, toolName: "httpx_probe", workspace: p.workspace, target: p.targets, rate: p.rate, defaultRate: RATE_DEFAULTS.httpx,
				active: false, ctx, signal, parse: httpxParse,
				args: ["-u", String(p.targets), "-json", "-silent", "-title", "-tech-detect", "-status-code"]
			})
		},
		{
			core: CORE_META.ffuf, toolName: "ffuf_fuzz",
			description: "Dir/param fuzz (local ffuf). Conservative rate by default (-rate 50). Requires target registered in assets.md (防盲打). Use mode=dir for path fuzzing, mode=param for parameter discovery. Wordlist must be explicit (absolute path or SecLists) — this tool never installs wordlists.",
			params: {
				url: Type.String({ description: "URL containing FUZZ keyword, e.g. https://host/FUZZ" }),
				workspace: Type.Optional(Type.String({ description: "Task workspace root（缺省=当前工作目录）" })),
				mode: Type.Union([Type.Literal("dir"), Type.Literal("param")], { description: "dir = path fuzz; param = parameter discovery (?FUZZ=1)" }),
				wordlist: Type.Optional(Type.String({ description: "Path to wordlist (default: common.txt if resolvable)" })),
				rate: Type.Optional(Type.Number({ description: `requests/sec override (default ${RATE_DEFAULTS.ffuf}; audit-logged)` }))
			},
			run: (p: Record<string, any>, ctx: ExecCtx, signal?: AbortSignal) => {
				const ws = path.resolve(p.workspace ?? ctx.cwd ?? process.cwd());
				const wl = p.wordlist ? String(p.wordlist) : path.resolve("common.txt");
				if (!fs.existsSync(wl)) {
					return Promise.resolve<ScanCoreResult>({
						ok: false, tool: "ffuf", toolName: "ffuf_fuzz", stage: "no-wordlist",
						error: `字典不存在：${wl}——请给 wordlist 参数（绝对路径或 SecLists）；本工具不代装字典。`,
						repeat: ledgerPrior("ffuf_fuzz", p.url)
					});
				}
				const u = p.mode === "param"
					? (String(p.url).includes("FUZZ=") ? String(p.url) : String(p.url) + (String(p.url).includes("?") ? "&" : "?") + "FUZZ=1")
					: String(p.url);
				ensureDirs(ws);
				const ts = new Date().toISOString().replace(/[-:T.]/g, "").slice(0, 14);
				const outFile = path.join(ws, "artifacts", "scans", `ffuf-${ts}.json`);
				return runScanCore({
					core: CORE_META.ffuf, toolName: "ffuf_fuzz", workspace: ws, target: p.url, rate: p.rate, defaultRate: RATE_DEFAULTS.ffuf,
					active: true, ctx, signal, parse: ffufParse, outFile,
					args: ["-u", u, "-w", wl, "-mc", "200,204,301,302,307,401,403", "-o", outFile, "-of", "json", "-s"]
				});
			}
		}
	];

	for (const cd of coreDefs) {
		toolNames.push(cd.toolName);
		allBins.push({ tool: cd.toolName, bin: cd.core.bin, label: cd.core.id });
		pi.registerTool({
			name: cd.toolName, label: cd.toolName, description: cd.description,
			parameters: Type.Object(cd.params),
			executionMode: "sequential",
			promptSnippet: `${cd.toolName}：${cd.core.tiers[0].replace(/（.*/, "")}（保守默认速率，缺失走六节点阶梯，绝不自动安装）`,
			promptGuidelines: [GUIDELINE_UNREGISTERED, GUIDELINE_LADDER],
			async execute(_id: string, raw: any, signal: AbortSignal | undefined, _onUpdate: any, ctx: ExtensionContext) {
				const p = raw as Record<string, any>;
				const r = await cd.run(p, { hasUI: ctx.hasUI, ui: ctx.ui, cwd: ctx.cwd }, signal);
				const note = repeatNote(r, cd.toolName, String(p.target ?? p.targets ?? p.url ?? ""));
				const text = r.ok
					? `${cd.core.id}: ${r.summaryText}${r.preview ? "\n" + r.preview : ""}${note}`
					: `${cd.core.id} 拒绝/失败：${r.error}${note}`;
				return txt(text, {
					tool: cd.toolName, stage: r.stage, ok: r.ok, cmd: r.cmd, exit: r.exit ?? null,
					evidenceId: r.evidenceId ?? "", file: r.file ?? "", bytes: r.bytes ?? 0, truncated: !!r.truncated,
					hits: r.hits ?? 0, reconciled: r.reconciled ?? 0, repeat: r.repeat
				});
			}
		});
	}

	// ── 注册表十三工具：def 带全部工具面元数据，新增工具只在 TOOL_DEFS 加一条数据 ──
	for (const def of Object.values(TOOL_DEFS)) {
		toolNames.push(def.name);
		allBins.push({ tool: def.name, bin: (def.bins ?? [def.bin])[0].replace("{module}", def.moduleParam ? String(def.params[def.moduleParam]?.enum?.[0] ?? "") : ""), label: def.id });
		pi.registerTool({
			name: def.name, label: def.name,
			description: `${def.summary} Full output always persisted to artifacts/tool-output/ with a capped preview returned. ${def.hint}。${tiersLine(def.tiers)}`,
			parameters: buildParams(def),
			executionMode: "sequential",
			promptSnippet: `${def.name}：${def.hint.slice(0, 60)}`,
			promptGuidelines: def.guard.active ? [GUIDELINE_UNREGISTERED, GUIDELINE_LADDER] : [GUIDELINE_LADDER],
			async execute(_id: string, raw: any, signal: AbortSignal | undefined, _onUpdate: any, ctx: ExtensionContext) {
				const p = raw as Record<string, any>;
				const r = await runGoverned({ def, params: p, workspace: p.workspace, ctx: { hasUI: ctx.hasUI, ui: ctx.ui, cwd: ctx.cwd }, signal });
				const note = repeatNote(r, def.name, targetFrom(def, p));
				const text = r.ok ? `${r.summaryText}\n${r.preview}${note}` : `${def.id} 拒绝/失败：${r.error}${note}`;
				return txt(text, {
					tool: def.name, id: def.id, stage: r.stage, ok: r.ok, cmd: r.cmd, exit: r.exit ?? null,
					evidenceId: r.evidenceId ?? "", persisted: r.persisted ?? "", bytes: r.bytes ?? 0, truncated: !!r.truncated, repeat: r.repeat
				});
			}
		});
	}

	// ── 清单与台账命令（终端安全：只 notify + 写文件，不假设 web 前端） ──
	pi.registerCommand("scanners", {
		description: "扫描器注册表清单 + 本机检测状态（写 ~/.pi/redteam/dsh-scanner-tools/registry.md）",
		handler: async (_args, ctx) => {
			const rows: string[] = ["# dsh-scanner-tools 注册表\n\n| 工具 | 二进制 | 类型 | 防盲打 | 保守默认 | 超时 | 本机检测 |", "|---|---|---|---|---|---|---|"];
			const xv = await httpxVariant();
			for (const cd of coreDefs) {
				const found = hasBin(cd.core.bin);
				const det = cd.core.id === "httpx" && found
					? `✓（变体：${xv === "pd" ? "projectdiscovery/httpx" : "python-httpx CLI，非 projectdiscovery——已改按变体模板执行"}）`
					: found ? "✓" : "✗ 未检测到";
				rows.push(`| ${cd.toolName} | ${cd.core.bin} | ${cd.core.id} | ${cd.toolName === "httpx_probe" ? "轻探测" : "主动"} | rate ${RATE_DEFAULTS[cd.core.id as keyof typeof RATE_DEFAULTS]} | ${Math.round(cd.core.timeoutMs / 1000)}s | ${det} |`);
			}
			for (const def of Object.values(TOOL_DEFS)) {
				const found = hasBin((def.bins ?? [def.bin])[0].replace("{module}", "secretsdump"));
				const dflt = Object.values(def.args?.combined ?? {}).map((c) => `${c.flag} ${c.def ?? "-"}`).join(" ") || "—";
				rows.push(`| ${def.name} | ${(def.bins ?? [def.bin]).join("/")} | ${def.kind} | ${def.guard.active ? "主动（须登记）" : "轻探测/被动"} | ${dflt} | ${Math.round(def.limits.timeoutMs / 1000)}s | ${found ? "✓" : "✗ 未检测到"} |`);
			}
			const file = path.join(STATE_DIR, "registry.md");
			fs.mkdirSync(STATE_DIR, { recursive: true });
			fs.writeFileSync(file, rows.join("\n") + "\n");
			ctx.ui.notify(`dsh-scanner-tools：${toolNames.length} 个工具（3 手写 + ${Object.keys(TOOL_DEFS).length} 注册表）；清单 ${file}`, "info");
		}
	});

	pi.registerCommand("scan-ledger", {
		description: "扫描调用台账（防盲打：同目标同工具重复扫描可查）——默认列最近 20 条",
		handler: async (args, ctx) => {
			const n = Math.max(1, Number(args?.trim() || 20) || 20);
			let text = "";
			try { text = fs.readFileSync(LEDGER_FILE, "utf8"); } catch { ctx.ui.notify(`台账为空：${LEDGER_FILE}`, "warning"); return; }
			const lines = text.trimEnd().split("\n").filter(Boolean);
			const last = lines.slice(-n);
			const rows = ["# 扫描调用台账（最近 " + last.length + " / 共 " + lines.length + " 条）\n", "| 时间 | 工具 | 目标 | 阶段 | 结果 | 命令/输出 |", "|---|---|---|---|---|---|"];
			for (const l of last) {
				let r: any; try { r = JSON.parse(l); } catch { continue; }
				rows.push(`| ${r.ts} | ${r.tool} | ${String(r.target).slice(0, 30)} | ${r.stage} | ${r.ok ? "ok" : "拒绝/失败"} | ${String(r.cmd || r.error || "").slice(0, 90)} |`);
			}
			const file = path.join(STATE_DIR, "ledger-latest.md");
			fs.mkdirSync(STATE_DIR, { recursive: true });
			fs.writeFileSync(file, rows.join("\n") + "\n");
			ctx.ui.notify(`台账 ${lines.length} 条，最近 ${last.length} 条已写 ${file}`, "info");
		}
	});

	pi.registerCommand("scanners-tools", {
		description: "调整扫描器工具面：/scanners-tools all|core|off（core=只留 nuclei/httpx/ffuf，off=全部停用）",
		handler: async (args, ctx) => {
			const mode = (args || "").trim().toLowerCase();
			const active = pi.getActiveTools();
			const others = active.filter((t) => !toolNames.includes(t));
			const coreThree = ["nuclei_scan", "httpx_probe", "ffuf_fuzz"];
			if (mode === "off") pi.setActiveTools(others);
			else if (mode === "core") pi.setActiveTools([...others, ...coreThree]);
			else pi.setActiveTools([...new Set([...others, ...toolNames])]);
			ctx.ui.notify(`扫描器工具面 ${mode || "all"}：本扩展活跃工具 ${pi.getActiveTools().filter((t) => toolNames.includes(t)).length}/${toolNames.length}`, "info");
		}
	});

	pi.on("session_start", async (_event, ctx) => {
		let missing = 0;
		const detected: string[] = [];
		for (const b of allBins) {
			const cand = b.bin.includes("{module}") ? b.bin.replace("{module}", "secretsdump") : b.bin;
			if (hasBin(cand)) detected.push(b.label); else missing += 1;
		}
		try {
			ctx.ui.notify(`dsh-scanner-tools：${toolNames.length} 个扫描工具已注册；本机检测到 ${detected.join("/") || "无"}，未检测到 ${missing} 个（走阶梯指路，绝不自动安装）`, "info");
		} catch { /* 无 UI 模式忽略 */ }
	});
}
