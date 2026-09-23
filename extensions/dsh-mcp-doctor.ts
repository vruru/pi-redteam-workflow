/**
 * dsh-mcp-studio → Pi extension: MCP 状态与诊断（只读）
 *
 * 源（只读）: ~/.pi/agent/redteam-model/plugins/dsh-mcp-studio/src/diagnose.ts
 *            ~/.pi/agent/redteam-model/plugins/dsh-mcp-studio/src/settings-rpc.ts
 *            ~/.pi/agent/redteam-model/plugins/dsh-mcp-studio/src/types.ts
 *
 * 本件只保留「只读体检 + 修复指路」，MCP 接入配置完全交给 Pi 原生 /mcp：
 *   - 读取 ~/.pi/agent/mcp.json 及 README 中声明的分层来源
 *   - 计算 precedence / 遮蔽关系
 *   - stdio 仅检查 command 可执行性，不拉起 server
 *   - HTTP 仅做 TCP/HTTP 探测，不跑完整 MCP 握手
 *   - 明确提示 lazy 生命周期：未连接 ≠ 坏
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import { URL } from "node:url";

const NAME = "dsh-mcp-doctor";
const STATE_DIR = path.join(os.homedir(), ".pi", "redteam", NAME);
const REPORT_DIR = path.join(STATE_DIR, "reports");

/** 原 diagnose.ts 的握手超时（diagnose.ts:10）。 */
const TIMEOUT_MS = 10_000;
/** 本件并发探测上限（原实现无并发控制，逐 server 顺序执行；为避免网络探测排队过久，设温和上限）。 */
const PROBE_CONCURRENCY = 4;

interface McpServerDef {
	command?: string;
	args?: string[];
	url?: string;
	headers?: Record<string, string>;
	socket?: string;
	lifecycle?: string;
	disabled?: boolean;
	[key: string]: unknown;
}

interface ConfigSource {
	path: string;
	/** 1=最低，6=最高 */
	rank: number;
	exists: boolean;
	servers: Record<string, McpServerDef>;
}

interface ServerEntry {
	name: string;
	def: McpServerDef;
	source: ConfigSource;
	shadowed?: ConfigSource;
}

interface Diagnosis {
	name: string;
	transport: "stdio" | "http" | "socket" | "unknown";
	sourcePath: string;
	rank: number;
	disabled: boolean;
	lifecycle: string;
	verdict: string;
	detail: string;
	fixHint: string;
	elapsedMs?: number;
}

const LAYERS: { path: string; rank: number; label: string }[] = [
	{ path: path.join(os.homedir(), ".config", "mcp", "mcp.json"), rank: 1, label: "user-global ~/.config/mcp/mcp.json" },
	{ path: path.join(os.homedir(), ".agents", "mcp.json"), rank: 2, label: "user-global ~/.agents/mcp.json" },
	{ path: path.join(os.homedir(), ".agents", "mcp", "mcp.json"), rank: 3, label: "user-global ~/.agents/mcp/mcp.json" },
	{ path: path.join(os.homedir(), ".pi", "agent", "mcp.json"), rank: 4, label: "Pi global ~/.pi/agent/mcp.json" },
	{ path: ".mcp.json", rank: 5, label: "project .mcp.json" },
	{ path: path.join(".pi", "mcp.json"), rank: 6, label: "project .pi/mcp.json" },
];

function nowIso(): string {
	return new Date().toISOString();
}

function stamp(): string {
	return nowIso().replace(/[:.]/g, "-");
}

function resolveLayerPath(template: string, cwd: string): string {
	if (path.isAbsolute(template)) return template;
	return path.resolve(cwd, template);
}

async function readSource(template: string, rank: number, cwd: string): Promise<ConfigSource> {
	const p = resolveLayerPath(template, cwd);
	let text = "";
	let exists = false;
	try {
		text = await fsp.readFile(p, "utf8");
		exists = true;
	} catch {
		exists = false;
	}
	let servers: Record<string, McpServerDef> = {};
	if (exists) {
		try {
			const parsed = JSON.parse(text) as { mcpServers?: Record<string, McpServerDef> };
			if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && parsed.mcpServers) {
				servers = parsed.mcpServers;
			}
		} catch (err) {
			servers = { _parse_error: { command: "", disabled: true, lifecycle: "lazy" } as McpServerDef };
		}
	}
	return { path: p, rank, exists, servers };
}

async function loadSources(cwd: string): Promise<ConfigSource[]> {
	const sources: ConfigSource[] = [];
	for (const layer of LAYERS) {
		sources.push(await readSource(layer.path, layer.rank, cwd));
	}
	return sources;
}

function mergeServers(sources: ConfigSource[]): { effective: ServerEntry[]; shadowed: ServerEntry[] } {
	const effective = new Map<string, ServerEntry>();
	const shadowed: ServerEntry[] = [];
	for (const source of sources) {
		for (const [name, def] of Object.entries(source.servers)) {
			if (name.startsWith("_")) continue; // internal markers
			const existing = effective.get(name);
			if (existing) {
				// lower-precedence entry becomes shadowed
				shadowed.push({ ...existing, shadowed: source });
				effective.set(name, { name, def, source });
			} else {
				effective.set(name, { name, def, source });
			}
		}
	}
	return { effective: [...effective.values()], shadowed };
}

function transportOf(def: McpServerDef): Diagnosis["transport"] {
	if (def.socket) return "socket";
	if (def.url) return "http";
	if (def.command) return "stdio";
	return "unknown";
}

function isExecutable(mode: number): boolean {
	// owner/group/other 任一可执行位即可
	return (mode & 0o111) !== 0;
}

async function commandExists(command: string): Promise<{ ok: boolean; detail: string }> {
	if (!command) return { ok: false, detail: "command 为空" };
	// 绝对路径或相对路径
	if (command.includes(path.sep) || command.startsWith(".")) {
		const resolved = path.resolve(command);
		try {
			const stat = await fsp.stat(resolved);
			if (!stat.isFile()) return { ok: false, detail: `${resolved} 不是普通文件` };
			if (!isExecutable(stat.mode)) return { ok: false, detail: `${resolved} 存在但不可执行` };
			return { ok: true, detail: `${resolved} 存在且可执行` };
		} catch {
			return { ok: false, detail: `${resolved} 不存在` };
		}
	}
	// PATH 搜索
	const pathDirs = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
	const extensions = process.platform === "win32" ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT").split(path.delimiter) : [""];
	for (const dir of pathDirs) {
		for (const ext of extensions) {
			const candidate = path.join(dir, command + ext);
			try {
				const stat = await fsp.stat(candidate);
				if (stat.isFile() && isExecutable(stat.mode)) {
					return { ok: true, detail: `在 PATH 找到 ${candidate}` };
				}
			} catch {
				// continue
			}
		}
	}
	return { ok: false, detail: `在 PATH 中未找到 "${command}"` };
}

async function checkStdio(def: McpServerDef): Promise<{ verdict: string; detail: string; fixHint: string; elapsedMs: number }> {
	const started = Date.now();
	const command = (def.command ?? "").trim();
	const args = Array.isArray(def.args) ? def.args : [];
	if (!command) {
		return {
			verdict: "配置错误",
			detail: "stdio server 缺少 command",
			fixHint: "在 /mcp 中补全 command 或改用 HTTP 传输",
			elapsedMs: Date.now() - started,
		};
	}
	const cmdCheck = await commandExists(command);
	let detail = cmdCheck.detail;
	let fixHint = cmdCheck.ok
		? "命令已就绪；lazy 模式下首次调用时才会真正连接"
		: `安装/配置 "${command}" 或将其目录加入 PATH；本件只诊断，不会自动安装`;

	// 辅助：node/python 等解释器后的第一个绝对路径参数是否存在
	if (cmdCheck.ok && args.length > 0) {
		const firstArg = args[0] ?? "";
		if (firstArg.includes(path.sep)) {
			try {
				await fsp.access(firstArg);
				detail += `；首个参数 ${firstArg} 存在`;
			} catch {
				detail += `；首个参数 ${firstArg} 不存在`;
				fixHint = `确认 ${firstArg} 路径正确`;
			}
		}
	}

	return {
		verdict: cmdCheck.ok ? "命令就绪" : "命令缺失/不可执行",
		detail,
		fixHint,
		elapsedMs: Date.now() - started,
	};
}

function httpRequest(url: string, timeoutMs: number): Promise<{ ok: boolean; status?: number; statusText?: string; error?: string; elapsedMs: number }> {
	const started = Date.now();
	return new Promise((resolve) => {
		const parsed = new URL(url);
		const lib = parsed.protocol === "https:" ? https : http;
		const req = lib.request(
			url,
			{ method: "GET", timeout: timeoutMs },
			(res) => {
				let body = "";
				res.setEncoding("utf8");
				res.on("data", (chunk: string) => (body += chunk));
				res.on("end", () => {
					resolve({ ok: true, status: res.statusCode, statusText: res.statusMessage ?? "", elapsedMs: Date.now() - started });
				});
			},
		);
		req.on("timeout", () => {
			req.destroy();
			resolve({ ok: false, error: `HTTP 探测超时（${timeoutMs}ms）`, elapsedMs: Date.now() - started });
		});
		req.on("error", (err) => {
			resolve({ ok: false, error: err.message, elapsedMs: Date.now() - started });
		});
		req.end();
	});
}

function tcpConnect(host: string, port: number, timeoutMs: number): Promise<{ ok: boolean; error?: string; elapsedMs: number }> {
	const started = Date.now();
	return new Promise((resolve) => {
		const socket = new net.Socket();
		let settled = false;
		const done = (ok: boolean, error?: string) => {
			if (settled) return;
			settled = true;
			try {
				socket.destroy();
			} catch {
				/* noop */
			}
			resolve({ ok, error, elapsedMs: Date.now() - started });
		};
		socket.setTimeout(timeoutMs);
		socket.once("connect", () => done(true));
		socket.once("error", (err) => done(false, err.message));
		socket.once("timeout", () => done(false, `TCP 连接超时（${timeoutMs}ms）`));
		socket.connect(port, host);
	});
}

async function checkHttp(def: McpServerDef): Promise<{ verdict: string; detail: string; fixHint: string; elapsedMs: number }> {
	const url = (def.url ?? "").trim();
	if (!url) {
		return {
			verdict: "配置错误",
			detail: "HTTP server 缺少 url",
			fixHint: "在 /mcp 中补全 url",
			elapsedMs: 0,
		};
	}
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return {
			verdict: "配置错误",
			detail: `url 格式非法: ${url}`,
			fixHint: "修正 url 格式",
			elapsedMs: 0,
		};
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		return {
			verdict: "配置错误",
			detail: `不支持的协议: ${parsed.protocol}`,
			fixHint: "仅支持 http/https",
			elapsedMs: 0,
		};
	}

	const host = parsed.hostname;
	const port = Number(parsed.port) || (parsed.protocol === "https:" ? 443 : 80);

	const tcp = await tcpConnect(host, port, TIMEOUT_MS);
	if (!tcp.ok) {
		const isLocal = host === "localhost" || host === "127.0.0.1" || host === "::1";
		const classification = isLocal ? "未启动 / 需要 GUI 应用先打开" : "网络不可达";
		return {
			verdict: "端口不可达",
			detail: `TCP ${host}:${port} ${tcp.error ?? "连接失败"} → ${classification}`,
			fixHint: isLocal
				? "先启动对应桌面应用（IDA/Ghidra/Burp 等）或本地 MCP 服务，再重试；lazy 模式下首次调用时也会尝试连接"
				: "检查网络、防火墙或远程服务状态",
			elapsedMs: tcp.elapsedMs,
		};
	}

	const httpResult = await httpRequest(url, TIMEOUT_MS);
	if (!httpResult.ok) {
		return {
			verdict: "HTTP 异常",
			detail: `TCP 通但 HTTP 探测失败: ${httpResult.error}`,
			fixHint: "检查服务是否已提供 MCP endpoint",
			elapsedMs: httpResult.elapsedMs,
		};
	}
	return {
		verdict: "端口可达",
		detail: `TCP 通，HTTP ${httpResult.status ?? "?"} ${httpResult.statusText ?? ""}`,
		fixHint: "服务已监听；lazy 模式下首次调用时才会真正完成 MCP 握手",
		elapsedMs: httpResult.elapsedMs,
	};
}

async function diagnoseServer(entry: ServerEntry): Promise<Diagnosis> {
	const def = entry.def;
	const disabled = def.disabled === true;
	const transport = transportOf(def);
	let result: { verdict: string; detail: string; fixHint: string; elapsedMs: number };
	switch (transport) {
		case "stdio":
			result = await checkStdio(def);
			break;
		case "http":
			result = await checkHttp(def);
			break;
		case "socket":
			result = {
				verdict: "未诊断",
				detail: "socket 传输暂不做只读探测",
				fixHint: "手动确认 rmcp-mux socket 文件存在且服务已启动",
				elapsedMs: 0,
			};
			break;
		default:
			result = {
				verdict: "配置错误",
				detail: "无法识别传输方式（无 command/url/socket）",
				fixHint: "在 /mcp 中补全传输配置",
				elapsedMs: 0,
			};
	}

	// 即使 disabled 也做只读探测，以便在报告中同时给出「已停用」和「端口/命令真实状态」。
	const verdict = disabled ? `已停用（${result.verdict}）` : result.verdict;
	const detail = disabled
		? `${result.detail}；另：该 server 在配置中 disabled=true`
		: result.detail;
	const fixHint = disabled
		? `如需启用：/mcp enable ${entry.name}；当前 ${result.fixHint}`
		: result.fixHint;

	return {
		name: entry.name,
		transport,
		sourcePath: entry.source.path,
		rank: entry.source.rank,
		disabled,
		lifecycle: String(def.lifecycle ?? "lazy"),
		verdict,
		detail,
		fixHint,
		elapsedMs: result.elapsedMs,
	};
}

async function withConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
	const results: R[] = new Array(items.length);
	let index = 0;
	async function worker(): Promise<void> {
		while (index < items.length) {
			const i = index++;
			results[i] = await fn(items[i]!);
		}
	}
	const workers: Promise<void>[] = [];
	for (let i = 0; i < Math.min(limit, items.length); i++) workers.push(worker());
	await Promise.all(workers);
	return results;
}

function formatTable(rows: Diagnosis[]): string {
	if (rows.length === 0) return "(无 server)";
	const cols = [
		{ key: "name", title: "server", width: 20 },
		{ key: "verdict", title: "verdict", width: 24 },
		{ key: "lifecycle", title: "lifecycle", width: 10 },
		{ key: "sourcePath", title: "source", width: 32 },
		{ key: "detail", title: "detail", width: 44 },
	] as const;
	function fit(s: string, w: number): string {
		const visual = s.length > w ? s.slice(0, w - 1) + "…" : s;
		return visual.padEnd(w, " ");
	}
	const sep = cols.map((c) => "-".repeat(c.width)).join("  ");
	const header = cols.map((c) => c.title.padEnd(c.width, " ")).join("  ");
	const lines = [header, sep];
	for (const row of rows) {
		const sourceBase = path.basename(row.sourcePath);
		const line = [
			fit(row.name, cols[0].width),
			fit(row.verdict, cols[1].width),
			fit(row.lifecycle, cols[2].width),
			fit(`${sourceBase} (r${row.rank})`, cols[3].width),
			fit(row.detail, cols[4].width),
		].join("  ");
		lines.push(line);
	}
	return lines.join("\n");
}

function buildMarkdown(
	diagnoses: Diagnosis[],
	sources: ConfigSource[],
	shadowed: ServerEntry[],
	reportPath: string,
): string {
	const total = diagnoses.length;
	const disabled = diagnoses.filter((d) => d.disabled).length;
	const stdioOk = diagnoses.filter((d) => d.transport === "stdio" && d.verdict.includes("命令就绪")).length;
	const stdioMissing = diagnoses.filter((d) => d.transport === "stdio" && d.verdict.includes("命令缺失")).length;
	const httpUnreachable = diagnoses.filter((d) => d.transport === "http" && d.verdict.includes("端口不可达")).length;
	const httpReachable = diagnoses.filter((d) => d.transport === "http" && d.verdict.includes("端口可达")).length;

	const lines: string[] = [];
	lines.push(`# MCP 状态与诊断报告`);
	lines.push("");
	lines.push(`- 生成时间: ${nowIso()}`);
	lines.push(`- 报告文件: ${reportPath}`);
	lines.push(`- 诊断范围: 本地 MCP 配置文件（只读），不启动 server`);
	lines.push("");
	lines.push("## 摘要");
	lines.push("");
	lines.push(`| 指标 | 数量 |`);
	lines.push(`|---|---|`);
	lines.push(`| server 总数 | ${total} |`);
	lines.push(`| 已停用 | ${disabled} |`);
	lines.push(`| stdio 命令就绪 | ${stdioOk} |`);
	lines.push(`| stdio 命令缺失/不可执行 | ${stdioMissing} |`);
	lines.push(`| HTTP 端口可达 | ${httpReachable} |`);
	lines.push(`| HTTP 端口不可达 | ${httpUnreachable} |`);
	lines.push(`| 被遮蔽项 | ${shadowed.length} |`);
	lines.push("");

	lines.push("## 分层配置来源与 precedence");
	lines.push("");
	lines.push("Pi MCP Adapter 的 precedence 顺序：后项覆盖前项（README 中 'Precedence is (later entries win)'）。");
	lines.push("");
	lines.push(`| rank | 来源 | 是否存在 | server 数 |`);
	lines.push(`|---|---|---|---|`);
	for (const s of sources) {
		lines.push(`| ${s.rank} | ${s.path} | ${s.exists ? "是" : "否"} | ${Object.keys(s.servers).length} |`);
	}
	lines.push("");

	lines.push("## 逐 server 诊断");
	lines.push("");
	lines.push(`| server | transport | lifecycle | disabled | source (rank) | verdict | detail | fix |`);
	lines.push(`|---|---|---|---|---|---|---|---|`);
	for (const d of diagnoses) {
		lines.push(
			`| ${d.name} | ${d.transport} | ${d.lifecycle} | ${d.disabled ? "是" : "否"} | ${path.basename(d.sourcePath)} (${d.rank}) | ${d.verdict} | ${d.detail} | ${d.fixHint} |`,
		);
	}
	lines.push("");

	if (shadowed.length > 0) {
		lines.push("## 被高 precedence 配置遮蔽的项");
		lines.push("");
		lines.push(`| server | 原来源 (rank) | 遮蔽来源 (rank) |`);
		lines.push(`|---|---|---|`);
		for (const s of shadowed) {
			lines.push(`| ${s.name} | ${path.basename(s.source.path)} (${s.source.rank}) | ${path.basename(s.shadowed!.path)} (${s.shadowed!.rank}) |`);
		}
		lines.push("");
	}

	lines.push("## 与原 diagnose.ts / settings-rpc.ts 的对照表");
	lines.push("");
	lines.push("本件只迁移了「状态与诊断」的**判定口径与阈值**，移除了真实握手与配置写入。");
	lines.push("");
	lines.push(`| 原插件项目 | 原位置 | 本件处理 | 说明 |`);
	lines.push(`|---|---|---|---|`);
	lines.push(`| TIMEOUT_MS = 10_000 | diagnose.ts:10 | 保留为 HTTP/TCP 探测超时 | 避免长时间等待 |`);
	lines.push(`| DiagnoseReport.ok | diagnose.ts:14 | 映射为 verdict: 端口可达 / 命令就绪 / 已停用 / ... | 不再做完整握手 |`);
	lines.push(`| DiagnoseReport.elapsedMs | diagnose.ts:15 | 保留并上报 | TCP/HTTP 或命令探测耗时 |`);
	lines.push(`| DiagnoseReport.protocolVersion | diagnose.ts:16 | **未实现** | 需要真实 MCP 握手，本件只读不做 |`);
	lines.push(`| DiagnoseReport.serverName | diagnose.ts:17 | **未实现** | 同上 |`);
	lines.push(`| DiagnoseReport.serverVersion | diagnose.ts:18 | **未实现** | 同上 |`);
	lines.push(`| DiagnoseReport.toolCount | diagnose.ts:19 | **未实现** | 同上 |`);
	lines.push(`| DiagnoseReport.error | diagnose.ts:20 | 映射为 detail + fixHint | 分类为命令缺失 / 端口不可达 / 超时等 |`);
	lines.push(`| stdioTransport (真实子进程) | diagnose.ts:28 | 替换为 commandExists / stat 只读检查 | 不拉起 server |`);
	lines.push(`| httpTransport (真实 POST 握手) | diagnose.ts:55 | 替换为 TCP + HTTP GET 探测 | 不跑 initialize/tools/list |`);
	lines.push(`| diagnoseServer | diagnose.ts:99 | 替换为 diagnoseServer (只读) | 输出 verdict/detail/fix |`);
	lines.push(`| ServerState 'disabled/mounting/connected/unreachable/error' | settings-rpc.ts | 映射为 verdict 字段 | 不读取工具注册表 |`);
	lines.push("");

	lines.push("## 为什么本件不接管 MCP 接入配置");
	lines.push("");
	lines.push("1. Pi 原生已提供 `/mcp` 命令与 `/mcp setup` 流程，负责 discover/write/enable/disable。");
	lines.push("2. `/mcp enable|disable` 只写入项目本地的 `.pi/mcp.json`（最高 precedence），不会修改共享来源；这是 Pi 设计好的配置治理。");
	lines.push("3. 本件只做只读体检，避免两个插件同时写同一配置文件产生冲突。");
	lines.push("4. 真实连接、OAuth、直接工具注册仍由 pi-mcp-adapter 在首次调用时 lazy 完成，诊断不应改变其状态。");
	lines.push("");

	lines.push("## lazy 生命周期判读口径");
	lines.push("");
	lines.push("- 默认 `lifecycle: lazy` 的 server 在 Pi 启动时**不会**主动连接。");
	lines.push("- 因此「TCP 端口不可达」或「命令已就绪但未连接」不等于 server 损坏；它只说明当前还没有发生首次工具调用。");
	lines.push("- 只有当你调用对应 server 的工具后，pi-mcp-adapter 才会真正连接并给出 `connected/error` 状态。");
	lines.push("- 本报告的 verdict 是「配置/前置条件是否就绪」，不是「运行时连接状态」。");
	lines.push("");

	lines.push("## 未完成项 / 差异");
	lines.push("");
	lines.push("- 未做真实 MCP `initialize` + `tools/list` 握手，因此不返回 protocolVersion/serverName/serverVersion/toolCount。");
	lines.push("- 未探测 socket 传输（rmcp-mux）的实际可用性。");
	lines.push("- 未解析 command/args 中的 `${VAR}` / `$env:VAR` / `~` 占位符。");
	lines.push("- 未读取运行时工具注册表，无法区分 `mounting` / `connected` / `error` 等连接中状态。");
	lines.push("- 未探测 OAuth / bearer token 是否有效。");
	lines.push("- 未实现 ancestor discovery 与 host-specific config discovery（默认 off）。");
	lines.push("- 未覆盖 pi-mcp-adapter runtime-register 与 package manifest 来源的 server。");
	lines.push("");

	return lines.join("\n");
}

export default function dshMcpDoctorExtension(pi: ExtensionAPI) {
	pi.registerCommand("mcp-doctor", {
		description: "Read-only MCP server health check: config precedence, command existence, HTTP/TCP reachability",
		handler: async (_args, ctx: ExtensionContext) => {
			await fsp.mkdir(REPORT_DIR, { recursive: true, mode: 0o700 });

			const sources = await loadSources(ctx.cwd ?? process.cwd());
			const { effective, shadowed } = mergeServers(sources);

			if (effective.length === 0) {
				const msg = "未在任何 MCP 配置文件中发现 mcpServers 条目。";
				if (ctx.mode === "tui") ctx.ui.notify(msg, "info");
				console.log(msg);
				return;
			}

			// 按来源 rank 排序，同 rank 按名称排序，输出稳定
			effective.sort((a, b) => {
				if (a.source.rank !== b.source.rank) return a.source.rank - b.source.rank;
				return a.name.localeCompare(b.name);
			});

			const diagnoses = await withConcurrency(effective, PROBE_CONCURRENCY, (entry) => diagnoseServer(entry));

			const reportName = `mcp-doctor-${stamp()}.md`;
			const reportPath = path.join(REPORT_DIR, reportName);
			const markdown = buildMarkdown(diagnoses, sources, shadowed, reportPath);
			await fsp.writeFile(reportPath, markdown, "utf8");

			const table = formatTable(diagnoses);
			const disabledCount = diagnoses.filter((d) => d.disabled).length;
			const stdioReadyCount = diagnoses.filter((d) => d.transport === "stdio" && d.verdict.includes("命令就绪")).length;
			const stdioMissingCount = diagnoses.filter((d) => d.transport === "stdio" && d.verdict.includes("命令缺失")).length;
			const httpUnreachableCount = diagnoses.filter((d) => d.transport === "http" && d.verdict.includes("端口不可达")).length;
			const summary = [
				`MCP 体检完成: ${diagnoses.length} 个 server, 已停用 ${disabledCount}, ` +
				`stdio 就绪 ${stdioReadyCount}, stdio 缺失 ${stdioMissingCount}, HTTP 不可达 ${httpUnreachableCount}`,
				`完整报告: ${reportPath}`,
				"",
				table,
			].join("\n");

			console.log(summary);
			if (ctx.mode === "tui") {
				ctx.ui.notify(`MCP 体检完成，报告已写入 ${reportPath}`, "info");
			}
		},
	});
}
