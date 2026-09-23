import { mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const PLUGIN_NAME = "dsh-trace-vault";
const STATE_DIR = join(homedir(), ".pi", "redteam", PLUGIN_NAME);
const DB_PATH = process.env.PI_TRACE_VAULT_DB || join(STATE_DIR, "traces.db");
const EXPORT_DIR = join(STATE_DIR, "exports");
const ARGS_CAP = 8 * 1024;
const RESULT_CAP = 32 * 1024;
const TOOL_OUTPUT_CAP = 12 * 1024;
const RETENTION_DAYS = positiveInteger(process.env.PI_TRACE_VAULT_RETENTION_DAYS, 14);
const MAX_ROWS = positiveInteger(process.env.PI_TRACE_VAULT_MAX_ROWS, 50000);
const INFLIGHT_CAP = 4096;
const BLOCKED_RE = /\b(403|forbidden|waf|blocked|rate.?limit|429|too many requests|captcha|denied)\b/i;

type Outcome = "ok" | "blocked" | "error";

interface TraceRow {
	id: string;
	sessionId: string;
	mode: string;
	tool: string;
	args: string;
	result: string;
	isError: boolean;
	outcome: Outcome;
	durMs: number | null;
	createdAt: string;
	argsLen?: number;
	resultLen?: number;
}

interface TraceStore {
	db: DatabaseSync;
	insertCount: number;
	closed: boolean;
}

interface PendingCall {
	sessionId: string;
	tool: string;
	args: string;
	startedAt: number;
}

const TraceSearchParams = Type.Object({
	query: Type.String({ description: "关键词（子串命中调用参数或响应文本）" }),
	tool: Type.Optional(Type.String({ description: "按工具名过滤（如 bash / read）" })),
	session_id: Type.Optional(Type.String({ description: "限定会话（省略=全部本地会话）" })),
	limit: Type.Optional(Type.Number({ description: "返回行数（默认 10，上限 50）" })),
	offset: Type.Optional(Type.Number({ description: "翻页偏移" })),
});

const TraceGetParams = Type.Object({
	id: Type.String({ description: "调用 id（trace_search/trace_recent 返回的 id）" }),
});

const TraceRecentParams = Type.Object({
	tool: Type.Optional(Type.String({ description: "按工具名过滤" })),
	session_id: Type.Optional(Type.String({ description: "限定会话（默认=当前会话）" })),
	limit: Type.Optional(Type.Number({ description: "返回行数（默认 20，上限 100）" })),
});

const TraceStatsParams = Type.Object({
	session_id: Type.Optional(Type.String({ description: "限定会话（默认=当前会话）" })),
});

export default function (pi: ExtensionAPI) {
	let store: TraceStore | undefined;
	const inflight = new Map<string, PendingCall>();

	const ensureStore = (): TraceStore => {
		if (store && !store.closed) return store;
		mkdirSync(dirname(DB_PATH), { recursive: true });
		const db = new DatabaseSync(DB_PATH);
		db.exec("PRAGMA journal_mode = WAL");
		db.exec("PRAGMA busy_timeout = 5000");
		db.exec(`
			CREATE TABLE IF NOT EXISTS traces (
				id         TEXT PRIMARY KEY,
				session_id TEXT NOT NULL,
				mode       TEXT NOT NULL DEFAULT 'pi',
				tool       TEXT NOT NULL,
				args       TEXT NOT NULL DEFAULT '',
				result     TEXT NOT NULL DEFAULT '',
				is_error   INTEGER NOT NULL DEFAULT 0,
				outcome    TEXT NOT NULL DEFAULT 'ok',
				dur_ms     INTEGER,
				created_at TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS traces_session ON traces(session_id, created_at DESC);
			CREATE INDEX IF NOT EXISTS traces_tool ON traces(tool);
			CREATE INDEX IF NOT EXISTS traces_created ON traces(created_at DESC);
		`);
		ensureModeColumn(db);
		store = { db, insertCount: 0, closed: false };
		purgeOld(store);
		capRows(store);
		return store;
	};

	const closeStore = () => {
		if (!store || store.closed) return;
		store.db.close();
		store.closed = true;
		store = undefined;
		inflight.clear();
	};

	pi.on("session_start", () => {
		ensureStore();
	});

	pi.on("session_shutdown", () => {
		closeStore();
	});

	pi.on("tool_call", (event, ctx) => {
		if (inflight.size >= INFLIGHT_CAP) inflight.clear();
		inflight.set(event.toolCallId, {
			sessionId: ctx.sessionManager.getSessionId(),
			tool: event.toolName,
			args: argsTextOf(event.input),
			startedAt: Date.now(),
		});
	});

	pi.on("tool_result", (event) => {
		const pending = inflight.get(event.toolCallId);
		if (!pending) return;
		inflight.delete(event.toolCallId);
		const result = resultTextOf(event.content);
		insertTrace(ensureStore(), {
			id: `${pending.sessionId}:${event.toolCallId}`,
			sessionId: pending.sessionId,
			mode: "pi",
			tool: pending.tool,
			args: pending.args,
			result,
			isError: event.isError,
			durMs: Date.now() - pending.startedAt,
		});
	});

	pi.registerTool({
		name: "trace_search",
		label: "Trace search",
		description: "过程检索：按关键词在历史工具调用的参数与响应文本里找命中（子串匹配，新到旧）。返回轻量命中行；用 trace_get 按 id 取落库上限内的参数和结果。结果过长时会截断，完整本次检索写入状态目录。",
		parameters: TraceSearchParams,
		executionMode: "sequential",
		async execute(_toolCallId, params) {
			const rows = searchTraces(ensureStore(), {
				q: params.query,
				tool: params.tool,
				sessionId: params.session_id,
				limit: params.limit,
				offset: params.offset,
			});
			return textResult(renderHits(rows, rows.length));
		},
	});

	pi.registerTool({
		name: "trace_get",
		label: "Trace get",
		description: "取一条历史工具调用的完整过程（调用参数全文 + 响应文本全文，均受过程库落库上限限制）。id 来自 trace_search 或 trace_recent。结果过长时会截断，完整本次读取写入状态目录。",
		parameters: TraceGetParams,
		executionMode: "sequential",
		async execute(_toolCallId, params) {
			const row = getTrace(ensureStore(), params.id);
			if (!row) throw new Error(`无此调用：${params.id}`);
			return textResult(renderFull(row));
		},
	});

	pi.registerTool({
		name: "trace_recent",
		label: "Trace recent",
		description: "最近工具调用一览（新到旧）：查看某工具或某会话最近调用及出局分类（ok/blocked/error）。blocked 聚集表示 WAF/限速等拦截信号。结果过长时会截断，完整本次检索写入状态目录。",
		parameters: TraceRecentParams,
		executionMode: "sequential",
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const sessionId = params.session_id || ctx.sessionManager.getSessionId();
			const activeStore = ensureStore();
			const rows = listRecent(activeStore, { sessionId, tool: params.tool, limit: params.limit });
			return textResult(renderHits(rows, rows.length, statsTraces(activeStore, { sessionId })));
		},
	});

	pi.registerTool({
		name: "trace_stats",
		label: "Trace stats",
		description: "会话画像统计：工具调用成败分布与成功率、自救信号（blocked 后是否推进到 ok）、人工介入次数（Pi 无等价事件时为 0）、受阻工具 top。输出文本表格。",
		parameters: TraceStatsParams,
		executionMode: "sequential",
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const sessionId = params.session_id || ctx.sessionManager.getSessionId();
			return textResult(formatStats(sessionStats(ensureStore(), { sessionId })));
		},
	});

	pi.registerCommand("trace-stats", {
		description: "Show trace-vault statistics for this session or /trace-stats <session-id>",
		handler: async (args, ctx) => {
			const sessionId = args.trim() || ctx.sessionManager.getSessionId();
			ctx.ui.notify(formatStats(sessionStats(ensureStore(), { sessionId })), "info");
		},
	});
}

function positiveInteger(value: string | undefined, fallback: number): number {
	const parsed = Number(value);
	return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

function capText(value: unknown, cap: number): string {
	const text = String(value ?? "");
	return text.length <= cap ? text : `${text.slice(0, cap)}\n…[trace-vault 截断：原 ${text.length} 字符，仅存前 ${cap}]`;
}

function argsTextOf(value: unknown): string {
	let text: string;
	try {
		text = JSON.stringify(value, null, 1) ?? "";
	} catch {
		text = String(value ?? "");
	}
	return capText(text, ARGS_CAP);
}

function resultTextOf(content: unknown): string {
	const texts: string[] = [];
	const walk = (blocks: unknown): void => {
		if (typeof blocks === "string") {
			texts.push(blocks);
			return;
		}
		if (!Array.isArray(blocks)) return;
		for (const block of blocks) {
			if (!block || typeof block !== "object") continue;
			const value = block as { type?: unknown; text?: unknown; content?: unknown };
			if (value.type === "text" && typeof value.text === "string") texts.push(value.text);
			else if (Array.isArray(value.content) || typeof value.content === "string") walk(value.content);
		}
	};
	walk(content);
	return capText(texts.join("\n"), RESULT_CAP);
}

function classifyOutcome(isError: boolean, result: string): Outcome {
	if (isError) return "error";
	return BLOCKED_RE.test(result) ? "blocked" : "ok";
}

function createdAt(): string {
	return new Date().toISOString();
}

function insertTrace(store: TraceStore, input: Omit<TraceRow, "outcome" | "createdAt">): void {
	const outcome = classifyOutcome(input.isError, input.result);
	store.db.prepare(`
		INSERT OR REPLACE INTO traces (id, session_id, mode, tool, args, result, is_error, outcome, dur_ms, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`).run(
		input.id,
		input.sessionId,
		input.mode,
		input.tool,
		input.args,
		input.result,
		input.isError ? 1 : 0,
		outcome,
		input.durMs === null || !Number.isFinite(input.durMs) ? null : Math.max(0, Math.round(input.durMs)),
		createdAt(),
	);
	store.insertCount += 1;
	if (store.insertCount % 200 === 0) {
		purgeOld(store);
		capRows(store);
	}
}

function ensureModeColumn(db: DatabaseSync): void {
	const columns = db.prepare("PRAGMA table_info(traces)").all() as Array<{ name: string }>;
	if (!columns.some((column) => column.name === "mode")) {
		db.exec("ALTER TABLE traces ADD COLUMN mode TEXT NOT NULL DEFAULT 'pi'");
	}
}

function purgeOld(store: TraceStore): void {
	store.db.prepare("DELETE FROM traces WHERE created_at < datetime('now', ?)").run(`-${RETENTION_DAYS} days`);
}

function capRows(store: TraceStore): void {
	const count = store.db.prepare("SELECT COUNT(*) AS count FROM traces").get() as { count: number };
	if (count.count <= MAX_ROWS) return;
	store.db.prepare("DELETE FROM traces WHERE id IN (SELECT id FROM traces ORDER BY created_at ASC, id ASC LIMIT ?)").run(count.count - MAX_ROWS);
}

function rowOf(row: Record<string, unknown>): TraceRow {
	return {
		id: String(row.id),
		sessionId: String(row.session_id),
		mode: typeof row.mode === "string" ? row.mode : "pi",
		tool: String(row.tool),
		args: typeof row.args === "string" ? row.args : "",
		result: typeof row.result === "string" ? row.result : "",
		isError: Number(row.is_error) === 1,
		outcome: row.outcome === "blocked" || row.outcome === "error" ? row.outcome : "ok",
		durMs: typeof row.dur_ms === "number" ? row.dur_ms : null,
		createdAt: String(row.created_at),
		argsLen: typeof row.args_len === "number" ? row.args_len : undefined,
		resultLen: typeof row.result_len === "number" ? row.result_len : undefined,
	};
}

function searchTraces(store: TraceStore, options: { q: string; tool?: string; sessionId?: string; limit?: number; offset?: number }): TraceRow[] {
	const limit = bounded(options.limit, 10, 1, 50);
	const offset = bounded(options.offset, 0, 0, Number.MAX_SAFE_INTEGER);
	const where: string[] = [];
	const params: unknown[] = [];
	if (options.q) {
		const pattern = `%${escapeLike(options.q)}%`;
		where.push("(args LIKE ? ESCAPE '\\' OR result LIKE ? ESCAPE '\\')");
		params.push(pattern, pattern);
	}
	if (options.tool) {
		where.push("tool = ?");
		params.push(options.tool);
	}
	if (options.sessionId) {
		where.push("session_id = ?");
		params.push(options.sessionId);
	}
	const rows = store.db.prepare(`
		SELECT id, session_id, mode, tool, is_error, outcome, dur_ms, created_at,
			length(args) AS args_len, length(result) AS result_len
		FROM traces ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
		ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?
	`).all(...params, limit, offset) as Record<string, unknown>[];
	return rows.map(rowOf);
}

function getTrace(store: TraceStore, id: string): TraceRow | undefined {
	const row = store.db.prepare("SELECT * FROM traces WHERE id = ?").get(id) as Record<string, unknown> | undefined;
	return row ? rowOf(row) : undefined;
}

function listRecent(store: TraceStore, options: { sessionId?: string; tool?: string; limit?: number }): TraceRow[] {
	const limit = bounded(options.limit, 20, 1, 100);
	const where: string[] = [];
	const params: unknown[] = [];
	if (options.sessionId) {
		where.push("session_id = ?");
		params.push(options.sessionId);
	}
	if (options.tool) {
		where.push("tool = ?");
		params.push(options.tool);
	}
	const rows = store.db.prepare(`
		SELECT id, session_id, mode, tool, is_error, outcome, dur_ms, created_at,
			length(args) AS args_len, length(result) AS result_len
		FROM traces ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
		ORDER BY created_at DESC, id DESC LIMIT ?
	`).all(...params, limit) as Record<string, unknown>[];
	return rows.map(rowOf);
}

function statsTraces(store: TraceStore, options: { sessionId?: string }): Record<Outcome | "total", number> {
	const params: unknown[] = [];
	const where = options.sessionId ? "WHERE session_id = ?" : "";
	if (options.sessionId) params.push(options.sessionId);
	const rows = store.db.prepare(`SELECT outcome, COUNT(*) AS count FROM traces ${where} GROUP BY outcome`).all(...params) as Array<{ outcome: Outcome; count: number }>;
	const stats: Record<Outcome | "total", number> = { total: 0, ok: 0, blocked: 0, error: 0 };
	for (const row of rows) {
		stats.total += row.count;
		if (row.outcome === "ok" || row.outcome === "blocked" || row.outcome === "error") stats[row.outcome] = row.count;
	}
	return stats;
}

function sessionStats(store: TraceStore, options: { sessionId: string }): {
	sessionId: string;
	calls: number;
	ok: number;
	blocked: number;
	error: number;
	interventions: number;
	successRate: number | null;
	selfRecovered: boolean;
	blockedTools: string[];
} {
	const rows = store.db.prepare("SELECT tool, outcome FROM traces WHERE session_id = ? ORDER BY created_at, rowid").all(options.sessionId) as Array<{ tool: string; outcome: Outcome }>;
	let ok = 0;
	let blocked = 0;
	let error = 0;
	let sawBlocked = false;
	let selfRecovered = false;
	const blockedTools = new Map<string, number>();
	for (const row of rows) {
		if (row.outcome === "ok") {
			ok += 1;
			if (sawBlocked) selfRecovered = true;
		} else if (row.outcome === "blocked") {
			blocked += 1;
			sawBlocked = true;
			blockedTools.set(row.tool, (blockedTools.get(row.tool) ?? 0) + 1);
		} else {
			error += 1;
		}
	}
	const calls = ok + blocked + error;
	return {
		sessionId: options.sessionId,
		calls,
		ok,
		blocked,
		error,
		interventions: 0,
		successRate: calls ? Math.round((ok / calls) * 1000) / 10 : null,
		selfRecovered,
		blockedTools: [...blockedTools.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([tool, count]) => `${tool}×${count}`),
	};
}

function bounded(value: number | undefined, fallback: number, min: number, max: number): number {
	const number = Number(value);
	if (!Number.isFinite(number)) return fallback;
	return Math.min(Math.max(Math.floor(number), min), max);
}

function escapeLike(value: string): string {
	return value.replace(/[\\%_]/g, (character) => `\\${character}`);
}

function renderHits(rows: TraceRow[], total: number, stats?: Record<Outcome | "total", number>): string {
	if (!rows.length) return "无命中。";
	const lines = rows.map((row) => `[${row.id}] ${row.createdAt} ${row.tool} → ${row.outcome}${row.isError ? "（错误）" : ""}${row.durMs !== null ? ` ${row.durMs}ms` : ""}（args ${row.argsLen ?? "?"} / result ${row.resultLen ?? "?"} 字符）`);
	const tail = stats ? `\n出局统计：ok ${stats.ok} / blocked ${stats.blocked} / error ${stats.error}${stats.blocked ? "——blocked 聚集为拦截信号，建议换路径/降速" : ""}` : "";
	return `${total} 行：\n${lines.join("\n")}${tail}`;
}

function renderFull(row: TraceRow): string {
	return [
		`调用 ${row.id}`,
		`模式 ${row.mode} · 会话 ${row.sessionId} · ${row.createdAt}${row.durMs !== null ? ` · ${row.durMs}ms` : ""} · 出局 ${row.outcome}${row.isError ? "（错误）" : ""}`,
		"—— 参数 ——",
		row.args || "(空)",
		"—— 结果 ——",
		row.result || "(空)",
	].join("\n");
}

function formatStats(stats: ReturnType<typeof sessionStats>): string {
	const rate = stats.successRate === null ? "-" : `${stats.successRate}%`;
	return [
		"trace-vault 会话画像",
		"指标              数值",
		"----------------  --------------------------------",
		`会话              ${stats.sessionId}`,
		`调用              ${stats.calls}`,
		`ok / blocked / error  ${stats.ok} / ${stats.blocked} / ${stats.error}`,
		`成功率            ${rate}`,
		`自救信号          ${stats.selfRecovered ? "有（blocked 后推进到 ok）" : "无"}`,
		`人工介入          ${stats.interventions}`,
		`受阻工具 top      ${stats.blockedTools.join("、") || "-"}`,
	].join("\n");
}

function textResult(fullText: string): { content: Array<{ type: "text"; text: string }>; details: { fullOutputPath: string; databasePath: string } } {
	mkdirSync(EXPORT_DIR, { recursive: true });
	const fullOutputPath = join(EXPORT_DIR, `trace-query-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.txt`);
	writeFileSync(fullOutputPath, fullText, "utf8");
	if (fullText.length <= TOOL_OUTPUT_CAP) {
		return {
			content: [{ type: "text", text: `${fullText}\n\n完整本次检索：${fullOutputPath}\n过程库：${DB_PATH}` }],
			details: { fullOutputPath, databasePath: DB_PATH },
		};
	}
	return {
		content: [{ type: "text", text: `${fullText.slice(0, TOOL_OUTPUT_CAP)}\n\n[结果已截断；完整本次检索：${fullOutputPath}]` }],
		details: { fullOutputPath, databasePath: DB_PATH },
	};
}
