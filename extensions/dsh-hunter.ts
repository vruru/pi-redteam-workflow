/**
 * dsh-hunter → Pi extension: FOFA / Hunter / Quake passive asset search.
 *
 * Source (read-only): ~/.pi/agent/redteam-model/plugins/dsh-hunter/lib/{adapters,index,store}.js
 * This port intentionally excludes the source plugin's verify.live pipeline: passive search only.
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

const NAME = "dsh-hunter";
const STATE_DIR = path.join(os.homedir(), ".pi", "redteam", NAME);
const KEYS_FILE = path.join(STATE_DIR, "keys.json");
const HISTORY_FILE = path.join(STATE_DIR, "history.jsonl");
const AUTHORIZED_FILE = path.join(STATE_DIR, "authorized.json");
const OUTPUT_DIR = path.join(STATE_DIR, "outputs");
const USER_AGENT = "pi-dsh-hunter/1.0 (passive-asset-mapping)";
const TIMEOUT_MS = 15_000;
const PREVIEW_ROWS = 25;
const PREVIEW_CHARS = 8_000;

// Values preserve the DSH adapter limits. Calls deliberately default well below these maxima.
export const LIMITS = {
	fofa: { pageSize: 100, nextSize: 1000, freeExport: 10000 },
	hunter: { pageSize: 100, creditPerRow: 1 },
	quake: { pageSize: 100, creditPerRow: 1 },
} as const;
const DEFAULT_SIZE = 20;
const DSL_FIELDS = ["title", "body", "header", "app", "server", "port", "protocol", "domain", "ip", "cert", "icon_hash", "country", "region", "city", "org", "isp", "os", "product", "icp", "asn"];
/** Confirmed FOFA free-account output fields (verified 2026-09-23 against api/v1/search/all): country/org/isp/os OK, product NOT permitted (820001). */
const FOFA_FIELDS = ["host", "title", "ip", "port", "domain", "protocol", "server", "country", "org", "isp", "os"];

type Platform = "fofa" | "hunter" | "quake";
type KeyConfig = { fofa?: string; fofa_email?: string; fofa_username?: string; hunter?: string; quake?: string; note?: string };
type Asset = Record<string, string | string[]>;
type History = { at: string; platform: Platform; query: string; mode: string; request: Record<string, unknown>; resultCount?: number; total?: number; outputPath?: string; outcome: "ok" | "error"; error?: string; retriedWithout?: string[] };
type Authorized = { key: string; note: string; created_at: string };

const SearchParams = Type.Object({
	query: Type.String({ description: 'Unified DSL filters, space-separated, field:value form — e.g. protocol:https country:CN port:443 title:login. Quote a value that contains spaces: city:"Beijing". Supported fields: title/body/header/app/server/port/protocol/domain/ip/cert/icon_hash/country/region/city/org/isp/os/product/icp/asn. To pass FOFA native syntax verbatim (field="value" && ...), also set mode=native.' }),
	mode: Type.Optional(Type.Union([Type.Literal("dsl"), Type.Literal("native")])),
	size: Type.Optional(Type.Integer({ minimum: 1, maximum: 1000, description: "Rows for this one passive API request; defaults to 20. Platform caps are enforced." })),
});

const FofaParams = Type.Intersect([SearchParams, Type.Object({
	next: Type.Optional(Type.String({ description: "FOFA cursor returned by a prior fofa_search result. Omit for the first page." })),
	includeIcp: Type.Optional(Type.Boolean({ description: "One-off FOFA ICP field check. Defaults false because its account permission is not assumed." })),
	permissionCheck: Type.Optional(Type.Boolean({ description: "One-off lastupdatetime permission fallback check. Defaults false; normal searches never request premium fields." })),
})]);
const HunterParams = Type.Intersect([SearchParams, Type.Object({
	page: Type.Optional(Type.Integer({ minimum: 1, description: "1-based Hunter page; defaults to 1." })),
	startTime: Type.Optional(Type.String({ description: "Hunter start_time, YYYY-MM-DD HH:mm:ss; defaults to 30 days ago." })),
	endTime: Type.Optional(Type.String({ description: "Hunter end_time, YYYY-MM-DD HH:mm:ss; defaults to now." })),
	isWeb: Type.Optional(Type.Integer({ minimum: 0, maximum: 1, description: "Hunter is_web value; defaults to 1." })),
})]);
const QuakeParams = Type.Intersect([SearchParams, Type.Object({
	start: Type.Optional(Type.Integer({ minimum: 0, description: "0-based Quake offset; use next.start returned by the prior page." })),
})]);
const AccountParams = Type.Object({});

function now(): string { return new Date().toISOString(); }
function b64(value: string): string { return Buffer.from(value, "utf8").toString("base64"); }
function clamp(value: unknown, fallback: number, maximum: number): number {
	const n = Number(value);
	return Number.isFinite(n) ? Math.max(1, Math.min(Math.floor(n), maximum)) : fallback;
}
function stamp(): string { return now().replace(/[:.]/g, "-"); }
function keyTail(value: string): string { return value.length > 4 ? `…${value.slice(-4)}` : value; }

async function ensureState(): Promise<void> {
	await fsp.mkdir(OUTPUT_DIR, { recursive: true, mode: 0o700 });
	try { await fsp.chmod(STATE_DIR, 0o700); } catch { /* directory can be shared by an existing installation */ }
}

async function readKeys(): Promise<KeyConfig> {
	let text: string;
	try { text = await fsp.readFile(KEYS_FILE, "utf8"); }
	catch { throw new Error(`未找到 ${KEYS_FILE}；只读此文件配置 key。可先用 /hunter settings 查看要求。`); }
	let parsed: unknown;
	try { parsed = JSON.parse(text); } catch { throw new Error(`${KEYS_FILE} 不是有效 JSON。`); }
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${KEYS_FILE} 必须是 JSON 对象。`);
	return parsed as KeyConfig;
}

function requireKey(config: KeyConfig, platform: Platform): string {
	const value = String(config[platform] ?? "").trim();
	if (!value) throw new Error(`${platform.toUpperCase()} 未配置 key；编辑 ${KEYS_FILE} 后重试。FOFA 可先调用 fofa_account_status 自检账户与免费档状态。`);
	return value;
}

async function fetchJson(url: string, init: RequestInit = {}, timeoutMs = TIMEOUT_MS): Promise<unknown> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const headers = new Headers(init.headers);
		if (!headers.has("User-Agent")) headers.set("User-Agent", USER_AGENT);
		if (!headers.has("Accept")) headers.set("Accept", "application/json");
		const response = await fetch(url, { ...init, headers, signal: controller.signal, redirect: "follow" });
		const text = await response.text();
		let data: any;
		try { data = JSON.parse(text); } catch { data = { raw: text }; }
		if (!response.ok) throw new Error(`${response.status}: ${String(data?.errmsg ?? data?.message ?? data?.error ?? text.slice(0, 240))}`);
		return data;
	} catch (error) {
		if (error instanceof Error && error.name === "AbortError") throw new Error(`请求超时（${timeoutMs}ms）`);
		throw error;
	} finally { clearTimeout(timer); }
}

function parseDsl(input: string): Map<string, string> {
	const source = String(input ?? "").trim();
	if (!source) throw new Error("查询为空");
	const out = new Map<string, string>();
	const re = /([a-z_]+)\s*:\s*("([^"]*)"|(\S+))/g;
	let match: RegExpExecArray | null;
	let last = 0;
	while ((match = re.exec(source)) !== null) {
		const field = match[1];
		const value = match[3] ?? match[4];
		if (!DSL_FIELDS.includes(field)) throw new Error(`未知 DSL 字段 "${field}"；支持: ${DSL_FIELDS.join("/")}`);
		if (!value) throw new Error(`字段 "${field}" 值为空`);
		out.set(field, value);
		last = match.index + match[0].length;
	}
	if (out.size === 0) throw new Error("未识别到字段:值条件，例如 title:\"login\" port:8080");
	if (source.slice(last).replace(/\s+/g, "") !== "") throw new Error(`无法解析的片段: "${source.slice(last).trim()}"`);
	return out;
}
function escaped(value: string): string { return String(value).replace(/"/g, '\\"'); }
function buildQuery(platform: Platform, input: string, mode: string | undefined): string {
	if (mode === "native") return String(input);
	const fields = parseDsl(input);
	const parts: string[] = [];
	for (const [field, value] of fields) {
		const v = escaped(value);
		if (platform === "fofa") parts.push(`${field}="${v}"`);
		else if (platform === "hunter") {
			const mapped: Record<string, string | undefined> = { title: "web.title", body: "web.body", header: "web.header", app: "app.name", server: "web.server", port: "ip.port", protocol: "protocol", domain: "domain", ip: "ip", cert: "cert" };
			const hunterField = mapped[field];
			// Never drop a filter silently: a missing mapping would widen the Hunter query and fake extra hits.
			if (!hunterField) throw new Error(`Hunter 无 "${field}" 对应映射（统一 DSL 字段 ${field} 会被静默丢弃）。请按 Hunter 文档补映射，或用 mode=native 传 Hunter 原生语法。`);
			parts.push(`${hunterField}="${v}"`);
		} else parts.push(`${field}:"${v}"`);
	}
	if (parts.length === 0) throw new Error(`${platform.toUpperCase()} 无法从 DSL 生成有效条件。`);
	return parts.join(platform === "quake" ? " AND " : " && ");
}
function fofaGuard(query: string): string { return `(${query}) && (is_honeypot=false && is_fraud=false)`; }
function dateStamp(date: Date): string {
	const p = (n: number) => String(n).padStart(2, "0");
	return `${date.getFullYear()}-${p(date.getMonth() + 1)}-${p(date.getDate())} ${p(date.getHours())}:${p(date.getMinutes())}:${p(date.getSeconds())}`;
}
function daysAgo(days: number): string { return dateStamp(new Date(Date.now() - days * 86_400_000)); }

function isPermissionError(data: any): boolean {
	const message = String(data?.errmsg ?? data?.message ?? data?.error ?? "");
	return /820001|没有权限|permission/i.test(message);
}
async function fofaPage(key: string, query: string, size: number, next: string | undefined, extraFields: string[]): Promise<{ data: any; fields: string[]; retriedWithout: string[] }> {
	let fields = [...FOFA_FIELDS, ...extraFields];
	const request = async (requestFields: string[]) => {
		const params = new URLSearchParams({ key, size: String(size), fields: requestFields.join(","), qbase64: b64(query) });
		if (next) params.set("next", next);
		return await fetchJson(`https://fofa.info/api/v1/search/next?${params}`) as any;
	};
	let data = await request(fields);
	if (data?.error && isPermissionError(data) && extraFields.length > 0) {
		const rejected = extraFields.filter((field) => String(data?.errmsg ?? "").includes(field) || field === "lastupdatetime");
		const retriedWithout = rejected.length ? rejected : extraFields;
		fields = fields.filter((field) => !retriedWithout.includes(field));
		data = await request(fields);
		return { data, fields, retriedWithout };
	}
	return { data, fields, retriedWithout: [] };
}

function normalizeFofa(row: any[]): Asset {
	const value = (index: number) => String(row?.[index] ?? "");
	return { host: value(0), title: value(1), ip: value(2), port: value(3), domain: value(4), protocol: value(5), server: value(6), country: value(7), platform: "fofa" };
}
function normalizeHunter(row: any): Asset {
	return { host: String(row?.url ?? ""), title: String(row?.web_title ?? ""), ip: String(row?.ip ?? ""), port: String(row?.port ?? ""), domain: String(row?.domain ?? ""), protocol: String(row?.protocol ?? ""), server: String(row?.web_server ?? ""), country: String(row?.country ?? ""), platform: "hunter" };
}
function normalizeQuake(row: any): Asset {
	const service = Array.isArray(row?.service) ? row.service[0] ?? {} : row?.service ?? {};
	const http = service?.http ?? {};
	return { host: String(http.host ?? ""), title: String(http.title ?? ""), ip: String(row?.ip ?? ""), port: String(row?.port ?? ""), domain: String(row?.domain ?? ""), protocol: String(service?.name ?? ""), server: String(http.server ?? ""), country: String(row?.country ?? ""), platform: "quake" };
}

async function appendHistory(entry: History): Promise<void> {
	await ensureState();
	await fsp.appendFile(HISTORY_FILE, `${JSON.stringify(entry)}\n`, { encoding: "utf8", mode: 0o600 });
	try { await fsp.chmod(HISTORY_FILE, 0o600); } catch { /* existing file mode is retained on restrictive filesystems */ }
}
async function writeOutput(platform: Platform, body: unknown): Promise<string> {
	await ensureState();
	const file = path.join(OUTPUT_DIR, `${stamp()}-${platform}-${crypto.randomBytes(3).toString("hex")}.json`);
	await fsp.writeFile(file, JSON.stringify(body, null, 2), { encoding: "utf8", mode: 0o600 });
	return file;
}
async function readAuthorized(): Promise<Authorized[]> {
	try {
		const parsed = JSON.parse(await fsp.readFile(AUTHORIZED_FILE, "utf8"));
		return Array.isArray(parsed) ? parsed.filter((item): item is Authorized => !!item && typeof item.key === "string") : [];
	} catch (error: any) {
		if (error?.code === "ENOENT") return [];
		throw new Error(`无法读取授权白名单：${error?.message ?? error}`);
	}
}
async function writeAuthorized(entries: Authorized[]): Promise<void> {
	await ensureState();
	await fsp.writeFile(AUTHORIZED_FILE, JSON.stringify(entries, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
}
function preview(value: unknown, fullPath: string): string {
	let text = JSON.stringify(value, null, 2);
	if (text.length > PREVIEW_CHARS) text = text.slice(0, PREVIEW_CHARS) + `\n…输出已截断；完整结果：${fullPath}`;
	return text;
}
function searchError(platform: Platform, error: unknown): Error {
	const text = error instanceof Error ? error.message : String(error);
	const rateHint = /429|rate.?limit|quota|超限|额度/i.test(text) ? "；平台限流/超限：请稍后重试或缩小查询。" : "";
	return new Error(`${platform.toUpperCase()} 被动查询失败：${text}${rateHint} 可先调用 fofa_account_status（FOFA）或 /hunter settings 检查本地只读配置。`);
}
function resultText(platform: Platform, query: string, rows: Asset[], total: number, next: Record<string, unknown>, outputPath: string, retriedWithout: string[] = []): string {
	const visible = rows.slice(0, PREVIEW_ROWS);
	const retried = retriedWithout.length ? `\n字段权限降级：收到 820001 后自动移除 ${retriedWithout.join(", ")} 并重试一次。` : "";
	const remainder = rows.length > visible.length ? `\n行预览：${visible.length}/${rows.length}；` : "\n";
	return `${platform.toUpperCase()} 被动资产搜索完成：本页 ${rows.length} 条，平台 total=${total}。\n原生查询：${query}\n下一页参数：${JSON.stringify(next)}${retried}${remainder}${JSON.stringify(visible, null, 2)}\n完整响应与归一化结果：${outputPath}`;
}

async function runFofa(params: any): Promise<{ text: string; details: Record<string, unknown> }> {
	const config = await readKeys();
	const key = requireKey(config, "fofa");
	const nativeQuery = fofaGuard(buildQuery("fofa", params.query, params.mode));
	const size = clamp(params.size, DEFAULT_SIZE, LIMITS.fofa.nextSize);
	const extraFields = params.includeIcp === true ? ["icp"] : params.permissionCheck === true ? ["lastupdatetime"] : []; 
	try {
		const page = await fofaPage(key, nativeQuery, size, params.next, extraFields);
		if (page.data?.error) throw new Error(String(page.data?.errmsg ?? "FOFA returned error"));
		const sourceRows = Array.isArray(page.data?.results) ? page.data.results : [];
		const rows = sourceRows.map(normalizeFofa);
		const next = String(page.data?.next ?? "");
		const total = typeof page.data?.size === "number" ? page.data.size : sourceRows.length;
		const outputPath = await writeOutput("fofa", { platform: "fofa", at: now(), query: nativeQuery, fields: page.fields, retriedWithout: page.retriedWithout, response: page.data, assets: rows });
		await appendHistory({ at: now(), platform: "fofa", query: nativeQuery, mode: params.mode === "native" ? "native" : "dsl", request: { size, next: params.next ?? "", includeIcp: params.includeIcp === true, permissionCheck: params.permissionCheck === true }, resultCount: rows.length, total, outputPath, outcome: "ok", retriedWithout: page.retriedWithout });
		return { text: resultText("fofa", nativeQuery, rows, total, { next }, outputPath, page.retriedWithout), details: { platform: "fofa", total, resultCount: rows.length, next, fields: page.fields, retriedWithout: page.retriedWithout, outputPath } };
	} catch (error) {
		await appendHistory({ at: now(), platform: "fofa", query: nativeQuery, mode: params.mode === "native" ? "native" : "dsl", request: { size, next: params.next ?? "" }, outcome: "error", error: error instanceof Error ? error.message : String(error) });
		throw searchError("fofa", error);
	}
}

async function runHunter(params: any): Promise<{ text: string; details: Record<string, unknown> }> {
	const config = await readKeys();
	const key = requireKey(config, "hunter");
	const query = buildQuery("hunter", params.query, params.mode);
	const page = clamp(params.page, 1, Number.MAX_SAFE_INTEGER);
	const size = clamp(params.size, DEFAULT_SIZE, LIMITS.hunter.pageSize);
	const startTime = String(params.startTime ?? daysAgo(30));
	const endTime = String(params.endTime ?? dateStamp(new Date()));
	try {
		const request = new URLSearchParams({ "api-key": key, search: b64(query), page: String(page), page_size: String(size), start_time: startTime, end_time: endTime, is_web: String(params.isWeb === 0 ? 0 : 1) });
		const data: any = await fetchJson(`https://hunter.qianxin.com/openApi/search?${request}`);
		if (data?.code !== 200) throw new Error(String(data?.message ?? JSON.stringify(data)));
		const sourceRows = Array.isArray(data?.data?.arr) ? data.data.arr : [];
		const rows = sourceRows.map(normalizeHunter);
		const total = typeof data?.data?.total === "number" ? data.data.total : sourceRows.length;
		const next = rows.length === size && page * size < total ? { page: page + 1 } : { page: null };
		const outputPath = await writeOutput("hunter", { platform: "hunter", at: now(), query, response: data, assets: rows });
		await appendHistory({ at: now(), platform: "hunter", query, mode: params.mode === "native" ? "native" : "dsl", request: { page, size, startTime, endTime, isWeb: params.isWeb === 0 ? 0 : 1 }, resultCount: rows.length, total, outputPath, outcome: "ok" });
		return { text: resultText("hunter", query, rows, total, next, outputPath), details: { platform: "hunter", total, resultCount: rows.length, next, outputPath } };
	} catch (error) {
		await appendHistory({ at: now(), platform: "hunter", query, mode: params.mode === "native" ? "native" : "dsl", request: { page, size, startTime, endTime }, outcome: "error", error: error instanceof Error ? error.message : String(error) });
		throw searchError("hunter", error);
	}
}

async function runQuake(params: any): Promise<{ text: string; details: Record<string, unknown> }> {
	const config = await readKeys();
	const token = requireKey(config, "quake");
	const query = buildQuery("quake", params.query, params.mode);
	const start = Math.max(0, Number(params.start) || 0);
	const size = clamp(params.size, DEFAULT_SIZE, LIMITS.quake.pageSize);
	try {
		const body = { query, start, size, latest: true, ignore_cache: false };
		const data: any = await fetchJson("https://quake.360.net/api/v3/search/quake_service", { method: "POST", headers: { "content-type": "application/json", "X-QuakeToken": token }, body: JSON.stringify(body) });
		if (data?.code !== 0) throw new Error(String(data?.message ?? JSON.stringify(data)));
		const sourceRows = Array.isArray(data?.data) ? data.data : [];
		const rows = sourceRows.map(normalizeQuake);
		const total = typeof data?.meta?.pagination?.total === "number" ? data.meta.pagination.total : sourceRows.length;
		const next = sourceRows.length === size && start + size < total ? { start: start + size } : { start: null };
		const outputPath = await writeOutput("quake", { platform: "quake", at: now(), query, request: body, response: data, assets: rows });
		await appendHistory({ at: now(), platform: "quake", query, mode: params.mode === "native" ? "native" : "dsl", request: body, resultCount: rows.length, total, outputPath, outcome: "ok" });
		return { text: resultText("quake", query, rows, total, next, outputPath), details: { platform: "quake", total, resultCount: rows.length, next, outputPath } };
	} catch (error) {
		await appendHistory({ at: now(), platform: "quake", query, mode: params.mode === "native" ? "native" : "dsl", request: { start, size }, outcome: "error", error: error instanceof Error ? error.message : String(error) });
		throw searchError("quake", error);
	}
}

async function accountStatus(): Promise<{ text: string; details: Record<string, unknown> }> {
	const config = await readKeys();
	const key = requireKey(config, "fofa");
	const email = String(config.fofa_email ?? "").trim();
	const expectedUsername = String(config.fofa_username ?? "").trim();
	try {
		const params = new URLSearchParams({ key });
		if (email) params.set("email", email);
		const data: any = await fetchJson(`https://fofa.info/api/v1/info/my?${params}`);
		if (data?.error) throw new Error(String(data?.errmsg ?? "FOFA returned error"));
		const fcoin = Number(data?.fcoin);
		const free = Number.isFinite(fcoin) && fcoin === 0;
		const tier = free ? "免费账户（fcoin=0）" : fcoin > 0 ? "有付费点数账户" : "账户点数状态未返回";
		const usernameMatches = expectedUsername ? String(data?.username ?? "") === expectedUsername : undefined;
		const freeHint = free ? "免费账户提示：lastupdatetime 等增值字段无权限，搜索已按可用字段收敛。" : "";
		return { text: `FOFA 账户自检成功：key 有效，${tier}。服务端账户标识不回显；搜索仍仅使用 key。${freeHint}`, details: { configured: true, keyTail: keyTail(key), emailConfigured: Boolean(email), usernameConfigured: Boolean(expectedUsername), usernameMatches, fcoin, responseUsernamePresent: Boolean(data?.username), responseEmailMasked: Boolean(data?.email) } };
	} catch (error) { throw searchError("fofa", error); }
}

async function manageAuthorized(params: any): Promise<{ text: string; details: Record<string, unknown> }> {
	const action = params.action;
	const entries = await readAuthorized();
	if (action === "list") return { text: entries.length ? `授权白名单 ${entries.length} 条：\n${JSON.stringify(entries, null, 2)}` : "授权白名单为空。", details: { count: entries.length, entries } };
	if (action === "add") {
		const ip = String(params.ip ?? "").trim();
		const port = String(params.port ?? "").trim();
		if (!ip || !port) throw new Error("authorized.add 需要 ip 和 port。");
		const key = `${ip}:${port}`;
		const entry: Authorized = { key, note: String(params.note ?? "").trim().slice(0, 500), created_at: now() };
		const next = [...entries.filter((item) => item.key !== key), entry];
		await writeAuthorized(next);
		return { text: `已本地标记授权资产 ${key}。本扩展不进行探测或 EXP 验证。`, details: { count: next.length, entry } };
	}
	if (action === "remove") {
		const key = String(params.key ?? "").trim();
		if (!key) throw new Error("authorized.remove 需要 key（ip:port）。");
		const next = entries.filter((item) => item.key !== key);
		await writeAuthorized(next);
		return { text: `已移除本地授权标记 ${key}。`, details: { count: next.length, key } };
	}
	throw new Error("action 必须是 list/add/remove。");
}

async function listHistory(limit: number): Promise<{ text: string; details: Record<string, unknown> }> {
	let lines: string[];
	try { lines = (await fsp.readFile(HISTORY_FILE, "utf8")).trim().split("\n").filter(Boolean); }
	catch (error: any) { if (error?.code === "ENOENT") return { text: "暂无本地查询历史。", details: { count: 0, entries: [] } }; throw error; }
	const entries = lines.slice(-limit).reverse().flatMap((line) => { try { return [JSON.parse(line)]; } catch { return []; } });
	return { text: `查询历史 ${entries.length}/${lines.length} 条：\n${preview(entries, HISTORY_FILE)}`, details: { count: entries.length, entries, historyPath: HISTORY_FILE } };
}

async function settingsSummary(): Promise<string> {
	const config = await readKeys();
	const state = (platform: Platform) => {
		const value = String(config[platform] ?? "").trim();
		return value ? `已配置 ${keyTail(value)}` : "未配置";
	};
	return `dsh-hunter 设置（只读）：\n- FOFA: ${state("fofa")}\n- Hunter: ${state("hunter")}\n- Quake: ${state("quake")}\n- FOFA email: ${config.fofa_email ? "已配置" : "未配置"}\n- FOFA username: ${config.fofa_username ? "已配置" : "未配置"}\n配置来源仅为 ${KEYS_FILE}；/hunter 不写入 key。`;
}

export default async function dshHunter(pi: ExtensionAPI) {
	// Read only the authoritative keys file at extension load. Adding a non-empty platform key
	// and running /reload enables that platform's tool without changing source code.
	const startupConfig = await readKeys();
	const hunterEnabled = Boolean(String(startupConfig.hunter ?? "").trim());
	const quakeEnabled = Boolean(String(startupConfig.quake ?? "").trim());
	pi.on("session_start", async () => { await ensureState(); });

	pi.registerTool({
		name: "fofa_search", label: "FOFA passive search",
		description: "Search FOFA's passive internet-asset index. One serial API page only; no probing, scanning, or EXP validation. Use next from the previous result for cursor pagination. The default field set is restricted to verified free-account fields; output is truncated and full JSON is saved locally.",
		parameters: FofaParams,
		async execute(_id, params) { const result = await runFofa(params); return { content: [{ type: "text", text: result.text }], details: result.details }; },
	});
	// Hunter/Quake adapters remain for source compatibility but stay out of the model tool
	// list until their key is non-empty at extension load. Add the key then run /reload.
	if (hunterEnabled) {
		pi.registerTool({
			name: "hunter_search", label: "Hunter passive search",
			description: "Search QiAnXin Hunter's passive internet-asset index. One serial API page only; no probing, scanning, or EXP validation. Use next.page from the result for pagination. Output is truncated and full JSON is saved locally.",
			parameters: HunterParams,
			async execute(_id, params) { const result = await runHunter(params); return { content: [{ type: "text", text: result.text }], details: result.details }; },
		});
	}
	if (quakeEnabled) {
		pi.registerTool({
			name: "quake_search", label: "Quake passive search",
			description: "Search 360 Quake's passive internet-asset index. One serial API page only; no probing, scanning, or EXP validation. Use next.start from the result for pagination. Output is truncated and full JSON is saved locally.",
			parameters: QuakeParams,
			async execute(_id, params) { const result = await runQuake(params); return { content: [{ type: "text", text: result.text }], details: result.details }; },
		});
	}
	pi.registerTool({
		name: "fofa_account_status", label: "FOFA account status",
		description: "Validate locally configured FOFA key/email through FOFA's account endpoint and report whether the account is free (fcoin=0). Never exposes the key or email.",
		parameters: AccountParams,
		async execute() { const result = await accountStatus(); return { content: [{ type: "text", text: result.text }], details: result.details }; },
	});
	pi.registerCommand("hunter", {
		description: "Browse dsh-hunter settings/history/authorization; key configuration stays read-only.",
		handler: async (args, ctx: ExtensionContext) => {
			const [action = "settings", subaction, first, ...rest] = args.trim().split(/\s+/).filter(Boolean);
			let text: string;
			if (action === "settings" || action === "status") text = await settingsSummary();
			else if (action === "history") text = (await listHistory(20)).text;
			else if (action === "authorized") text = (await manageAuthorized({ action: "list" })).text;
			else if (action === "authorize" && subaction === "add") text = (await manageAuthorized({ action: "add", ip: first, port: rest[0], note: rest.slice(1).join(" ") })).text;
			else if (action === "authorize" && subaction === "remove") text = (await manageAuthorized({ action: "remove", key: first })).text;
			else text = "用法：/hunter [settings|status|history|authorized|authorize add <ip> <port> [note]|authorize remove <ip:port>]";
			if (ctx.hasUI) ctx.ui.notify(text, "info");
		},
	});
}
