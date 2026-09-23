/**
 * dsh-campaign-memory → Pi extension（战役记忆）
 *
 * 源：~/.pi/agent/redteam-model/plugins/dsh-campaign-memory/{README.md,lib/store.js,lib/index.js}（只读，未修改）
 * 去重键 / 热度计分 / 衰减公式 / 清理周期全部照搬原实现（数值见下方常量区与 PORT 报告）。
 *
 * 与 DSH 宿主的差异（Pi 侧）：
 *  - 状态目录 ~/.pi/redteam/dsh-campaign-memory/（不用 ~/.dsh/）
 *  - Pi 无 agentPresets：mode 由 /campaign-mode 命令（按工作区记忆）+ CAMPAIGN_MEMORY_MODE 环境变量 + 工具可选 mode 参数解析
 *  - 召回注入走 before_agent_start 的 systemPromptOptions.sections（Pi 渲染为 <dsh-campaign-memory> 标签块）
 *  - 原 HTTP 通道 memory.stats / memory.purge 提升为模型工具 campaign_memory_stats / campaign_memory_purge；Web 标签页不做（约定 6）
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { DatabaseSync } from "node:sqlite";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/* ============================ 常量（照搬原实现） ============================ */

export const MEMORY_KINDS = ["tactic", "fingerprint", "tooling", "lesson", "detect"];
const KIND_LABELS: Record<string, string> = {
	tactic: "战术打法", fingerprint: "目标指纹", tooling: "工具可用性", lesson: "教训", detect: "检测指纹",
};
export function kindLabel(kind: string): string { return KIND_LABELS[kind] || "战术打法"; }

const DETECT_DEFAULT_DAYS = 30;            // 检测指纹默认 30 天过期并自动清理（免杀情报半衰期）
const FINGERPRINT_DEFAULT_DAYS = 180;      // 目标指纹默认 180 天：到期退出自动召回、检索仍可命中带过期标记
const HALF_LIFE_DAYS = 30;                 // 热度时间衰减半衰期（天）
export const MAX_ROWS_PER_WORKSPACE = 400; // 单工作区（mode × workspace）上限，超限按热度×半衰最冷淘汰（归档可恢复）
const MAX_CONTENT_CHARS = 4000;            // 正文上限，超出显式截断（返回 truncated，不静默腰斩）
const INJECT_BUDGET = 700;                 // 注入块字符预算
const INJECT_TOP_ROWS = 3;                 // 注入条数
const INJECT_TAG = "dsh-campaign-memory";
/** 工具返回体字符预算：超出写全文文件并告知路径（约定 5） */
const TOOL_TEXT_BUDGET = 9000;

export const MODE_IDS = ["redteam", "pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver", "asset-mapping"];
export const MODE_LABELS: Record<string, string> = {
	redteam: "安全研究员", pentest: "渗透测试", "code-audit": "代码审计", "binary-analysis": "二进制分析",
	"attack-defense": "攻防评估", "av-evasion": "免杀对抗", "incident-response": "应急溯源",
	"cloud-security": "云安全攻防", "ctf-solver": "CTF 解题", "asset-mapping": "资产测绘",
};

/* ============================ 数据层（store.js 逐条移植） ============================ */

type Row = Record<string, any>;
interface Store { db: DatabaseSync; fts: boolean; close(): void }

/** 热度评分（排序用）：usage+1 为基数，按最后使用距今 HALF_LIFE_DAYS=30 天半衰
 *  ——pow(0.5, days/30)；读取（get）刷新 last_used 即复活。 */
const HOTNESS_ORDER = `ORDER BY (usage_count + 1.0) * pow(0.5, (julianday('now') - julianday(COALESCE(NULLIF(last_used_at, ''), created_at))) / ${HALF_LIFE_DAYS}.0) DESC, last_used_at DESC, created_at DESC`;
/** 冷淘汰序：同一评分取最冷（与 HOTNESS_ORDER 同式反向）。 */
const COLD_ORDER = `ORDER BY (usage_count + 1.0) * pow(0.5, (julianday('now') - julianday(COALESCE(NULLIF(last_used_at, ''), created_at))) / ${HALF_LIFE_DAYS}.0) ASC, updated_at ASC, created_at ASC`;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS memories (
	id           TEXT PRIMARY KEY,
	mode         TEXT NOT NULL,
	kind         TEXT NOT NULL,
	title        TEXT NOT NULL,
	content      TEXT NOT NULL,
	tags         TEXT NOT NULL DEFAULT '',
	target_kind  TEXT NOT NULL DEFAULT '',
	workspace    TEXT NOT NULL DEFAULT '',
	workspace_key TEXT NOT NULL DEFAULT '',
	usage_count  INTEGER NOT NULL DEFAULT 0,
	last_used_at TEXT DEFAULT '',
	source_session TEXT NOT NULL DEFAULT '',
	expires_at   TEXT,
	created_at   TEXT NOT NULL,
	updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS memories_mode ON memories(mode);
CREATE INDEX IF NOT EXISTS memories_ws ON memories(mode, workspace_key);
CREATE TABLE IF NOT EXISTS memories_archive (
	id           TEXT PRIMARY KEY,
	mode         TEXT NOT NULL,
	kind         TEXT NOT NULL,
	title        TEXT NOT NULL,
	content      TEXT NOT NULL,
	tags         TEXT NOT NULL DEFAULT '',
	target_kind  TEXT NOT NULL DEFAULT '',
	workspace    TEXT NOT NULL DEFAULT '',
	workspace_key TEXT NOT NULL DEFAULT '',
	usage_count  INTEGER NOT NULL DEFAULT 0,
	last_used_at TEXT DEFAULT '',
	source_session TEXT NOT NULL DEFAULT '',
	expires_at   TEXT,
	created_at   TEXT NOT NULL,
	updated_at   TEXT NOT NULL,
	archived_at  TEXT NOT NULL
);
`;

const FTS_GENERATION = 1;
function setupFts(db: DatabaseSync): boolean {
	db.exec(`CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
	title, content, tags, content='memories', content_rowid='rowid', tokenize='trigram')`);
	db.exec(`CREATE TRIGGER IF NOT EXISTS memories_fts_ai AFTER INSERT ON memories BEGIN
	INSERT INTO memories_fts(rowid, title, content, tags) VALUES (new.rowid, new.title, new.content, new.tags); END`);
	db.exec(`CREATE TRIGGER IF NOT EXISTS memories_fts_ad AFTER DELETE ON memories BEGIN
	INSERT INTO memories_fts(memories_fts, rowid, title, content, tags) VALUES ('delete', old.rowid, old.title, old.content, old.tags); END`);
	db.exec(`CREATE TRIGGER IF NOT EXISTS memories_fts_au AFTER UPDATE ON memories BEGIN
	INSERT INTO memories_fts(memories_fts, rowid, title, content, tags) VALUES ('delete', old.rowid, old.title, old.content, old.tags);
	INSERT INTO memories_fts(rowid, title, content, tags) VALUES (new.rowid, new.title, new.content, new.tags); END`);
	const v = db.prepare("PRAGMA user_version").get() as Row | undefined;
	if ((v as any)?.user_version !== FTS_GENERATION) {
		db.exec("INSERT INTO memories_fts(memories_fts) VALUES ('rebuild')");
		db.exec(`PRAGMA user_version = ${FTS_GENERATION}`);
	}
	return true;
}

function now(): string { return new Date().toISOString().replace("T", " ").slice(0, 19); }
function clean(s: unknown, max: number): string { return String(s ?? "").trim().slice(0, max); }

export function openStore(dbPath: string): Store {
	if (dbPath !== ":memory:") fs.mkdirSync(path.dirname(dbPath), { recursive: true });
	const db = new DatabaseSync(dbPath);
	db.exec("PRAGMA journal_mode = WAL");
	db.exec("PRAGMA busy_timeout = 5000"); // 多进程并发写不直接抛 SQLITE_BUSY
	db.exec(SCHEMA);
	try { db.exec("ALTER TABLE memories ADD COLUMN workspace TEXT NOT NULL DEFAULT ''"); } catch { /* 旧库已迁移 */ }
	try { db.exec("ALTER TABLE memories ADD COLUMN workspace_key TEXT NOT NULL DEFAULT ''"); } catch { /* 旧库已迁移 */ }
	let fts = false;
	try { fts = setupFts(db); } catch { /* 构建缺 FTS5：检索回落 LIKE */ }
	purgeExpired({ db } as Store); // 开库即清过期：免杀指纹等时效记忆不滞留
	return { db, fts, close() { db.close(); } };
}

function expiry(kind: string, days: unknown): string | null {
	const d = Number(days);
	if (Number.isFinite(d) && d > 0) return new Date(Date.now() + d * 86400_000).toISOString().replace("T", " ").slice(0, 19);
	if (kind === "detect") return expiry(kind, DETECT_DEFAULT_DAYS);
	if (kind === "fingerprint") return expiry(kind, FINGERPRINT_DEFAULT_DAYS);
	return null;
}

/** 标题归一（去空白+小写）：同题判定的比较基准。 */
function normTitle(t: unknown): string { return String(t ?? "").trim().toLowerCase().replace(/\s+/g, ""); }

export interface WriteInput {
	mode: string; kind: string; title: string; content: string;
	tags?: string; target_kind?: string; expires_days?: number;
	source_session?: string; workspace?: string; workspace_key?: string;
}

/** 写入一条战役记忆（原文入库不脱敏）。去重键 = mode + workspace(basename) + normTitle + target_kind + workspace_key：
 *  命中即刷新既有行（正文/类别/时效更新、热度与 created_at 保留），并带回执（原正文字数+开头预览）。
 *  超 4000 字符显式截断；工作区超 400 条按热度×半衰最冷淘汰（先归档 memories_archive 再删）。 */
export function writeMemory(st: Store, input: WriteInput) {
	const m = clean(input.mode, 40), k = MEMORY_KINDS.includes(input.kind) ? input.kind : "tactic";
	const t = clean(input.title, 80);
	if (!m || !t) throw new Error("mode/title 必填");
	const raw = String(input.content ?? "").trim();
	const c = raw.slice(0, MAX_CONTENT_CHARS);
	if (!c) throw new Error("content 必填");
	const truncated = raw.length > MAX_CONTENT_CHARS;
	const ws = clean(input.workspace, 60);
	const wk = clean(input.workspace_key, 80);
	const exp = expiry(k, input.expires_days);
	const nt = normTitle(t);
	const tk = clean(input.target_kind, 40);
	// 同题判定带 target_kind 维度：同题同目标形态才刷新——跨平台同名题不互覆
	const rows = st.db.prepare("SELECT id, title, content, workspace_key, target_kind FROM memories WHERE mode = ? AND workspace = ?").all(m, ws) as Row[];
	const prev = rows.find((r) => normTitle(r.title) === nt && String(r.target_kind || "") === tk && (wk ? r.workspace_key === wk : r.workspace_key === ""));
	if (prev) {
		st.db.prepare("UPDATE memories SET kind = ?, title = ?, content = ?, tags = ?, target_kind = ?, expires_at = ?, source_session = ?, workspace_key = ?, updated_at = ? WHERE id = ?")
			.run(k, t, c, clean(input.tags, 200), tk, exp, clean(input.source_session, 80), wk, now(), prev.id);
		return {
			id: String(prev.id), mode: m, kind: k, workspace: ws, expires_at: exp, refreshed: true, evicted: 0, truncated,
			chars: c.length, prev: { chars: String(prev.content ?? "").length, preview: String(prev.content ?? "").slice(0, 60) },
		};
	}
	const id = "cm-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
	st.db.prepare("INSERT INTO memories (id, mode, kind, title, content, tags, target_kind, workspace, workspace_key, usage_count, last_used_at, source_session, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?, ?, ?)")
		.run(id, m, k, t, c, clean(input.tags, 200), tk, ws, wk, clean(input.source_session, 80), exp, now(), now());
	let evicted = 0;
	const total = (st.db.prepare("SELECT COUNT(*) AS n FROM memories WHERE mode = ? AND workspace = ?").get(m, ws) as Row).n as number;
	if (total > MAX_ROWS_PER_WORKSPACE) {
		const keyCond = wk ? "workspace_key = ?" : "workspace_key = ''";
		const coldArgs = wk ? [m, ws, wk, id, total - MAX_ROWS_PER_WORKSPACE] : [m, ws, id, total - MAX_ROWS_PER_WORKSPACE];
		const cold = st.db.prepare(`SELECT id FROM memories WHERE mode = ? AND workspace = ? AND ${keyCond} AND id != ? ${COLD_ORDER} LIMIT ?`).all(...coldArgs) as Row[];
		for (const row of cold) {
			st.db.prepare(`INSERT OR REPLACE INTO memories_archive (id, mode, kind, title, content, tags, target_kind, workspace, workspace_key, usage_count, last_used_at, source_session, expires_at, created_at, updated_at, archived_at)
				SELECT id, mode, kind, title, content, tags, target_kind, workspace, workspace_key, usage_count, last_used_at, source_session, expires_at, created_at, updated_at, ? FROM memories WHERE id = ?`).run(now(), row.id);
			st.db.prepare("DELETE FROM memories WHERE id = ?").run(row.id);
			evicted += 1;
		}
	}
	return { id, mode: m, kind: k, workspace: ws, expires_at: exp, refreshed: false, evicted, truncated, chars: c.length };
}

function rowOut(r: Row) {
	const expired = !!(r.expires_at && String(r.expires_at) <= now());
	return { ...r, usageCount: r.usage_count, lastUsedAt: r.last_used_at, sourceSession: r.source_session, targetKind: r.target_kind, expired };
}
type OutRow = ReturnType<typeof rowOut>;

const SELECT = "SELECT id, mode, kind, title, content, tags, target_kind, workspace, usage_count, last_used_at, source_session, expires_at, created_at, updated_at FROM memories";

function notExpired(expr = ""): string {
	return ` expires_at IS NULL OR expires_at > datetime('now') ${expr ? "AND " + expr : ""}`;
}

/** 正文预览：超上限截断加省略号（检索/list 行级 token 收敛）；截点不劈代理对。 */
function preview(text: unknown, max: number): string {
	const t = String(text ?? "");
	if (t.length <= max) return t;
	let cut = t.slice(0, max);
	if (/[\uD800-\uDBFF]$/.test(cut)) cut = cut.slice(0, -1);
	return cut + "…（全文经 campaign_memory_get 按需读取）";
}

/** 检索（FTS5 trigram 主路 + LIKE 回落），不记账——读全文（getMemory）才计。
 *  排序 = 热度×30 天半衰 / (1 + bm25)：词法更贴者排前、久未读取自然让位。
 *  过期记忆不召回，唯一例外 fingerprint（带 expired 标记 + 复活指引）。 */
export function searchMemories(st: Store, opts: { mode: string; query?: string; kind?: string; target_kind?: string; limit?: number }) {
	const m = clean(opts.mode, 40);
	if (!m) throw new Error("mode required");
	const q = clean(opts.query, 120);
	const lim = Math.min(Math.max(Number(opts.limit) || 8, 1), 20);
	const toks = q ? q.split(/\s+/).map((t) => t.replace(/"/g, "").trim()).filter(Boolean) : [];
	const ftsToks = toks.filter((t) => t.length >= 3);
	const shortToks = toks.filter((t) => t.length < 3);
	const kindCond = !!opts.kind && MEMORY_KINDS.includes(opts.kind);
	const tk = clean(opts.target_kind, 40);
	let rows: Row[];
	if (st.fts && ftsToks.length > 0) {
		const match = ftsToks.map((t) => `"${t}"`).join(" OR ");
		const conds = ["m.mode = ?", "(m.expires_at IS NULL OR m.expires_at > datetime('now') OR m.kind = 'fingerprint')", "memories_fts MATCH ?"];
		const args: any[] = [m, match];
		if (kindCond) { conds.push("m.kind = ?"); args.push(opts.kind); }
		if (tk) { conds.push("m.target_kind = ?"); args.push(tk); }
		rows = st.db.prepare(`SELECT m.id, m.mode, m.kind, m.title, m.content, m.tags, m.target_kind, m.workspace, m.usage_count, m.last_used_at, m.source_session, m.expires_at, m.created_at, m.updated_at,
			snippet(memories_fts, 1, '»', '«', '…', 120) AS snip, bm25(memories_fts) AS rel
			FROM memories m JOIN memories_fts ON memories_fts.rowid = m.rowid
			WHERE ${conds.join(" AND ")}
			ORDER BY ((m.usage_count + 1.0) * pow(0.5, (julianday('now') - julianday(COALESCE(NULLIF(m.last_used_at, ''), m.created_at))) / ${HALF_LIFE_DAYS}.0)) / (1.0 + COALESCE(bm25(memories_fts), 12.0)) DESC, m.last_used_at DESC, m.created_at DESC
			LIMIT ?`).all(...args, lim) as Row[];
		if (shortToks.length) {
			const likeConds = shortToks.map(() => "(title LIKE ? OR content LIKE ? OR tags LIKE ?)").join(" OR ");
			const likeArgs = shortToks.flatMap((t) => [`%${t}%`, `%${t}%`, `%${t}%`]);
			const c2 = ["mode = ?", "(expires_at IS NULL OR expires_at > datetime('now') OR kind = 'fingerprint')", `(${likeConds})`];
			const a2: any[] = [m, ...likeArgs];
			if (kindCond) { c2.push("kind = ?"); a2.push(opts.kind); }
			if (tk) { c2.push("target_kind = ?"); a2.push(tk); }
			const likeRows = st.db.prepare(`${SELECT} WHERE ${c2.join(" AND ")} ${HOTNESS_ORDER} LIMIT ?`).all(...a2, lim) as Row[];
			const seen = new Set(rows.map((r) => r.id));
			for (const r of likeRows) if (!seen.has(r.id)) rows.push(r);
			rows = rows.slice(0, lim);
		}
	} else {
		const conds = ["mode = ?", "(expires_at IS NULL OR expires_at > datetime('now') OR kind = 'fingerprint')"];
		const args: any[] = [m];
		if (q) { conds.push("(title LIKE ? OR content LIKE ? OR tags LIKE ?)"); args.push(`%${q}%`, `%${q}%`, `%${q}%`); }
		if (kindCond) { conds.push("kind = ?"); args.push(opts.kind); }
		if (tk) { conds.push("target_kind = ?"); args.push(tk); }
		rows = st.db.prepare(`${SELECT} WHERE ${conds.join(" AND ")} ${HOTNESS_ORDER} LIMIT ?`).all(...args, lim) as Row[];
	}
	return rows.map(({ snip: _snip, rel: _rel, ...r }) => {
		const body = (typeof _snip === "string" && _snip !== "") ? _snip : r.content;
		const out = rowOut({ ...r, content: preview(body, 600) });
		if (out.expired) out.content = "[已过期——适用性自判；重新验证后同题 campaign_memory_write 刷新] " + out.content;
		return out;
	}) as OutRow[];
}

/** 召回注入候选（纯读、不记账）：仅本工作区、未过期，按热度×半衰取前 N。
 *  wk=隔离键（basename@路径哈希 8 位）：按键精确隔离；缺省走旧 basename 语义（仅匹配无键行）。 */
export function topForInjection(st: Store, mode: string, workspace: string, n = 3, wk = ""): OutRow[] {
	const rows = wk
		? st.db.prepare(`${SELECT} WHERE mode = ? AND workspace_key = ? AND (${notExpired()}) ${HOTNESS_ORDER} LIMIT ?`).all(clean(mode, 40), clean(wk, 80), n)
		: st.db.prepare(`${SELECT} WHERE mode = ? AND workspace = ? AND workspace_key = '' AND (${notExpired()}) ${HOTNESS_ORDER} LIMIT ?`).all(clean(mode, 40), clean(workspace, 60), n);
	return (rows as Row[]).map(rowOut);
}

/** 清单（收口复盘/治理用）：行数钳制（默认 50、上限 200），正文预览 200。 */
export function listMemories(st: Store, opts: { mode: string; kind?: string; includeExpired?: boolean; limit?: number }): OutRow[] {
	const m = clean(opts.mode, 40);
	if (!m) throw new Error("mode required");
	const conds = ["mode = ?"];
	const args: any[] = [m];
	if (!opts.includeExpired) conds.push("(" + notExpired() + ")");
	if (opts.kind && MEMORY_KINDS.includes(opts.kind)) { conds.push("kind = ?"); args.push(opts.kind); }
	return (st.db.prepare(`${SELECT} WHERE ${conds.join(" AND ")} ${HOTNESS_ORDER} LIMIT ?`).all(...args, Math.min(Math.max(Number(opts.limit) || 50, 1), 200)) as Row[])
		.map((r) => rowOut({ ...r, content: preview(r.content, 200) }));
}

/** 读取全文=真实使用：记账（usage+1 / last_used 刷新）——热度与半衰排序的唯一驱动。
 *  account:false 供纯浏览（查看不是采用，不推高召回排名）。 */
export function getMemory(st: Store, id: string, opts: { account?: boolean } = {}) {
	const i = String(id ?? "");
	if (opts.account !== false) st.db.prepare("UPDATE memories SET usage_count = usage_count + 1, last_used_at = ? WHERE id = ?").run(now(), i);
	const r = st.db.prepare(`${SELECT} WHERE id = ?`).get(i) as Row | undefined;
	return r ? rowOut(r) : undefined;
}

export function removeMemory(st: Store, id: string) {
	const r = st.db.prepare("DELETE FROM memories WHERE id = ?").run(String(id ?? ""));
	if ((r as any).changes === 0) throw new Error(`记忆不存在：${id}`);
	return { removed: String(id) };
}

export function statsMemories(st: Store, mode: string) {
	const m = clean(mode, 40);
	if (!m) throw new Error("mode required");
	const rows = st.db.prepare("SELECT kind, expires_at FROM memories WHERE mode = ?").all(m) as Row[];
	const byKind: Record<string, number> = {};
	for (const k of MEMORY_KINDS) byKind[k] = 0;
	let expired = 0;
	for (const r of rows) {
		byKind[r.kind] = (byKind[r.kind] ?? 0) + 1;
		if (r.expires_at && String(r.expires_at) <= now()) expired += 1;
	}
	return { total: rows.length, byKind, expired };
}

/** 清理只删过期的检测指纹（免杀情报半衰期已过）；fingerprint 等其余到期行退出召回但保留资产。 */
export function purgeExpired(st: Store) {
	const r = st.db.prepare("DELETE FROM memories WHERE kind = 'detect' AND expires_at IS NOT NULL AND expires_at <= datetime('now')").run();
	return { purged: (r as any).changes };
}

/* ============================ 注入块（index.js buildMemoryBlock 移植） ============================ */

/** 装配期召回块（完整标签版，供 /campaign-memory peek 与测试）：标记化、预算内（超限先减记忆行）。 */
export function buildMemoryBlock(mode: string, workspace: string, rows: OutRow[]): string {
	if (!rows || rows.length === 0) return "";
	const close = `</${INJECT_TAG}>`;
	const guide = "沉淀/检索：有效打法即时 campaign_memory_write 记忆（正文原样入库不脱敏——凭据可入库或只写指位指向本地凭据库）；开战/接案或换目标类型先 campaign_memory_search 检索。";
	const build = (kept: OutRow[]) => {
		const kinds = [...new Set(kept.map((r) => r.targetKind).filter(Boolean))];
		const topicLine = kinds.length > 1 ? `本工作区记忆含多目标（${kinds.slice(0, 4).join("/")}${kinds.length > 4 ? " 等" : ""}）——适用性按目标自判，检索可加 target_kind 过滤。` : "";
		return [
			`<${INJECT_TAG} mode="${mode}" workspace="${workspace}" n="${kept.length}">`,
			"本工作区战役记忆（历史战役沉淀；适用性自判——目标环境可能已变化）：",
			...kept.map((r, i) => `${i + 1}. [${kindLabel(r.kind)}${r.targetKind ? "·" + r.targetKind : ""}] ${r.title}——${String(r.content).split("\n")[0].slice(0, 160)}`),
			...(topicLine ? [topicLine] : []),
			guide,
		].join("\n") + "\n" + close;
	};
	return fitBudget(mode, workspace, rows, build, close);
}

/** Pi 注入版：Pi 的 sections 渲染已自带 <tag>…</tag>，这里给块内文（mode/workspace/n 属性写入首行）。 */
export function buildMemorySection(mode: string, workspace: string, rows: OutRow[]): string {
	if (!rows || rows.length === 0) return "";
	const guide = "沉淀/检索：有效打法即时 campaign_memory_write 记忆（正文原样入库不脱敏——凭据可入库或只写指位指向本地凭据库）；开战/接案或换目标类型先 campaign_memory_search 检索。";
	const build = (kept: OutRow[]) => {
		const kinds = [...new Set(kept.map((r) => r.targetKind).filter(Boolean))];
		const topicLine = kinds.length > 1 ? `本工作区记忆含多目标（${kinds.slice(0, 4).join("/")}${kinds.length > 4 ? " 等" : ""}）——适用性按目标自判，检索可加 target_kind 过滤。` : "";
		return [
			`本工作区战役记忆 mode="${mode}" workspace="${workspace}" n="${kept.length}"（历史战役沉淀；适用性自判——目标环境可能已变化）：`,
			...kept.map((r, i) => `${i + 1}. [${kindLabel(r.kind)}${r.targetKind ? "·" + r.targetKind : ""}] ${r.title}——${String(r.content).split("\n")[0].slice(0, 160)}`),
			...(topicLine ? [topicLine] : []),
			guide,
		].join("\n");
	};
	return fitBudget(mode, workspace, rows, build);
}

/** 预算收敛（两版共用）：超限先减记忆行（数据让位、指引行最后丢），最后硬截到预算内（保留闭合标签）。 */
function fitBudget(mode: string, workspace: string, rows: OutRow[], build: (kept: OutRow[]) => string, closeTag = ""): string {
	const budget = INJECT_BUDGET - closeTag.length;
	let kept = rows.slice();
	let text = build(kept);
	while (kept.length > 0 && text.length > budget) {
		kept = kept.slice(0, -1);
		text = build(kept);
	}
	if (text.length > budget) text = text.slice(0, Math.max(0, budget - 1)) + "…";
	return text + closeTag;
}

/* ============================ 宿主状态（mode / 工作区 / 路径） ============================ */

const DATA_DIR = path.join(os.homedir(), ".pi", "redteam", "dsh-campaign-memory");
const DB_PATH = path.join(DATA_DIR, "memory.db");
const STATE_PATH = path.join(DATA_DIR, "state.json");
const EXPORT_DIR = path.join(DATA_DIR, "exports");

interface State { defaultMode?: string; workspaces?: Record<string, { mode?: string }> }
function readState(): State {
	try { return JSON.parse(fs.readFileSync(STATE_PATH, "utf8")) as State; } catch { return {}; }
}
function writeState(s: State) {
	fs.mkdirSync(DATA_DIR, { recursive: true });
	fs.writeFileSync(STATE_PATH, JSON.stringify(s, null, "\t"));
}

/** 工作区标识：name=目录 basename，key=basename@全路径 sha256 前 8 位（同名目录不串场、移动目录=新 key 干净开局）。 */
function workspaceOf(cwd: string | undefined) {
	if (typeof cwd !== "string" || !cwd) return { name: "", key: "" };
	const base = path.basename(cwd).slice(0, 60);
	return { name: base, key: base + "@" + crypto.createHash("sha256").update(cwd).digest("hex").slice(0, 8) };
}

/** mode 解析优先级：显式参数 > CAMPAIGN_MEMORY_MODE 环境变量 > 本工作区记忆（/campaign-mode 设定） > state.defaultMode。 */
function resolveMode(ctx: ExtensionContext | undefined, explicit?: string): string {
	const e = clean(explicit, 40);
	if (e && MODE_IDS.includes(e)) return e;
	const env = clean(process.env.CAMPAIGN_MEMORY_MODE, 40);
	if (env && MODE_IDS.includes(env)) return env;
	const st = readState();
	const wsKey = workspaceOf(ctx?.cwd).key;
	const per = clean(st.workspaces?.[wsKey]?.mode, 40);
	if (per && MODE_IDS.includes(per)) return per;
	const d = clean(st.defaultMode, 40);
	return MODE_IDS.includes(d) ? d : "";
}

let store: Store | undefined;
function theStore(): Store {
	if (store === undefined) store = openStore(DB_PATH);
	return store;
}
function closeStore() {
	if (!store) return;
	try { store.close(); } catch { /* 已关闭 */ }
	store = undefined;
}

function noModeText(mode: string) {
	return `仅安全模式会话内可用（当前 mode="${mode || "未设置"}"）：先 /campaign-mode <${MODE_IDS.join("|")}> 设定本工作区模式，或给工具传 mode`;
}

/** 大输出裁剪：超出预算写全文文件并告知路径（约定 5）。 */
function clipWithFile(text: string, label: string, max = TOOL_TEXT_BUDGET): string {
	if (text.length <= max) return text;
	fs.mkdirSync(EXPORT_DIR, { recursive: true });
	const file = path.join(EXPORT_DIR, `${label}-${new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19)}.txt`);
	fs.writeFileSync(file, text, "utf8");
	const cut = text.slice(0, max);
	return `${cut}\n\n[输出已截断：${text.length} 字符仅显示前 ${max} 字符，全文见 ${file}]`;
}

function metaLine(r: OutRow): string {
	return [
		r.id,
		`[${kindLabel(String(r.kind))}${r.targetKind ? "·" + r.targetKind : ""}]`,
		r.workspace ? `@${r.workspace}` : "",
		r.tags ? `tags=${r.tags}` : "",
		`热度 ${r.usageCount}`,
		r.lastUsedAt ? `近用 ${String(r.lastUsedAt).slice(0, 16)}` : "未用过",
		r.expires_at ? (r.expired ? `已过期(${String(r.expires_at).slice(0, 16)})` : `${String(r.expires_at).slice(0, 16)} 过期`) : "永久",
	].filter(Boolean).join(" · ");
}

function rowsToText(rows: OutRow[], header: string): string {
	if (rows.length === 0) return `${header}\n（无命中——该方向尚无历史沉淀）`;
	const lines = rows.map((r, i) => `${i + 1}. ${metaLine(r)}\n   ${r.title}\n   ${String(r.content).replace(/\n/g, "\n   ")}`);
	return clipWithFile(`${header}\n${lines.join("\n")}`, "search");
}

/* ============================ 参数 schema（不使用 minimum/maximum，钳制在代码里做） ============================ */

const kindSchema = () => Type.Union(MEMORY_KINDS.map((k) => Type.Literal(k)), { description: "记忆类别" });
const modeParam = Type.Optional(Type.String({ description: `战役模式（省略=会话模式；${MODE_IDS.join("/")}）` }));

export default function (pi: ExtensionAPI) {
	/* ---------- 生命周期：session_start 建/开库（开库即清理），session_shutdown 幂等关闭 ---------- */
	pi.on("session_start", async (_event, ctx) => {
		const st = theStore();
		const mode = resolveMode(ctx);
		const ws = workspaceOf(ctx.cwd);
		const stats = mode ? statsMemories(st, mode) : null;
		if (ctx.hasUI) {
			ctx.ui.notify(
				`战役记忆已就绪 ${mode ? `（模式 ${MODE_LABELS[mode] || mode} @${ws.name}）` : "（模式未设置，/campaign-mode 设定）"}`
				+ (stats ? ` · 本模式 ${stats.total} 条 / 已过期 ${stats.expired}` : ""),
				"info",
			);
		}
	});
	pi.on("session_shutdown", async () => { closeStore(); });

	/* ---------- 装配期召回注入：before_agent_start 改 systemPromptOptions.sections ---------- */
	pi.on("before_agent_start", async (event, ctx) => {
		const mode = resolveMode(ctx);
		if (!mode) return;
		try {
			const ws = workspaceOf(ctx.cwd);
			const section = buildMemorySection(mode, ws.name, topForInjection(theStore(), mode, ws.name, INJECT_TOP_ROWS, ws.key));
			if (section === "") return;
			event.systemPromptOptions.sections = { ...(event.systemPromptOptions.sections ?? {}), [INJECT_TAG]: section };
		} catch { /* 记忆库不可用不影响本轮 */ }
	});

	/* ---------- 模型工具（名称与原实现一致） ---------- */
	pi.registerTool({
		name: "campaign_memory_write",
		label: "campaign memory write",
		description: "把本次战役中验证有效的打法/目标指纹/工具可用性/教训/检测指纹沉淀为战役记忆（跨会话长期复用）。存储原文不做脱敏——内网地址/指纹细节/凭据均原样入库（记忆库是本地库）；已有独立凭据库（hunter key 库/webshell 连接库等）时也可只写指位。正文建议四段结构：命中条件/打法步骤/关键参数/验证结果；超 4000 字符会截断（返回 truncated 提示）。同模式同工作区同题（+同 target_kind）写入=刷新既有记忆（正文与时效更新、热度保留，不产生重复；刷新带回执：原正文字数与开头预览，非同题误合并可察觉）。kind：tactic 战术打法 / fingerprint 目标指纹（默认 180 天时效，到期退出自动召回、检索仍可命中带过期标记，同题重写即刷新）/ tooling 工具可用性 / lesson 教训 / detect 检测指纹（默认 30 天过期并清理，可 expires_days 覆盖）。战役记忆只进本工具，用户偏好/环境事实等通用记忆走 pi-memory（MEMORY.md/daily）。同模式同工作区上限 400 条，超限冷淘汰（归档可恢复）；同目录多目标以 target_kind 填目标标识（厂商名/样本哈希前 8 位/平台名/案件号）。有效即可记，不必等收口。",
		promptSnippet: "沉淀跨会话战役打法/目标指纹/工具可用性/教训/检测指纹（同模式同工作区同题=刷新）",
		promptGuidelines: ["验证有效的打法、目标指纹、工具可用性结论、教训、检测指纹，随手 campaign_memory_write 沉淀（不必等收口）", "开战、接案或换目标类型先 campaign_memory_search 检索历史打法；读全文用 campaign_memory_get（读全文计热度）", "打法/指纹类经验只进战役记忆；用户偏好与环境事实走通用记忆（pi-memory），不要混写"],
		parameters: Type.Object({
			title: Type.String({ description: "一句话标题（如：XX 框架后台默认凭据直连）；同题同 target_kind 即刷新而非新增" }),
			content: Type.String({ description: "打法/事实正文（怎么做的、命中条件、关键参数、验证结果；原样入库不脱敏）" }),
			kind: kindSchema(),
			tags: Type.Optional(Type.String({ description: "检索标签（逗号分隔，如：java,后台,弱口令）" })),
			target_kind: Type.Optional(Type.String({ description: "适用目标形态（web/api/域环境/家族名/案件号/平台名等）" })),
			expires_days: Type.Optional(Type.Number({ description: "有效期天数（省略时 detect=30 天、fingerprint=180 天，其余永久）" })),
			mode: modeParam,
		}),
		executionMode: "sequential",
		async execute(_id, args, _signal, _onUpdate, ctx) {
			const mode = resolveMode(ctx, args.mode);
			if (!mode) throw new Error(noModeText(mode));
			const ws = workspaceOf(ctx.cwd);
			const m = writeMemory(theStore(), {
				mode, kind: args.kind, title: args.title, content: args.content, tags: args.tags ?? "",
				target_kind: args.target_kind ?? "", expires_days: args.expires_days,
				source_session: String(ctx.sessionManager?.getSessionId?.() ?? ""), workspace: ws.name, workspace_key: ws.key,
			});
			const text = `记忆已${m.refreshed ? "刷新" : "沉淀"}：${m.id}（${kindLabel(m.kind)} · @${m.workspace || "-"} · ${m.chars} 字符）`
				+ (m.expires_at ? `（${m.expires_at} 过期）` : "（永久）")
				+ (m.refreshed && m.prev ? `（原正文 ${m.prev.chars} 字符→${m.chars} 字符，原开头是「${m.prev.preview}…」——非同题勿合并）` : "")
				+ (m.truncated ? "（正文超 4000 字符已截断——建议精简或同题拆卡）" : "")
				+ (m.evicted ? `（本工作区超上限，冷淘汰 ${m.evicted} 条，已归档可恢复）` : "");
			return { content: [{ type: "text", text }], details: m };
		},
	});

	pi.registerTool({
		name: "campaign_memory_search",
		label: "campaign memory search",
		description: "检索本模式战役记忆（开战或换目标类型时先查——历史打法可能直接给出可复用路径）。多关键词空格分词（任一命中即召回，词法更贴者排前）——换词多试几种表述可补召回；<3 字符短词走 LIKE 补位。按 bm25×热度混排（热度=使用频次×30 天时间衰减，久未读取自然让位、读全文即复活）；检索预览不记账，campaign_memory_get 读全文才记账。跨工作区检索：同模式全部工作区记忆都可命中，每行带 workspace 来源标注。已过期目标指纹仍可命中（带过期标记）。行内为命中窗摘录，全文经 campaign_memory_get 按需读取。返回为空说明该方向没有历史沉淀。",
		promptSnippet: "检索战役记忆（bm25×热度×30 天衰减混排，检索不记账）",
		parameters: Type.Object({
			query: Type.String({ description: "关键词（标题/正文/标签匹配，如：XX 云台 弱口令）" }),
			kind: Type.Optional(kindSchema()),
			target_kind: Type.Optional(Type.String({ description: "限定目标形态（可选）" })),
			limit: Type.Optional(Type.Number({ description: "返回条数（默认 8，上限 20）" })),
			mode: modeParam,
		}),
		executionMode: "sequential",
		async execute(_id, args, _signal, _onUpdate, ctx) {
			const mode = resolveMode(ctx, args.mode);
			if (!mode) throw new Error(noModeText(mode));
			const rows = searchMemories(theStore(), { mode, query: args.query, kind: args.kind, target_kind: args.target_kind, limit: args.limit });
			const text = rowsToText(rows, `命中 ${rows.length} 条战役记忆（mode=${mode}${args.kind ? " kind=" + args.kind : ""}；检索不记账，读全文 campaign_memory_get 计热度）`);
			return { content: [{ type: "text", text }], details: { mode, count: rows.length, memories: rows } };
		},
	});

	pi.registerTool({
		name: "campaign_memory_get",
		label: "campaign memory get",
		description: "读取一条战役记忆全文（检索/list 返回的是正文预览，需要完整打法细节时按 id 取全文）。读取即计入热度（usage/last_used 刷新）——驱动热度×30 天衰减排序，被采用的历史打法读完即复活。peek=true 为纯浏览不记账（查看不是采用）。",
		promptSnippet: "按 id 读战役记忆全文（读全文计热度）",
		parameters: Type.Object({
			id: Type.String({ description: "记忆 id（cm- 开头）" }),
			peek: Type.Optional(Type.Boolean({ description: "true=纯浏览不记账（默认 false=记账）" })),
		}),
		executionMode: "sequential",
		async execute(_id, args, _signal, _onUpdate, _ctx) {
			const m = getMemory(theStore(), args.id, { account: !args.peek });
			if (!m) throw new Error(`记忆不存在：${args.id}`);
			const text = clipWithFile(`记忆全文：${m.title}\n${metaLine(m)}\n\n${m.content}`, "get", 12000);
			return { content: [{ type: "text", text }], details: { memory: m } };
		},
	});

	pi.registerTool({
		name: "campaign_memory_list",
		label: "campaign memory list",
		description: "列出本模式当前有效战役记忆（收口复盘与记忆治理用；按热度×衰减排序取前列——默认 50 条、上限 200，需要更多用检索收窄；include_expired=true 查看已到期资产做取舍）。",
		promptSnippet: "列出本模式战役记忆（治理/复盘用）",
		parameters: Type.Object({
			kind: Type.Optional(kindSchema()),
			limit: Type.Optional(Type.Number({ description: "返回条数（默认 50，上限 200）" })),
			include_expired: Type.Optional(Type.Boolean({ description: "true=含已过期（默认 false）" })),
			mode: modeParam,
		}),
		executionMode: "sequential",
		async execute(_id, args, _signal, _onUpdate, ctx) {
			const mode = resolveMode(ctx, args.mode);
			if (!mode) throw new Error(noModeText(mode));
			const rows = listMemories(theStore(), { mode, kind: args.kind, includeExpired: !!args.include_expired, limit: args.limit });
			const text = rowsToText(rows, `本模式战役记忆 ${rows.length} 条（mode=${mode}${args.include_expired ? " · 含已过期" : ""}）`);
			return { content: [{ type: "text", text }], details: { mode, count: rows.length, memories: rows } };
		},
	});

	pi.registerTool({
		name: "campaign_memory_remove",
		label: "campaign memory remove",
		description: "删除一条战役记忆（过时/失效/错误的记忆及时清除，保持记忆库可信）。",
		promptSnippet: "删除一条战役记忆",
		parameters: Type.Object({ id: Type.String({ description: "记忆 id（cm- 开头）" }) }),
		executionMode: "sequential",
		async execute(_id, args, _signal, _onUpdate, _ctx) {
			const r = removeMemory(theStore(), args.id);
			return { content: [{ type: "text", text: `记忆已删除：${r.removed}` }], details: r };
		},
	});

	pi.registerTool({
		name: "campaign_memory_stats",
		label: "campaign memory stats",
		description: "战役记忆统计（原 HTTP 通道 memory.stats 的模型侧等价物）：本模式总数、各类别计数、已过期条数，并附 DB 路径与全模式总数。收口治理用。",
		promptSnippet: "战役记忆统计（总数/类别/已过期）",
		parameters: Type.Object({ mode: modeParam }),
		executionMode: "sequential",
		async execute(_id, args, _signal, _onUpdate, ctx) {
			const st = theStore();
			const mode = resolveMode(ctx, args.mode);
			if (!mode) throw new Error(noModeText(mode));
			const s = statsMemories(st, mode);
			const all = MODE_IDS.map((k) => `${MODE_LABELS[k] || k}=${statsMemories(st, k).total}`).join(" ");
			const text = `战役记忆统计 mode=${mode}：总数 ${s.total} · `
				+ MEMORY_KINDS.map((k) => `${kindLabel(k)} ${s.byKind[k] ?? 0}`).join(" · ")
				+ ` · 已过期 ${s.expired}\n各模式总量：${all}\n库：${DB_PATH}`;
			return { content: [{ type: "text", text }], details: { mode, stats: s } };
		},
	});

	pi.registerTool({
		name: "campaign_memory_purge",
		label: "campaign memory purge",
		description: "清理过期记忆：只删已过期的检测指纹（免杀情报半衰期已过即无保留价值）；目标指纹等其余到期记忆退出自动召回但保留资产（可 include_expired 查看、同题重写复活、或 campaign_memory_remove 手动删除）。开库时自动执行一次。",
		promptSnippet: "清理过期检测指纹（其余到期记忆保留）",
		parameters: Type.Object({}),
		executionMode: "sequential",
		async execute() {
			const r = purgeExpired(theStore());
			return { content: [{ type: "text", text: `已清理过期检测指纹 ${r.purged} 条（其余到期记忆保留资产）` }], details: r };
		},
	});

	/* ---------- 命令（终端/无 UI 皆可打印） ---------- */
	pi.registerCommand("campaign-mode", {
		description: `设定本工作区战役模式（无参=查看；/campaign-mode <${MODE_IDS.join("|")}> 设定；default <mode> 设默认；clear 清除本区设定）`,
		handler: async (args, ctx) => {
			const arg = args.trim();
			const st = readState();
			const ws = workspaceOf(ctx.cwd);
			const show = () => {
				const mode = resolveMode(ctx);
				const lines = MODE_IDS.map((k) => `${mode === k ? "*" : " "} ${k.padEnd(17)} ${MODE_LABELS[k]}${k === mode ? "（当前）" : ""}`);
				ctx.ui.notify(`本工作区 ${ws.name}（key=${ws.key || "-"}）模式：${mode ? `${MODE_LABELS[mode]} (${mode})` : "未设置"}\n默认模式：${st.defaultMode || "未设置"}\n${lines.join("\n")}`, "info");
			};
			if (arg === "") { show(); return; }
			if (arg === "clear") {
				if (st.workspaces) delete st.workspaces[ws.key];
				writeState(st); ctx.ui.notify(`已清除本工作区模式设定（回落默认/环境变量）`, "info"); return;
			}
			let target = arg;
			let global = false;
			if (arg.startsWith("default ")) { target = arg.slice("default ".length).trim(); global = true; }
			if (!MODE_IDS.includes(target)) {
				ctx.ui.notify(`未知模式 "${target}"，可选：${MODE_IDS.join(", ")}`, "warning");
				show(); return;
			}
			if (global) st.defaultMode = target;
			else { st.workspaces = st.workspaces ?? {}; st.workspaces[ws.key] = { mode: target }; }
			writeState(st);
			ctx.ui.notify(`战役模式已设定：${MODE_LABELS[target]} (${target})${global ? "（全局默认）" : ` @${ws.name}`}——战役记忆按该模式作用域隔离`, "info");
		},
	});

	pi.registerCommand("campaign-memory", {
		description: "战役记忆治理：/campaign-memory stats|list [kind]|search <关键词>|peek|purge|archive",
		handler: async (args, ctx) => {
			const st = theStore();
			const arg = args.trim();
			const sp = arg.indexOf(" ");
			const sub = (sp < 0 ? arg : arg.slice(0, sp)).toLowerCase();
			const rest = sp < 0 ? "" : arg.slice(sp + 1).trim();
			const mode = resolveMode(ctx);
			if (sub === "" || sub === "help") { ctx.ui.notify("用法：/campaign-memory stats|list [kind]|search <关键词>|peek|purge|archive", "info"); return; }
			if (sub === "purge") { const r = purgeExpired(st); ctx.ui.notify(`已清理过期检测指纹 ${r.purged} 条`, "info"); return; }
			if (sub === "archive") {
				const rows = st.db.prepare("SELECT id, title, kind, workspace, archived_at FROM memories_archive ORDER BY archived_at DESC LIMIT 20").all() as Row[];
				ctx.ui.notify(rows.length === 0 ? "冷淘汰归档为空（memories_archive）" : `归档 ${rows.length} 条（最近）：\n` + rows.map((r) => `${r.id} [${kindLabel(String(r.kind))}] ${r.title} @${r.workspace} → ${r.archived_at}`).join("\n"), "info");
				return;
			}
			if (sub === "peek") {
				const ws = workspaceOf(ctx.cwd);
				const block = buildMemoryBlock(mode || "-", ws.name, mode ? topForInjection(st, mode, ws.name, INJECT_TOP_ROWS, ws.key) : []);
				ctx.ui.notify(block === "" ? "本工作区暂无可注入记忆（未过期、本区、按热度×衰减前 3 条）" : clipWithFile(block, "peek", 1200), "info");
				return;
			}
			if (!mode) { ctx.ui.notify(noModeText(mode), "warning"); return; }
			if (sub === "stats") {
				const s = statsMemories(st, mode);
				ctx.ui.notify(`战役记忆 mode=${mode}：总数 ${s.total} · ${MEMORY_KINDS.map((k) => `${kindLabel(k)} ${s.byKind[k] ?? 0}`).join(" · ")} · 已过期 ${s.expired}\n库：${DB_PATH}`, "info");
				return;
			}
			if (sub === "list") {
				const kind = MEMORY_KINDS.includes(rest) ? rest : "";
				const rows = listMemories(st, { mode, kind, limit: 50 });
				ctx.ui.notify(clipWithFile(rowsToText(rows, `本模式战役记忆 ${rows.length} 条（mode=${mode}）`), "list", 4000), "info");
				return;
			}
			if (sub === "search") {
				if (!rest) { ctx.ui.notify("用法：/campaign-memory search <关键词>", "warning"); return; }
				const rows = searchMemories(st, { mode, query: rest, limit: 20 });
				ctx.ui.notify(clipWithFile(rowsToText(rows, `命中 ${rows.length} 条（mode=${mode} q="${rest}"）`), "search", 4000), "info");
				return;
			}
			ctx.ui.notify(`未知子命令 "${sub}"（stats|list|search|peek|purge|archive）`, "warning");
		},
	});
}
