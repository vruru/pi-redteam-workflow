/**
 * dsh-redteam-results → Pi extension
 *
 * 源：~/.pi/agent/redteam-model/plugins/dsh-redteam-results/lib/index.js + store.js（只读）
 * 约定：~/.pi/agent/extensions/redteam/PORT-CONVENTIONS.md
 *
 * Web 面板降级为「工具 + 命令 + 状态行/文本汇总 + markdown 台账」：
 *   - 模型工具保留原宿主平面名：redteam_finding_register / redteam_finding_update /
 *     redteam_finding_delete；新增 redteam_finding_list / redteam_finding_stats 供模型读台账。
 *   - /redteam-results 命令输出当前/跨会话聚合 markdown；支持筛选、分组、导出。
 *   - 持久化用 node:sqlite 落 ~/.pi/redteam/dsh-redteam-results/results.db，字段名与源表一致。
 *   - 原 web 通道、CSRF、自注册路由、atlas 互链等 UI/网络行为全部移除。
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

//#region constants and schema (mirrored from store.js)

const PLUGIN = "dsh-redteam-results";
const DATA_DIR = path.join(os.homedir(), ".pi", "redteam", PLUGIN);
const DB_PATH = path.join(DATA_DIR, "results.db");

const MODES = [
	"redteam",
	"pentest",
	"code-audit",
	"binary-analysis",
	"attack-defense",
	"av-evasion",
	"incident-response",
	"cloud-security",
	"ctf-solver",
] as const;

const MODE_LABELS: Record<string, string> = {
	redteam: "研究员模式",
	pentest: "渗透测试模式",
	"code-audit": "代码审计模式",
	"binary-analysis": "二进制分析模式",
	"attack-defense": "攻防评估模式",
	"av-evasion": "免杀对抗模式",
	"incident-response": "应急溯源模式",
	"cloud-security": "云安全攻防模式",
	"ctf-solver": "CTF 解题模式",
};

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const STATUSES = ["pending", "code-reviewed", "verified", "false-positive", "fixed"] as const;
const EVIDENCE_LEVELS = ["impact", "confirmed", "partial", "unknown"] as const;
const SOURCE_ORIGINS = ["manual", "scan-confirmed", "scan-false-positive"] as const;

const MODE_STATUSES: Record<string, string[]> = {
	default: [...STATUSES],
	redteam: ["pending", "verified", "false-positive", "fixed"],
	"attack-defense": ["pending", "verified", "false-positive", "fixed"],
	"cloud-security": ["pending", "verified", "false-positive", "fixed"],
	"av-evasion": ["pending", "verified", "detected"],
	"ctf-solver": ["pending", "stuck", "verified"],
	"binary-analysis": ["pending", "suspect", "verified"],
};

const ALL_STATUSES = Array.from(new Set(Object.values(MODE_STATUSES).flat()));
const statusesOf = (mode: string) => MODE_STATUSES[mode] ?? STATUSES;

const EXTRA_FIELDS = [
	"baseline",
	"diffEvidence",
	"markerEcho",
	"impact",
	"cvss",
	"retestNote",
	"retestAt",
	"requestPkt",
	"responsePkt",
	"snippetEntry",
	"snippetSink",
	"chainTracer",
	"chainVerdict",
	"cwe",
	"patch",
	"sampleHash",
	"family",
	"packer",
	"iocs",
	"detectionRule",
	"timelineAt",
	"entry",
	"identity",
	"permission",
	"resource",
	"auditMode",
] as const;

const COL_OF: Record<string, string> = {
	baseline: "baseline",
	diffEvidence: "diff_evidence",
	markerEcho: "marker_echo",
	impact: "impact",
	cvss: "cvss",
	retestNote: "retest_note",
	retestAt: "retest_at",
	requestPkt: "request_pkt",
	responsePkt: "response_pkt",
	snippetEntry: "snippet_entry",
	snippetSink: "snippet_sink",
	chainTracer: "chain_tracer",
	chainVerdict: "chain_verdict",
	cwe: "cwe",
	patch: "patch",
	sampleHash: "sample_hash",
	family: "family",
	packer: "packer",
	iocs: "iocs",
	detectionRule: "detection_rule",
	timelineAt: "timeline_at",
	entry: "entry",
	identity: "identity",
	permission: "permission",
	resource: "resource",
	auditMode: "audit_mode",
};

const COLS = [
	"session_id",
	"id",
	"seq",
	"mode",
	"title",
	"severity",
	"status",
	"evidence_level",
	"type",
	"target",
	"summary",
	"description",
	"poc",
	"chain",
	"evidence",
	"fix",
	"verify_note",
	"created_at",
	"updated_at",
	"verified_at",
	...EXTRA_FIELDS.map((k) => COL_OF[k]),
].join(",");

const N_COLS = COLS.split(",").length;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS findings (
	session_id TEXT NOT NULL,
	id         TEXT NOT NULL,
	seq        INTEGER NOT NULL,
	mode       TEXT NOT NULL,
	title      TEXT NOT NULL,
	severity   TEXT NOT NULL,
	status     TEXT NOT NULL,
	evidence_level TEXT NOT NULL,
	type       TEXT NOT NULL DEFAULT '',
	target     TEXT NOT NULL DEFAULT '',
	summary    TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	poc        TEXT NOT NULL DEFAULT '',
	chain      TEXT NOT NULL DEFAULT '',
	evidence   TEXT NOT NULL DEFAULT '',
	fix        TEXT NOT NULL DEFAULT '',
	verify_note TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	verified_at TEXT NOT NULL DEFAULT '',
	baseline   TEXT NOT NULL DEFAULT '',
	diff_evidence TEXT NOT NULL DEFAULT '',
	marker_echo TEXT NOT NULL DEFAULT '',
	impact     TEXT NOT NULL DEFAULT '',
	cvss       TEXT NOT NULL DEFAULT '',
	retest_note TEXT NOT NULL DEFAULT '',
	retest_at  TEXT NOT NULL DEFAULT '',
	request_pkt TEXT NOT NULL DEFAULT '',
	response_pkt TEXT NOT NULL DEFAULT '',
	snippet_entry TEXT NOT NULL DEFAULT '',
	snippet_sink TEXT NOT NULL DEFAULT '',
	chain_tracer TEXT NOT NULL DEFAULT '',
	chain_verdict TEXT NOT NULL DEFAULT '',
	cwe        TEXT NOT NULL DEFAULT '',
	patch      TEXT NOT NULL DEFAULT '',
	source_origin TEXT NOT NULL DEFAULT '',
	sample_hash TEXT NOT NULL DEFAULT '',
	family     TEXT NOT NULL DEFAULT '',
	packer     TEXT NOT NULL DEFAULT '',
	iocs       TEXT NOT NULL DEFAULT '',
	detection_rule TEXT NOT NULL DEFAULT '',
	timeline_at  TEXT NOT NULL DEFAULT '',
	entry       TEXT NOT NULL DEFAULT '',
	identity    TEXT NOT NULL DEFAULT '',
	permission  TEXT NOT NULL DEFAULT '',
	resource    TEXT NOT NULL DEFAULT '',
	audit_mode  TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (session_id, id)
);
CREATE INDEX IF NOT EXISTS idx_findings_session_mode ON findings(session_id, mode, seq);
CREATE TABLE IF NOT EXISTS counters (
	session_id TEXT NOT NULL,
	mode       TEXT NOT NULL,
	last_seq   INTEGER NOT NULL,
	PRIMARY KEY (session_id, mode)
);
`;

//#endregion

//#region store layer

interface Store {
	dbPath: string;
	insert: ReturnType<DatabaseSync["prepare"]>;
	get: ReturnType<DatabaseSync["prepare"]>;
	counterGet: ReturnType<DatabaseSync["prepare"]>;
	counterSet: ReturnType<DatabaseSync["prepare"]>;
	update: ReturnType<DatabaseSync["prepare"]>;
	remove: ReturnType<DatabaseSync["prepare"]>;
	listAll: ReturnType<DatabaseSync["prepare"]>;
	listAllAll: ReturnType<DatabaseSync["prepare"]>;
	listGlobal: ReturnType<DatabaseSync["prepare"]>;
	listGlobalMode: ReturnType<DatabaseSync["prepare"]>;
	countsAll: ReturnType<DatabaseSync["prepare"]>;
	counts: ReturnType<DatabaseSync["prepare"]>;
	close: () => void;
}

let storeCache: Store | undefined;

function openStore(dbPath: string): Store {
	const dir = path.dirname(dbPath);
	if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
	const db = new DatabaseSync(dbPath);
	db.exec("PRAGMA journal_mode = WAL;");
	db.exec("PRAGMA busy_timeout = 5000;");
	db.exec(SCHEMA);
	db.exec("INSERT OR IGNORE INTO counters (session_id, mode, last_seq) SELECT session_id, mode, MAX(seq) FROM findings GROUP BY session_id, mode");
	return {
		dbPath,
		insert: db.prepare(`INSERT INTO findings (${COLS}) VALUES (${"?,".repeat(N_COLS - 1)}?)`),
		get: db.prepare(`SELECT ${COLS} FROM findings WHERE session_id = ? AND id = ?`),
		counterGet: db.prepare("SELECT last_seq AS n FROM counters WHERE session_id = ? AND mode = ?"),
		counterSet: db.prepare("INSERT INTO counters (session_id, mode, last_seq) VALUES (?, ?, ?) ON CONFLICT(session_id, mode) DO UPDATE SET last_seq = excluded.last_seq"),
		update: db.prepare(
			`UPDATE findings SET title=?, severity=?, status=?, evidence_level=?, type=?, target=?, summary=?, description=?, poc=?, chain=?, evidence=?, fix=?, verify_note=?, updated_at=?, verified_at=?, baseline=?, diff_evidence=?, marker_echo=?, impact=?, cvss=?, retest_note=?, retest_at=?, request_pkt=?, response_pkt=?, snippet_entry=?, snippet_sink=?, chain_tracer=?, chain_verdict=?, cwe=?, patch=?, source_origin=?, sample_hash=?, family=?, packer=?, iocs=?, detection_rule=?, timeline_at=?, entry=?, identity=?, permission=?, resource=?, audit_mode=? WHERE session_id=? AND id=?`,
		),
		remove: db.prepare("DELETE FROM findings WHERE session_id = ? AND id = ?"),
		listAll: db.prepare(`SELECT ${COLS} FROM findings WHERE session_id = ? AND mode = ? ORDER BY seq DESC`),
		listAllAll: db.prepare(`SELECT ${COLS} FROM findings WHERE session_id = ? ORDER BY updated_at DESC, seq DESC`),
		listGlobal: db.prepare(`SELECT ${COLS} FROM findings ORDER BY updated_at DESC, seq DESC`),
		listGlobalMode: db.prepare(`SELECT ${COLS} FROM findings WHERE mode = ? ORDER BY updated_at DESC, seq DESC`),
		countsAll: db.prepare("SELECT mode, COUNT(*) AS n FROM findings GROUP BY mode"),
		counts: db.prepare("SELECT mode, COUNT(*) AS n FROM findings WHERE session_id = ? GROUP BY mode"),
		close: () => {
			try {
				db.close();
			} catch {
				/* ignore */
			}
		},
	};
}

function theStore(): Store {
	if (!storeCache) storeCache = openStore(DB_PATH);
	return storeCache;
}

function closeStore() {
	if (storeCache) {
		storeCache.close();
		storeCache = undefined;
	}
}

const nowIso = () => new Date().toISOString();
const cleanEnum = (v: unknown, allowed: readonly string[], fallback: string) => (typeof v === "string" && allowed.includes(v) ? v : fallback);
const cleanText = (v: unknown, max = 20000) => {
	const s = typeof v === "string" ? v.trim() : "";
	return s.length > max ? s.slice(0, max) : s;
};

interface FindingInput {
	title?: unknown;
	severity?: unknown;
	status?: unknown;
	evidenceLevel?: unknown;
	type?: unknown;
	target?: unknown;
	summary?: unknown;
	description?: unknown;
	poc?: unknown;
	chain?: unknown;
	evidence?: unknown;
	fix?: unknown;
	verifyNote?: unknown;
	baseline?: unknown;
	diffEvidence?: unknown;
	markerEcho?: unknown;
	impact?: unknown;
	cvss?: unknown;
	retestNote?: unknown;
	retestAt?: unknown;
	requestPkt?: unknown;
	responsePkt?: unknown;
	snippetEntry?: unknown;
	snippetSink?: unknown;
	chainTracer?: unknown;
	chainVerdict?: unknown;
	cwe?: unknown;
	patch?: unknown;
	sourceOrigin?: unknown;
	sampleHash?: unknown;
	family?: unknown;
	packer?: unknown;
	iocs?: unknown;
	detectionRule?: unknown;
	timelineAt?: unknown;
	entry?: unknown;
	identity?: unknown;
	permission?: unknown;
	resource?: unknown;
	auditMode?: unknown;
	[key: string]: unknown;
}

interface Finding {
	id: string;
	seq: number;
	mode: string;
	title: string;
	severity: string;
	status: string;
	evidenceLevel: string;
	type: string;
	target: string;
	summary: string;
	description: string;
	poc: string;
	chain: string;
	evidence: string;
	fix: string;
	verifyNote: string;
	createdAt: string;
	updatedAt: string;
	verifiedAt: string;
	sourceOrigin: string;
	[key: string]: string | number;
}

function rowToFinding(row: Record<string, string>): Finding {
	const f: Finding = {
		id: row.id,
		seq: Number(row.seq),
		mode: row.mode,
		title: row.title,
		severity: row.severity,
		status: row.status,
		evidenceLevel: row.evidence_level,
		type: row.type,
		target: row.target,
		summary: row.summary,
		description: row.description,
		poc: row.poc,
		chain: row.chain,
		evidence: row.evidence,
		fix: row.fix,
		verifyNote: row.verify_note,
		createdAt: row.created_at,
		updatedAt: row.updated_at,
		verifiedAt: row.verified_at,
		sourceOrigin: row.source_origin || "manual",
	};
	for (const k of EXTRA_FIELDS) f[k] = row[COL_OF[k]] ?? "";
	return f;
}

function registerFinding(store: Store, sessionId: string, mode: string, input: FindingInput): Finding {
	const seq = ((store.counterGet.get(sessionId, mode) as { n?: number } | undefined)?.n ?? 0) + 1;
	store.counterSet.run(sessionId, mode, seq);
	const id = `${mode}-${seq}`;
	const now = nowIso();
	const status = cleanEnum(input.status, statusesOf(mode), "pending");
	if (mode !== "redteam" && status === "fixed") throw new Error("fixed 不可在登记时直接写入——先登记（pending/verified），经 update 流转标记 fixed");
	const f: Finding = {
		id,
		seq,
		mode,
		title: cleanText(input.title, 200) || "未命名发现",
		severity: cleanEnum(input.severity, SEVERITIES, "medium"),
		status,
		evidenceLevel: cleanEnum(input.evidenceLevel, EVIDENCE_LEVELS, "unknown"),
		type: cleanText(input.type, 60),
		target: cleanText(input.target, 500),
		summary: cleanText(input.summary, 300),
		description: cleanText(input.description),
		poc: cleanText(input.poc),
		chain: cleanText(input.chain),
		evidence: cleanText(input.evidence),
		fix: cleanText(input.fix),
		verifyNote: "",
		createdAt: now,
		updatedAt: now,
		verifiedAt: "",
		sourceOrigin: cleanEnum(input.sourceOrigin, SOURCE_ORIGINS, "manual"),
	};
	for (const k of EXTRA_FIELDS) f[k] = cleanText(input[k]);
	if (mode === "code-audit") f.auditMode = ["static", "dynamic"].includes(f.auditMode) ? f.auditMode : "";
	store.insert.run(
		sessionId,
		f.id,
		f.seq,
		mode,
		f.title,
		f.severity,
		f.status,
		f.evidenceLevel,
		f.type,
		f.target,
		f.summary,
		f.description,
		f.poc,
		f.chain,
		f.evidence,
		f.fix,
		f.verifyNote,
		f.createdAt,
		f.updatedAt,
		f.verifiedAt,
		...EXTRA_FIELDS.map((k) => f[k]),
	);
	return f;
}

function updateFinding(store: Store, sessionId: string, mode: string, id: string, patch: FindingInput): Finding | undefined {
	const row = store.get.get(sessionId, id) as Record<string, string> | undefined;
	if (!row || row.mode !== mode) return undefined;
	const prev = rowToFinding(row);
	const statusSet = statusesOf(mode);
	const nextStatus = cleanEnum(patch.status, statusSet, prev.status);
	if (mode !== "redteam" && statusSet.includes("fixed") && nextStatus === "fixed" && prev.status !== "verified") {
		throw new Error("fixed 仅可用于此前已验证（verified）真实存在的 finding");
	}
	const next: Finding = {
		...prev,
		title: cleanText(patch.title, 200) || prev.title,
		severity: cleanEnum(patch.severity, SEVERITIES, prev.severity),
		status: nextStatus,
		evidenceLevel: cleanEnum(patch.evidenceLevel, EVIDENCE_LEVELS, prev.evidenceLevel),
		type: patch.type !== undefined ? cleanText(patch.type, 60) : prev.type,
		target: patch.target !== undefined ? cleanText(patch.target, 500) : prev.target,
		summary: patch.summary !== undefined ? cleanText(patch.summary, 300) : prev.summary,
		description: patch.description !== undefined ? cleanText(patch.description) : prev.description,
		poc: patch.poc !== undefined ? cleanText(patch.poc) : prev.poc,
		chain: patch.chain !== undefined ? cleanText(patch.chain) : prev.chain,
		evidence: patch.evidence !== undefined ? cleanText(patch.evidence) : prev.evidence,
		fix: patch.fix !== undefined ? cleanText(patch.fix) : prev.fix,
		verifyNote: patch.verifyNote !== undefined ? cleanText(patch.verifyNote) : prev.verifyNote,
		updatedAt: nowIso(),
		verifiedAt: prev.status !== "verified" && nextStatus === "verified" ? nowIso() : prev.verifiedAt,
		sourceOrigin: cleanEnum(patch.sourceOrigin, SOURCE_ORIGINS, prev.sourceOrigin),
	};
	for (const k of EXTRA_FIELDS) next[k] = patch[k] !== undefined ? cleanText(patch[k]) : prev[k];
	if (mode === "code-audit") next.auditMode = ["static", "dynamic"].includes(next.auditMode) ? next.auditMode : "";
	store.update.run(
		next.title,
		next.severity,
		next.status,
		next.evidenceLevel,
		next.type,
		next.target,
		next.summary,
		next.description,
		next.poc,
		next.chain,
		next.evidence,
		next.fix,
		next.verifyNote,
		next.updatedAt,
		next.verifiedAt,
		...EXTRA_FIELDS.map((k) => next[k]),
		sessionId,
		id,
	);
	return next;
}

function removeFinding(store: Store, sessionId: string, id: string) {
	store.remove.run(sessionId, id);
}

function getFinding(store: Store, sessionId: string, id: string): Finding | undefined {
	const row = store.get.get(sessionId, id) as Record<string, string> | undefined;
	return row ? rowToFinding(row) : undefined;
}

function allFindings(store: Store, sessionId: string, mode: string): Finding[] {
	return (store.listAll.all(sessionId, mode) as Record<string, string>[]).map(rowToFinding);
}

interface ListOptions {
	page?: number;
	pageSize?: number;
	severity?: string;
	status?: string;
	q?: string;
}

function listFindings(store: Store, sessionId: string, mode: string, opts: ListOptions = {}) {
	const needle = String(opts.q ?? "").trim().toLowerCase();
	const rows = allFindings(store, sessionId, mode)
		.filter((f) => (opts.severity ? f.severity === opts.severity : true))
		.filter((f) => (opts.status ? f.status === opts.status : true))
		.filter((f) =>
			needle ? `${f.title} ${f.summary} ${f.target} ${f.type} ${f.cwe}`.toLowerCase().includes(needle) : true,
		);
	const size = Math.max(1, Math.min(100, Number(opts.pageSize) || 10));
	const total = rows.length;
	const pages = Math.max(1, Math.ceil(total / size));
	const current = Math.min(pages, Math.max(1, Number(opts.page) || 1));
	return { rows: rows.slice((current - 1) * size, current * size), total, page: current, pageSize: size, pages };
}

function listFindingsAll(store: Store, mode: string, opts: ListOptions & { from?: string; to?: string; all?: boolean } = {}) {
	const needle = String(opts.q ?? "").trim().toLowerCase();
	const rows = (store.listGlobalMode.all(mode) as Record<string, string>[])
		.map((row) => ({ ...rowToFinding(row), sessionId: row.session_id }))
		.filter((f) => (opts.severity ? f.severity === opts.severity : true))
		.filter((f) => (opts.status ? f.status === opts.status : true))
		.filter((f) => (opts.from ? f.createdAt >= opts.from : true))
		.filter((f) => (opts.to ? f.createdAt <= opts.to : true))
		.filter((f) =>
			needle ? `${f.title} ${f.summary} ${f.target} ${f.type} ${f.cwe}`.toLowerCase().includes(needle) : true,
		);
	if (opts.all) return { rows, total: rows.length, page: 1, pageSize: rows.length, pages: 1 };
	const size = Math.max(1, Math.min(100, Number(opts.pageSize) || 10));
	const total = rows.length;
	const pages = Math.max(1, Math.ceil(total / size));
	const current = Math.min(pages, Math.max(1, Number(opts.page) || 1));
	return { rows: rows.slice((current - 1) * size, current * size), total, page: current, pageSize: size, pages };
}

function statsOf(rows: Finding[], mode = "") {
	const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
	const byStatus = Object.fromEntries((mode ? statusesOf(mode) : ALL_STATUSES).map((s) => [s, 0]));
	const byEvidence = Object.fromEntries(EVIDENCE_LEVELS.map((s) => [s, 0]));
	const typeMap = new Map<string, number>();
	const cweMap = new Map<string, number>();
	const sourceMap = new Map<string, number>();
	const auditModeMap = new Map<string, number>();
	const familyMap = new Map<string, number>();
	const packerMap = new Map<string, number>();
	const targetMap = new Map<string, number>();
	let lastAt = "";
	for (const f of rows) {
		bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
		byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
		byEvidence[f.evidenceLevel] = (byEvidence[f.evidenceLevel] ?? 0) + 1;
		typeMap.set(f.type || "未分类", (typeMap.get(f.type || "未分类") ?? 0) + 1);
		if (f.cwe) cweMap.set(f.cwe, (cweMap.get(f.cwe) ?? 0) + 1);
		if (f.family) familyMap.set(f.family, (familyMap.get(f.family) ?? 0) + 1);
		if (f.packer) packerMap.set(f.packer, (packerMap.get(f.packer) ?? 0) + 1);
		sourceMap.set(f.sourceOrigin || "manual", (sourceMap.get(f.sourceOrigin || "manual") ?? 0) + 1);
		if (f.auditMode) auditModeMap.set(f.auditMode, (auditModeMap.get(f.auditMode) ?? 0) + 1);
		targetMap.set(f.target || "（未填）", (targetMap.get(f.target || "（未填）") ?? 0) + 1);
		if (f.updatedAt > lastAt) lastAt = f.updatedAt;
	}
	const top = (m: Map<string, number>, n: number) =>
		[...m.entries()]
			.sort((a, b) => b[1] - a[1])
			.slice(0, n)
			.map(([key, count]) => ({ key, count }));
	return {
		total: rows.length,
		bySeverity,
		byStatus,
		byEvidence,
		byType: top(typeMap, 8),
		byCwe: top(cweMap, 8),
		bySource: top(sourceMap, 4),
		byAuditMode: top(auditModeMap, 2),
		byTarget: top(targetMap, 8),
		byFamily: top(familyMap, 8),
		byPacker: top(packerMap, 6),
		lastAt,
	};
}

function computeStats(store: Store, sessionId: string, mode: string) {
	return statsOf(allFindings(store, sessionId, mode), mode);
}

function computeStatsAll(store: Store, mode: string, { from = "", to = "" } = {}) {
	const rows = (store.listGlobalMode.all(mode) as Record<string, string>[])
		.map(rowToFinding)
		.filter((f) => (from === "" || f.createdAt >= from) && (to === "" || f.createdAt <= to));
	return statsOf(rows, mode);
}

function modeCountsAll(store: Store) {
	const out = Object.fromEntries(MODES.map((m) => [m, 0]));
	for (const row of store.countsAll.all() as { mode: string; n: number }[]) {
		if (out[row.mode] !== undefined) out[row.mode] = row.n;
	}
	return out;
}

function modeCounts(store: Store, sessionId: string) {
	const out = Object.fromEntries(MODES.map((m) => [m, 0]));
	for (const row of store.counts.all(sessionId) as { mode: string; n: number }[]) {
		if (out[row.mode] !== undefined) out[row.mode] = row.n;
	}
	return out;
}

function ledgerOverviewAll(store: Store, { from = "", to = "" } = {}) {
	const rows = store.listGlobal.all() as Record<string, string>[];
	const inRange = (row: Record<string, string>) =>
		(from === "" || row.created_at >= from) && (to === "" || row.created_at <= to);
	const byMode = Object.fromEntries(MODES.map((m) => [m, 0]));
	const byStatus = Object.fromEntries(ALL_STATUSES.map((s) => [s, 0]));
	const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
	const byEvidence = Object.fromEntries(EVIDENCE_LEVELS.map((s) => [s, 0]));
	const sessions = new Set<string>();
	let lastAt = "";
	let total = 0;
	for (const row of rows) {
		if (!inRange(row)) continue;
		total += 1;
		sessions.add(row.session_id);
		if (byMode[row.mode] !== undefined) byMode[row.mode] += 1;
		byStatus[row.status] = (byStatus[row.status] ?? 0) + 1;
		if (bySeverity[row.severity] !== undefined) bySeverity[row.severity] += 1;
		if (byEvidence[row.evidence_level] !== undefined) byEvidence[row.evidence_level] += 1;
		if (row.updated_at > lastAt) lastAt = row.updated_at;
	}
	const recent = rows
		.filter(inRange)
		.slice(0, 120)
		.map((row) => ({ ...rowToFinding(row), sessionId: row.session_id }));
	return { total, sessions: sessions.size, byMode, byStatus, bySeverity, byEvidence, recent, lastAt, range: { from, to } };
}

function ledgerOverview(store: Store, sessionId: string) {
	const rows = (store.listAllAll.all(sessionId) as Record<string, string>[]) ?? [];
	const byMode = Object.fromEntries(MODES.map((m) => [m, 0]));
	const byStatus = Object.fromEntries(ALL_STATUSES.map((s) => [s, 0]));
	const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
	const byEvidence = Object.fromEntries(EVIDENCE_LEVELS.map((s) => [s, 0]));
	let lastAt = "";
	for (const row of rows) {
		if (byMode[row.mode] !== undefined) byMode[row.mode] += 1;
		byStatus[row.status] = (byStatus[row.status] ?? 0) + 1;
		if (bySeverity[row.severity] !== undefined) bySeverity[row.severity] += 1;
		if (byEvidence[row.evidence_level] !== undefined) byEvidence[row.evidence_level] += 1;
		if (row.updated_at > lastAt) lastAt = row.updated_at;
	}
	const recent = rows.slice(0, 120).map(rowToFinding);
	return { total: rows.length, byMode, byStatus, bySeverity, byEvidence, recent, lastAt };
}

//#endregion

//#region helpers

function sessionMode(ctx: ExtensionContext | undefined): { id: string; mode: string } | undefined {
	const id = ctx?.sessionManager?.getSessionId?.();
	if (!id) return undefined;
	const header = ctx?.sessionManager?.getHeader?.();
	const preset = header?.agentPreset || "redteam";
	return { id: String(id), mode: MODES.includes(preset as (typeof MODES)[number]) ? preset : "redteam" };
}

function result<T>(text: string, details: T) {
	return { content: [{ type: "text" as const, text }], details };
}

function fmtFinding(f: Finding, showSession = false) {
	const parts = [
		`${showSession ? `[${f.sessionId ?? ""}] ` : ""}#${f.seq} ${f.title}`,
		`  等级=${f.severity} 状态=${f.status} 证据=${f.evidenceLevel} 类型=${f.type || "-"}`,
		`  目标=${f.target || "-"}`,
		`  摘要=${f.summary || "-"}`,
	];
	if (f.description) parts.push(`  描述=${f.description.slice(0, 120)}${f.description.length > 120 ? "…" : ""}`);
	if (f.fix) parts.push(`  修复=${f.fix.slice(0, 120)}${f.fix.length > 120 ? "…" : ""}`);
	if (f.verifyNote) parts.push(`  复核=${f.verifyNote}`);
	return parts.join("\n");
}

function renderStats(stats: ReturnType<typeof statsOf>, mode: string) {
	const sev = Object.entries(stats.bySeverity)
		.map(([k, v]) => `${k}:${v}`)
		.join(" ");
	const status = Object.entries(stats.byStatus)
		.filter(([, v]) => v > 0)
		.map(([k, v]) => `${k}:${v}`)
		.join(" ");
	const ev = Object.entries(stats.byEvidence)
		.map(([k, v]) => `${k}:${v}`)
		.join(" ");
	const lines = [
		`total=${stats.total}`,
		`severity: ${sev}`,
		`status: ${status}`,
		`evidence: ${ev}`,
	];
	if (stats.byType.length) lines.push(`type top: ${stats.byType.map((x) => `${x.key}=${x.count}`).join(" ")}`);
	if (mode === "code-audit" && stats.byCwe.length) lines.push(`CWE top: ${stats.byCwe.map((x) => `${x.cwe}=${x.count}`).join(" ")}`);
	if (mode === "binary-analysis" && stats.byFamily.length) lines.push(`family top: ${stats.byFamily.map((x) => `${x.key}=${x.count}`).join(" ")}`);
	return lines.join("\n");
}

function toMarkdownOverview(overview: ReturnType<typeof ledgerOverviewAll>, title: string) {
	const lines = [
		`# ${title}`,
		"",
		`| 指标 | 值 |`,
		`|---|---|`,
		`| 总 findings | ${overview.total} |`,
		`| 涉及会话 | ${overview.sessions} |`,
		`| 最近更新 | ${overview.lastAt || "-"} |`,
		"",
		"## 按模式",
		"",
		`| 模式 | 数量 |`,
		`|---|---|`,
		...Object.entries(overview.byMode).map(([m, n]) => `| ${MODE_LABELS[m] || m} | ${n} |`),
		"",
		"## 按严重度",
		"",
		`| 严重度 | 数量 |`,
		`|---|---|`,
		...Object.entries(overview.bySeverity).map(([s, n]) => `| ${s} | ${n} |`),
		"",
		"## 按状态",
		"",
		`| 状态 | 数量 |`,
		`|---|---|`,
		...Object.entries(overview.byStatus)
			.filter(([, n]) => n > 0)
			.map(([s, n]) => `| ${s} | ${n} |`),
		"",
	];
	if (overview.recent.length) {
		lines.push("## 最近登记", "", "| 会话 | ID | 标题 | 状态 |", "|---|---|---|---|");
		for (const f of overview.recent.slice(0, 30)) {
			lines.push(`| ${f.sessionId ?? ""} | ${f.id} | ${f.title.replace(/\|/g, "\\|")} | ${f.status} |`);
		}
		lines.push("");
	}
	return lines.join("\n");
}

//#endregion

//#region extension

export default function (pi: ExtensionAPI) {
	const modeSchema = Type.Union(MODES.map((m) => Type.Literal(m)));
	const severitySchema = Type.Union(SEVERITIES.map((s) => Type.Literal(s)));

	const findingInputProps = {
		title: Type.String({ description: "名称（简短）" }),
		severity: Type.Optional(severitySchema),
		target: Type.String({ description: "地址/目标/位置" }),
		summary: Type.String({ description: "一句话简介" }),
		type: Type.Optional(Type.String({ description: "分类标签（按模式本体词表）" })),
		description: Type.Optional(Type.String({ description: "描述（影响与成因）" })),
		poc: Type.Optional(Type.String({ description: "测试过程+完整EXP" })),
		chain: Type.Optional(Type.String({ description: "调用链 entry→sink" })),
		evidence: Type.Optional(Type.String({ description: "证据引用" })),
		fix: Type.Optional(Type.String({ description: "修复建议" })),
		status: Type.Optional(Type.String({ description: "默认 pending" })),
		evidenceLevel: Type.Optional(Type.Union(EVIDENCE_LEVELS.map((e) => Type.Literal(e)), { description: "impact/confirmed/partial/unknown" })),
		baseline: Type.Optional(Type.String()),
		diffEvidence: Type.Optional(Type.String()),
		markerEcho: Type.Optional(Type.String()),
		impact: Type.Optional(Type.String()),
		cvss: Type.Optional(Type.String()),
		requestPkt: Type.Optional(Type.String()),
		responsePkt: Type.Optional(Type.String()),
		snippetEntry: Type.Optional(Type.String()),
		snippetSink: Type.Optional(Type.String()),
		chainTracer: Type.Optional(Type.String()),
		chainVerdict: Type.Optional(Type.String()),
		cwe: Type.Optional(Type.String()),
		patch: Type.Optional(Type.String()),
		sourceOrigin: Type.Optional(Type.Union(SOURCE_ORIGINS.map((s) => Type.Literal(s)))),
		sampleHash: Type.Optional(Type.String()),
		family: Type.Optional(Type.String()),
		packer: Type.Optional(Type.String()),
		iocs: Type.Optional(Type.String()),
		detectionRule: Type.Optional(Type.String()),
		timelineAt: Type.Optional(Type.String()),
		entry: Type.Optional(Type.String()),
		identity: Type.Optional(Type.String()),
		permission: Type.Optional(Type.String()),
		resource: Type.Optional(Type.String()),
		auditMode: Type.Optional(Type.Union([Type.Literal("static"), Type.Literal("dynamic")])),
	};

	pi.registerTool({
		name: "redteam_finding_register",
		label: "redteam finding register",
		description:
			"登记一条 finding 到本会话「redteam 成果」台账（会话×模式自动隔离）。每条进报告的 finding 必登；status 复核前一律 pending。",
		promptSnippet: "登记 redteam 成果 finding",
		executionMode: "sequential",
		parameters: Type.Object(findingInputProps),
		async execute(_id, p, _signal, _onUpdate, ctx) {
			const session = sessionMode(ctx);
			if (!session) throw new Error("无法解析当前会话（工具需在会话内调用）");
			const finding = registerFinding(theStore(), session.id, session.mode, p);
			return result(
				`已登记成果 #${finding.seq} ${finding.title}（${finding.mode}，${finding.severity}）——本会话「redteam 成果」页可见`,
				{ ok: true, id: finding.id, seq: finding.seq, mode: finding.mode, severity: finding.severity },
			);
		},
	});

	pi.registerTool({
		name: "redteam_finding_update",
		label: "redteam finding update",
		description: "按 id 更新一条 finding：状态流转、字段修订、verifyNote 记复核结论。",
		promptSnippet: "更新 redteam 成果 finding",
		executionMode: "sequential",
		parameters: Type.Object({
			id: Type.String({ description: "finding id（如 pentest-3）" }),
			...findingInputProps,
			verifyNote: Type.Optional(Type.String({ description: "复核注记" })),
			retestNote: Type.Optional(Type.String({ description: "复测注记" })),
		}),
		async execute(_id, p, _signal, _onUpdate, ctx) {
			const session = sessionMode(ctx);
			if (!session) throw new Error("无法解析当前会话");
			const finding = updateFinding(theStore(), session.id, session.mode, p.id, p);
			if (!finding) throw new Error(`finding ${p.id} 不存在（本会话 ${session.mode}）`);
			return result(
				`成果已更新：${finding.id} → ${finding.status}${finding.verifyNote ? `（${finding.verifyNote}）` : ""}`,
				{ ok: true, id: finding.id, status: finding.status, verifyNote: finding.verifyNote },
			);
		},
	});

	pi.registerTool({
		name: "redteam_finding_delete",
		label: "redteam finding delete",
		description: "Remove one finding from this session's「redteam 成果」by id。",
		promptSnippet: "删除 redteam 成果 finding",
		executionMode: "sequential",
		parameters: Type.Object({ id: Type.String({ description: "finding id" }) }),
		async execute(_id, p, _signal, _onUpdate, ctx) {
			const session = sessionMode(ctx);
			if (!session) throw new Error("无法解析当前会话");
			removeFinding(theStore(), session.id, p.id);
			return result(`已删除成果 ${p.id}`, { ok: true, id: p.id });
		},
	});

	pi.registerTool({
		name: "redteam_finding_list",
		label: "redteam finding list",
		description: "列出本会话或跨会话（scope=all）的 findings，支持分页/严重度/状态/关键词/时间范围筛选。",
		promptSnippet: "列出 redteam 成果台账",
		executionMode: "parallel",
		parameters: Type.Object({
			scope: Type.Optional(Type.Union([Type.Literal("session"), Type.Literal("all")], { description: "session=本会话（默认），all=跨会话聚合" })),
			mode: Type.Optional(modeSchema),
			page: Type.Optional(Type.Number({ description: "页码，默认 1" })),
			pageSize: Type.Optional(Type.Number({ description: "每页条数，默认 10" })),
			severity: Type.Optional(severitySchema),
			status: Type.Optional(Type.String()),
			q: Type.Optional(Type.String({ description: "关键词筛选" })),
			from: Type.Optional(Type.String({ description: "created_at 起始 ISO" })),
			to: Type.Optional(Type.String({ description: "created_at 截止 ISO" })),
		}),
		async execute(_id, p, _signal, _onUpdate, ctx) {
			const store = theStore();
			const mode = p.mode ?? sessionMode(ctx)?.mode ?? "redteam";
			if (p.scope === "all") {
				const list = listFindingsAll(store, mode, {
					page: p.page,
					pageSize: p.pageSize,
					severity: p.severity,
					status: p.status,
					q: p.q,
					from: p.from,
					to: p.to,
				});
				const stats = computeStatsAll(store, mode, { from: p.from ?? "", to: p.to ?? "" });
				const counts = modeCountsAll(store);
				const text = [
					`跨会话「${MODE_LABELS[mode] || mode}」成果：${list.total} 条（第 ${list.page}/${list.pages} 页，每页 ${list.pageSize}）`,
					renderStats(stats, mode),
					"",
					...list.rows.map((f) => fmtFinding(f as Finding & { sessionId?: string }, true)),
				].join("\n");
				return result(text, { scope: "all", mode, list, stats, counts });
			}
			const session = sessionMode(ctx);
			if (!session) throw new Error("无法解析当前会话");
			const list = listFindings(store, session.id, mode, {
				page: p.page,
				pageSize: p.pageSize,
				severity: p.severity,
				status: p.status,
				q: p.q,
			});
			const stats = computeStats(store, session.id, mode);
			const counts = modeCounts(store, session.id);
			const text = [
				`本会话「${MODE_LABELS[mode] || mode}」成果：${list.total} 条（第 ${list.page}/${list.pages} 页）`,
				renderStats(stats, mode),
				"",
				...list.rows.map((f) => fmtFinding(f)),
			].join("\n");
			return result(text, { scope: "session", sessionId: session.id, mode, list, stats, counts });
		},
	});

	pi.registerTool({
		name: "redteam_finding_stats",
		label: "redteam finding stats",
		description: "本会话或跨会话成果统计聚合（严重度/状态/证据/类型 top）。",
		promptSnippet: "redteam 成果统计",
		executionMode: "parallel",
		parameters: Type.Object({
			scope: Type.Optional(Type.Union([Type.Literal("session"), Type.Literal("all")])),
			mode: Type.Optional(modeSchema),
			from: Type.Optional(Type.String({ description: "created_at 起始 ISO" })),
			to: Type.Optional(Type.String({ description: "created_at 截止 ISO" })),
		}),
		async execute(_id, p, _signal, _onUpdate, ctx) {
			const store = theStore();
			const mode = p.mode ?? sessionMode(ctx)?.mode ?? "redteam";
			if (p.scope === "all") {
				const stats = computeStatsAll(store, mode, { from: p.from ?? "", to: p.to ?? "" });
				const counts = modeCountsAll(store);
				return result(`跨会话「${MODE_LABELS[mode] || mode}」统计\n${renderStats(stats, mode)}`, { scope: "all", mode, stats, counts });
			}
			const session = sessionMode(ctx);
			if (!session) throw new Error("无法解析当前会话");
			const stats = computeStats(store, session.id, mode);
			const counts = modeCounts(store, session.id);
			return result(`本会话「${MODE_LABELS[mode] || mode}」统计\n${renderStats(stats, mode)}`, { scope: "session", sessionId: session.id, mode, stats, counts });
		},
	});

	pi.on("session_shutdown", async () => {
		closeStore();
	});

	pi.registerCommand("redteam-results", {
		description: "redteam 成果台账：输出当前/跨会话聚合 markdown",
		handler: async (args, ctx) => {
			const store = theStore();
			const argv = args.trim().split(/\s+/).filter(Boolean);
			const modeArg = argv.find((a) => MODES.includes(a as (typeof MODES)[number]));
			const mode = modeArg ?? sessionMode(ctx)?.mode ?? "redteam";
			const all = argv.includes("--all") || argv.includes("-a");
			const from = argv.find((a, i) => argv[i - 1] === "--from") ?? "";
			const to = argv.find((a, i) => argv[i - 1] === "--to") ?? "";

			let md: string;
			let file: string;
			if (all) {
				const overview = ledgerOverviewAll(store, { from, to });
				md = toMarkdownOverview(overview, `跨会话 redteam 成果大屏（${mode ? `模式 ${MODE_LABELS[mode] || mode}` : "全部模式"}）`);
				file = path.join(DATA_DIR, `overview-all-${Date.now()}.md`);
			} else {
				const session = sessionMode(ctx);
				const sessionId = session?.id ?? "unknown";
				const overview = ledgerOverview(store, sessionId);
				md = toMarkdownOverview(
					{ ...overview, sessions: 1, range: { from, to } } as ReturnType<typeof ledgerOverviewAll>,
					`本会话 redteam 成果台账（${MODE_LABELS[mode] || mode} / ${sessionId}）`,
				);
				file = path.join(DATA_DIR, `overview-${sessionId}-${Date.now()}.md`);
			}
			try {
				fs.writeFileSync(file, md);
			} catch (e) {
				file = `(写盘失败：${(e as Error).message})`;
			}
			ctx.ui.notify(`redteam-results 已输出：${file}`, "info");
			if (ctx.mode === "tui") ctx.ui.setWidget("redteam-results", md.split("\n").slice(0, 40));
		},
	});
}

//#endregion
