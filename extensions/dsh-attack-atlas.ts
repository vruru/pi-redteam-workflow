import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const PLUGIN = "dsh-attack-atlas";
const DATA_DIR = path.join(os.homedir(), ".pi", "redteam", PLUGIN);
const DB_PATH = path.join(DATA_DIR, "atlas.db");
const MAX_TEXT = 12000;
const META_URL = import.meta.url;
/** 旧版（session-scoped）数据的新归属 scope；不删数据，只收拢到一个可查询的名字下。 */
const LEGACY_SCOPE = "legacy";

/**
 * 上游 lib 定位：环境变量 > 与扩展同包（打包发布形态）> 本地 redteam-model 仓库。
 * 上游文件只读 import，绝不修改（git pull 会覆盖它）。
 */
function upstreamUrl(name: string): string {
	const envHome = (process.env.PI_REDTEAM_ATLAS_LIB || "").trim();
	const envRepo = (process.env.PI_REDTEAM_HOME || "").trim();
	const cands: string[] = [];
	if (envHome) cands.push(path.join(envHome, name));
	if (envRepo) cands.push(path.join(envRepo, "plugins/dsh-attack-atlas/lib", name));
	try { cands.push(fileURLToPathSafe(`./upstream/attack-atlas-lib/${name}`)); } catch { }
	cands.push(path.join(os.homedir(), ".pi/agent/redteam-model/plugins/dsh-attack-atlas/lib", name));
	for (const c of cands) { try { if (fs.existsSync(c)) return "file://" + c; } catch { } }
	throw new Error(`找不到上游模块 ${name}；已尝试：${cands.join(" | ")}（可用 PI_REDTEAM_HOME 指向 redteam-model 仓库根，或 PI_REDTEAM_ATLAS_LIB 直接指向 lib 目录）`);
}
function fileURLToPathSafe(rel: string): string {
	const u = new URL(rel, META_URL);
	return decodeURIComponent(u.pathname);
}

/**
 * 一次性、幂等：把旧 session-scoped 行收拢到 legacy scope，同业务键只保留时间戳最新的一行。
 * 不动表结构、不改上游一行 SQL。
 */
function migrateLegacyScopes(): string {
	if (!fs.existsSync(DB_PATH)) return "无历史库，未迁移";
	const spec: Array<[string, string, string[]]> = [
		["coverage", "updated_at", ["mode", "target", "key"]],
		["stages", "updated_at", ["mode", "target", "stage"]],
		["chain_nodes", "created_at", ["mode", "target", "id"]],
		["chain_edges", "created_at", ["mode", "target", "src", "dst", "label"]],
		["targets", "created_at", ["mode", "seq"]],
	];
	const db = new DatabaseSync(DB_PATH);
	try {
		const names = new Set((db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as Array<{ name: string }>).map((r) => r.name));
		let moved = 0;
		let deduped = 0;
		for (const [table, tsCol, keyCols] of spec) {
			if (!names.has(table)) continue;
			const where = keyCols.map((c) => `"${c}"=?`).join(" AND ");
			const rows = db.prepare(`SELECT * FROM ${table} WHERE session_id NOT LIKE 'ws:%' AND session_id<>?`).all(LEGACY_SCOPE) as Array<Record<string, unknown>>;
			if (!rows.length) continue;
			const best = new Map<string, Record<string, unknown>>();
			for (const r of rows) {
				const k = keyCols.map((c) => String(r[c] ?? "")).join("\u0000");
				const cur = best.get(k);
				if (!cur || String(r[tsCol] ?? "") > String(cur[tsCol] ?? "")) best.set(k, r);
				else { db.prepare(`DELETE FROM ${table} WHERE session_id=? AND ${where}`).run(r.session_id as string, ...keyCols.map((c) => r[c])); deduped++; }
			}
			for (const r of best.values()) {
				const vals = keyCols.map((c) => r[c]);
				db.prepare(`DELETE FROM ${table} WHERE session_id=? AND ${where}`).run(LEGACY_SCOPE, ...vals);
				db.prepare(`UPDATE ${table} SET session_id=? WHERE session_id=? AND ${where}`).run(LEGACY_SCOPE, r.session_id as string, ...vals);
				moved++;
			}
		}
		if (moved || deduped) { try { fs.copyFileSync(DB_PATH, path.join(DATA_DIR, `atlas.pre-workspace-scope-${Date.now()}.db.bak`)); } catch { } }
		return `迁入 legacy ${moved} 行（同键去重 ${deduped} 行）`;
	} finally { try { db.close(); } catch { } }
}

const STATE_PRIORITY = ["tested-found", "tested-clear", "na", "budget-stop"];
const MODE_LABELS: Record<string, string> = {
	pentest: "渗透测试模式",
	"code-audit": "代码审计模式",
	"binary-analysis": "二进制分析模式",
	"attack-defense": "攻防评估模式",
	"av-evasion": "免杀对抗模式",
	"incident-response": "应急溯源模式",
	"cloud-security": "云安全攻防模式",
	"ctf-solver": "CTF 解题模式",
};

export default async function (pi: ExtensionAPI) {
	const tax = await import(upstreamUrl("taxonomy.js"));
	const sto = await import(upstreamUrl("store.js"));
	const met = await import(upstreamUrl("method.js"));

	const { ATLAS_MODES, CELL_STATES, STAGE_STATES, TAXONOMIES, locate } = tax;
	const {
		openStore, markCell, markStage, getCoverage, clearCoverage,
		addTarget, listTargets, removeTarget, switchTarget, getActiveTarget,
		addChainNode, addChainEdge, listChain, clearChain,
		CHAIN_NODE_KINDS, CHAIN_EDGE_TYPES, chainKindLabel, TARGET_KINDS, targetKindLabel,
		saveMethod, listMethods, getMethod, removeMethod, copyMethod, exportMethods, importMethods,
		saveCap, listCaps, removeCap, exportCaps, importCaps, recordMiss, missSummary,
	} = sto;
	const { validateMethod, normalizeGraph, METHOD_LIMITS, methodRunMessage, inferTargetKind } = met;

	const MODES: readonly string[] = ATLAS_MODES;
	const EDGE_TYPE_LABEL: Record<string, string> = CHAIN_EDGE_TYPES;

	let store: any;
	let migrationNote = "";
	function theStore(): any {
		if (!store) {
			migrationNote = migrateLegacyScopes();
			store = openStore(DB_PATH);
		}
		return store;
	}

	function clip(text: string): string {
		if (text.length <= MAX_TEXT) return text;
		return `${text.slice(0, MAX_TEXT)}\n\n[输出已截断（${text.length} 字符）——用 redteam_atlas_matrix 落盘或 /atlas 命令查全文]`;
	}

	function result<T>(text: string, details: T) {
		return { content: [{ type: "text" as const, text }], details };
	}

	function resolveMode(ctx: ExtensionContext, explicit?: string): string {
		const e = String(explicit ?? "").trim();
		if (e && MODES.includes(e)) return e;
		if (e) throw new Error(`未知模式 ${e}（合法：${MODES.join("、")}）`);
		try {
			const j = JSON.parse(fs.readFileSync(path.join(ctx.cwd, "operation-state.json"), "utf8"));
			if (MODES.includes(String(j?.mode ?? ""))) return String(j.mode);
		} catch { }
		throw new Error("无法确定专业模式——给工具传 mode 参数，或先用 operation_goal 登记目标契约");
	}

	function softMode(ctx: ExtensionContext, explicit?: unknown): string {
		const e = String(explicit ?? "").trim();
		if (MODES.includes(e)) return e;
		try {
			const j = JSON.parse(fs.readFileSync(path.join(ctx.cwd, "operation-state.json"), "utf8"));
			if (MODES.includes(String(j?.mode ?? ""))) return String(j.mode);
		} catch { }
		return "";
	}

	/**
	 * 工作区级 scope：目标/矩阵四态/阶段带/链路在同一工作区内跨会话延续。
	 * 上游以 session_id 为主键首位，这里只把实参换成稳定值，不改上游一行 SQL。
	 */
	function sessionIdOf(ctx: ExtensionContext): string {
		let root = ctx.cwd || process.cwd();
		try { root = fs.realpathSync(root); } catch { }
		return "ws:" + crypto.createHash("sha1").update(root).digest("hex").slice(0, 16);
	}

	/** 真实会话 id：只用于 miss 台账与来源可追溯。 */
	function liveSessionId(ctx: ExtensionContext): string {
		try { return String(ctx.sessionManager.getSessionId() ?? "unknown"); } catch { return "unknown"; }
	}

	function taxonomyFor(st: any, mode: string): any {
		const base = TAXONOMIES[mode];
		if (!base) throw new Error(`模式 ${mode} 无体系定义`);
		return taxonomyWithCaps(st, base, mode);
	}

	function enforceEvidence(state: string, findingRefs: unknown): void {
		if (state === "tested-found" && !String(findingRefs ?? "").trim()) {
			throw new Error("tested-found 须附证据引用（findingRefs：finding id / 证据编号 / 证据文件路径）——发现≠已验证，无证据引用不得点亮 confirmed 态");
		}
	}

	// ── 标签/终态归一（ Pi 侧最小适配层；逻辑同源 index.js 数据面） ──

	const LABEL_STRIP = /[\s·•,，、。.；;：:！!？?（）()\[\]【】「」『』/／\-—_~*"'`|｜\\#]/g;
	const FUZZY_MIN = 0.45;
	const FUZZY_MARGIN = 1.25;
	const FUZZY_INCOV = 0.6;

	function normLabel(s: unknown): string {
		return String(s ?? "").toLowerCase().normalize("NFKC").replace(/^\d{1,2}[\s.、．]+/, "").replace(LABEL_STRIP, "");
	}
	function bigramSet(s: string): Set<string> {
		const set = new Set<string>();
		for (let i = 0; i < s.length - 1; i++) set.add(s.slice(i, i + 2));
		return set;
	}
	function bestOf(cands: any[], norm: string): { ok: boolean; best?: any; top: any[] } {
		const inputGrams = bigramSet(norm);
		let best: any = null, second = 0;
		for (const c of cands) {
			const grams = bigramSet(normLabel(c.label));
			let hit = 0;
			for (const g of inputGrams) if (grams.has(g)) hit++;
			const score = inputGrams.size && grams.size ? (2 * hit) / (inputGrams.size + grams.size) : 0;
			const inputCov = inputGrams.size ? hit / inputGrams.size : 0;
			if (!best || score > best.score) { if (best) second = best.score; best = { ...c, score, inputCov }; }
			else if (score > second) second = score;
		}
		const top = cands.map((c) => {
			const grams = bigramSet(normLabel(c.label)); let hit = 0;
			for (const g of inputGrams) if (grams.has(g)) hit++;
			return { ...c, score: inputGrams.size && grams.size ? (2 * hit) / (inputGrams.size + grams.size) : 0 };
		}).sort((a: any, b: any) => b.score - a.score).slice(0, 5);
		const ok = !!(best && inputGrams.size >= 3 && best.score >= FUZZY_MIN && best.score >= FUZZY_MARGIN * Math.max(second, 0.01) && best.inputCov >= FUZZY_INCOV);
		return { ok, best, top };
	}

	function keyLabel(taxonomy: any, key: string): string {
		const [catId, itemId] = String(key).split("/");
		const cat = taxonomy.categories.find((c: any) => c.id === catId);
		if (!cat) return key;
		if (itemId === undefined) return cat.label;
		return `${cat.label}/${cat.items.find((i: any) => i.id === itemId)?.label ?? itemId}`;
	}

	function resolveKey(taxonomy: any, input: unknown): any {
		const raw = String(input ?? "").trim();
		if (!raw) return null;
		const norm = normLabel(raw);
		if (!norm) return null;
		for (const [aliasKey, ref] of Object.entries(taxonomy.aliases ?? {})) {
			if (normLabel(aliasKey) === norm) {
				if (String(ref).includes("/")) {
					const [cId, iId] = String(ref).split("/");
					const c = taxonomy.categories.find((x: any) => x.id === cId);
					if (c?.items.some((it: any) => it.id === iId)) return { key: String(ref), catId: cId, itemId: iId, via: "alias" };
				} else {
					const c = taxonomy.categories.find((x: any) => x.id === ref);
					if (c) return { key: c.id, catId: c.id, via: "alias" };
				}
			}
		}
		if (raw.includes("/")) {
			const idx = raw.indexOf("/");
			const catId = raw.slice(0, idx), itemIdRaw = raw.slice(idx + 1);
			const cat = taxonomy.categories.find((c: any) => c.id === catId);
			if (cat) {
				if (cat.items.some((it: any) => it.id === itemIdRaw)) return { key: `${catId}/${itemIdRaw}`, catId, itemId: itemIdRaw, via: "id" };
				const items = cat.items.map((it: any) => ({ key: `${catId}/${it.id}`, catId, itemId: it.id, label: it.label }));
				for (const it of items) if (normLabel(it.label) === normLabel(itemIdRaw)) return { ...it, via: "label" };
				const hits = items.filter((it: any) => { const l = normLabel(it.label); return l.includes(normLabel(itemIdRaw)) || normLabel(itemIdRaw).includes(l); });
				if (hits.length === 1) return { ...hits[0], via: "contains" };
				const b = bestOf(items, normLabel(itemIdRaw));
				if (b.ok) return { key: b.best.key, catId, itemId: b.best.itemId, via: "fuzzy" };
				if (b.best && b.best.score >= FUZZY_MIN) return { ambiguous: b.top.filter((x: any) => x.score >= FUZZY_MIN).map((x: any) => ({ key: x.key, catId, itemId: x.itemId })) };
				return { missingItem: { catId, input: raw } };
			}
		}
		const allItems: any[] = [];
		for (const c of taxonomy.categories) for (const it of c.items) allItems.push({ key: `${c.id}/${it.id}`, catId: c.id, itemId: it.id, label: it.label });
		for (const it of allItems) if (normLabel(it.label) === norm) return { ...it, via: "label" };
		const catExact = taxonomy.categories.find((c: any) => normLabel(c.label) === norm);
		if (catExact) return { key: catExact.id, catId: catExact.id, via: "label" };
		const shortAscii = /^[a-z0-9]{1,4}$/.test(norm);
		const tokenHit = (label: string) => {
			const l = normLabel(label);
			if (l.includes(norm)) {
				if (!shortAscii) return true;
				let i = l.indexOf(norm);
				while (i !== -1) {
					const before = i === 0 ? "" : l[i - 1];
					const after = i + norm.length >= l.length ? "" : l[i + norm.length];
					if (!/[a-z0-9]/.test(before) && !/[a-z0-9]/.test(after)) return true;
					i = l.indexOf(norm, i + 1);
				}
				return false;
			}
			return norm.includes(l);
		};
		const hits = allItems.filter((it: any) => tokenHit(it.label));
		const catHits = taxonomy.categories.filter((c: any) => tokenHit(c.label));
		if (hits.length === 1) return { ...hits[0], via: "contains" };
		if (hits.length > 1) {
			const prefixed = hits.filter((it: any) => normLabel(it.label).startsWith(norm));
			const pool = prefixed.length ? prefixed : hits;
			if (pool.length === 1) return { ...pool[0], via: "contains" };
			const byLen = [...pool].sort((a: any, b: any) => normLabel(a.label).length - normLabel(b.label).length);
			if (normLabel(byLen[0].label).length < normLabel(byLen[1].label).length) return { ...byLen[0], via: "contains" };
			return { ambiguous: byLen.slice(0, 6).map((h: any) => ({ key: h.key, catId: h.catId, itemId: h.itemId })) };
		}
		if (catHits.length === 1) return { key: catHits[0].id, catId: catHits[0].id, via: "contains" };
		if (shortAscii) return null;
		const bi = bestOf(allItems, norm);
		const bc = bestOf(taxonomy.categories.map((c: any) => ({ key: c.id, catId: c.id, label: c.label })), norm);
		if (bi.ok && (!bc.best || bi.best.score >= bc.best.score)) return { key: bi.best.key, catId: bi.best.catId, itemId: bi.best.itemId, via: "fuzzy" };
		if (bc.ok) return { key: bc.best.key, catId: bc.best.key, via: "fuzzy-cat" };
		if (bi.best && bi.best.score >= FUZZY_MIN && bi.best.inputCov >= FUZZY_INCOV) return { ambiguous: bi.top.filter((x: any) => x.score >= FUZZY_MIN).map((x: any) => ({ key: x.key, catId: x.catId, itemId: x.itemId })) };
		return null;
	}

	function canonicalKey(taxonomy: any, input: unknown): string | undefined {
		return resolveKey(taxonomy, input)?.key;
	}

	function validateCoverageRef(taxonomy: any, key: unknown): string {
		const raw = String(key ?? "").trim();
		if (!raw) return "key 不能为空（形如 cat/item 或 cat，也接受主类/格子中文标签）";
		const res = resolveKey(taxonomy, raw);
		if (res?.key) return "";
		if (res?.missingItem) {
			const cat = taxonomy.categories.find((c: any) => c.id === res.missingItem.catId);
			return `子项不存在：「${raw}」——主类「${cat?.label ?? res.missingItem.catId}」合法子项：${(cat?.items ?? []).map((it: any) => `${it.label}(${cat.id}/${it.id})`).join("、")}`;
		}
		if (res?.ambiguous) return `「${raw}」无法唯一解析（命中多格）：${res.ambiguous.map((a: any) => keyLabel(taxonomy, a.key)).join("、")}——请写完整标签或 cat/item 形式 key`;
		return `主类不存在：「${raw}」（不在${taxonomy.label}体系）。合法主类：${taxonomy.categories.map((c: any) => `${c.label}(${c.id})`).join("、")}；key=主类id 或 主类id/子项id，也接受中文标签`;
	}

	function resolveStageId(taxonomy: any, input: unknown): string {
		const raw = String(input ?? "").trim();
		if (!raw) return "";
		const stages = taxonomy.stages ?? [];
		for (const s of stages) if (s.id === raw) return s.id;
		const norm = normLabel(raw);
		for (const s of stages) if (normLabel(s.label) === norm) return s.id;
		for (const s of stages) { const l = normLabel(s.label); if (l.includes(norm) || norm.includes(l)) return s.id; }
		const b = bestOf(stages.map((s: any) => ({ key: s.id, label: s.label })), norm);
		return b.ok ? b.best.key : "";
	}

	function validateStageRef(taxonomy: any, stage: unknown): string {
		const raw = String(stage ?? "").trim();
		if (resolveStageId(taxonomy, raw)) return "";
		return `阶段不存在：「${raw}」（不在${taxonomy.label}作战流程）。合法阶段：${(taxonomy.stages ?? []).map((s: any) => `${s.id} ${s.label}`).join("、")}——也接受阶段中文标签`;
	}

	const STATE_ALIASES: Array<[string, string[]]> = [
		["tested-found", ["已测有发现", "已审有finding", "有finding", "走通", "有战果", "发现", "过检"]],
		["tested-clear", ["已测未命中", "已审无finding", "无finding", "未走通", "未命中", "被检出", "卡点"]],
		["na", ["不适用"]],
		["budget-stop", ["未完成", "让位", "预算耗尽", "预算", "未测", "未开", "未查", "未分析"]],
	];
	for (const _t of Object.values(TAXONOMIES)) {
		const t = _t as any;
		if (!t.stateLabels) continue;
		for (const [canonical, label] of Object.entries(t.stateLabels)) {
			const n = normLabel(label);
			const row = STATE_ALIASES.find(([c]) => c === canonical);
			if (row && !row[1].includes(n)) row[1].push(n);
		}
	}

	function resolveStateLabel(input: unknown): string {
		const raw = String(input ?? "").trim().toLowerCase();
		if (CELL_STATES.includes(raw)) return raw;
		const norm = normLabel(raw);
		if (!norm) return "";
		for (const [canonical, aliases] of STATE_ALIASES) {
			if (norm === normLabel(canonical) || aliases.includes(norm)) return canonical;
		}
		const hits = new Set<string>();
		for (const [canonical, aliases] of STATE_ALIASES) {
			for (const a of aliases) {
				if (norm.includes(a) || a.includes(norm)) { hits.add(canonical); break; }
			}
		}
		if (hits.size === 1) return [...hits][0];
		return "";
	}

	function capFormsOf(taxonomy: any, raw: string): string[] {
		const ids = new Set((taxonomy.forms || []).map((f: any) => f.id));
		return String(raw ?? "").split(/[,，;；\s]+/).map((s) => s.trim()).filter((s) => ids.has(s));
	}

	function taxonomyWithCaps(st: any, taxonomy: any, mode: string): any {
		const caps = listCaps(st, mode);
		const itemsByCat: Record<string, any[]> = {};
		for (const c of caps) if (c.kind === "item") (itemsByCat[c.cat] = itemsByCat[c.cat] || []).push(c);
		const capItemNode = (i: any): any => {
			const fs = capFormsOf(taxonomy, i.forms);
			return { id: i.item, label: i.label, ref: i.ref || undefined, pb: i.pb || undefined, ...(fs.length ? { forms: fs } : {}), _cap: i };
		};
		const categories = taxonomy.categories.map((c: any) => {
			const extra = (itemsByCat[c.id] || []).map(capItemNode);
			return extra.length ? { ...c, items: c.items.concat(extra) } : c;
		});
		const formCategories: Record<string, string[]> = { ...(taxonomy.formCategories || {}) };
		for (const c of caps) {
			if (c.kind !== "category") continue;
			const fs = capFormsOf(taxonomy, c.forms);
			for (const f of fs) formCategories[f] = [...(formCategories[f] || []), c.cat];
			categories.push({ ...c, id: c.cat, label: c.label, desc: c.descr, ...(fs.length ? { forms: fs } : {}), _cap: c, items: (itemsByCat[c.cat] || []).map(capItemNode) });
		}
		return { ...taxonomy, categories, formCategories };
	}

	const MODE_POSTURE: Record<string, string> = {
		pentest: "按 playbook 验证姿势执行（最小影响、非破坏性）",
		"code-audit": "按 playbook 审计姿势执行（扫描链禁网；结论须 sink 指位与复现链）",
		"attack-defense": "按 playbook 验证姿势执行（最小影响、非破坏性）",
		"cloud-security": "按 playbook 验证姿势执行（只读探测优先、最小影响）",
		"binary-analysis": "按 playbook 分析姿势执行（样本不外传；动态分析须隔离环境）",
		"av-evasion": "按 playbook 实验姿势执行（本地默认验证；授权目标按任务）",
		"incident-response": "按 playbook 取证姿势执行（先保全后分析、只读优先）",
		"ctf-solver": "按 playbook 解题姿势执行（平台规则内，flag 以平台回显为准）",
	};
	const MODE_VERB: Record<string, string> = {
		"code-audit": "审计", "binary-analysis": "分析", "incident-response": "排查", "av-evasion": "实验",
	};
	const verbOf = (taxonomy: any): string => MODE_VERB[taxonomy?.id] || "开测";
	const postureOf = (taxonomy: any): string => MODE_POSTURE[taxonomy?.id] || MODE_POSTURE.pentest;
	function trioWords(taxonomy: any): string {
		const sl = taxonomy.stateLabels || {};
		return `${sl["tested-found"] || "已测·有发现"} / ${sl["tested-clear"] || "已测·未命中"} / ${sl.na || "N-A 附原因"}`;
	}
	const MODE_REQUIREMENT: Record<string, (trio: string) => string> = {
		"code-audit": (trio) => `要求：子项逐格审计，每格终态三选一（${trio}），逐格调用 redteam_coverage_mark 回写；finding 即 redteam_finding_register 登记（附复现链与 sink 指位，双链命中对账）；扫描链禁网，深度审计链按面映射推进。`,
		"binary-analysis": (trio) => `要求：子项逐格分析，每格终态三选一（${trio}），逐格调用 redteam_coverage_mark 回写；有结论即 redteam_finding_register 登记（附能力与危害判定、IOC 假设指位）；静态优先、动态须隔离环境，样本外传须登记，假设台账同步更新。`,
		"av-evasion": (trio) => `要求：子项逐格实验，每格终态三选一（${trio}），逐格调用 redteam_coverage_mark 回写；检出/过检即 redteam_finding_register 登记（附判定环境与判定依据）；判定环境以 experiment-plan 为基线不污染，本地默认验证。`,
		"incident-response": (trio) => `要求：子项逐格排查，每格终态三选一（${trio}），逐格调用 redteam_coverage_mark 回写；查实 IOC/入侵痕迹即 redteam_finding_register 登记（附证据指位与时间线位置）；先保全后分析、只读优先，不扰动现场。`,
		"ctf-solver": (trio) => `要求：子项逐格推进，每格终态三选一（${trio}），逐格调用 redteam_coverage_mark 回写；解出即 redteam_finding_register 登记（附 flag 与解题路径）；平台规则即边界，题面登记与 challenge-board 同步。`,
	};
	const requirementOf = (taxonomy: any, trio: string): string => (MODE_REQUIREMENT[taxonomy?.id] ?? ((t: string) => `要求：子项逐格推进，每格终态三选一（${t}），逐格调用 redteam_coverage_mark 回写；发现即 redteam_finding_register 登记；速率与红线照 playbook 执行。`))(trio);
	const MODE_ANCHOR: Record<string, { word: string; obj: string; reg: string; baseline: string; discipline: string; detail: string }> = {
		"code-audit": { word: "对象", obj: "审计对象", reg: "开工先确认仓库/版本范围并调 redteam_atlas_target 登记审计对象（应用/模块组/源码仓库）", baseline: "面映射基线（入口清单+sink 面）", discipline: "不超出约定审计范围", detail: "入口清单与 sink 面见面映射表" },
		"binary-analysis": { word: "样本", obj: "样本", reg: "先过样本登记（B0：sha256/形态/来源）并调 redteam_atlas_target 登记", baseline: "样本登记与假设台账", discipline: "按受理样本分析，样本外传须登记", detail: "样本档案与假设台账见 B0 登记产物" },
		"av-evasion": { word: "对象", obj: "在验载荷", reg: "先调 redteam_atlas_target 登记实验对象（生成的 shell/载荷/引擎族）", baseline: "experiment-plan 判定环境清单", discipline: "本地默认验证；授权目标按任务执行", detail: "判定环境与实验课题见 experiment-plan" },
		"incident-response": { word: "范围", obj: "调查对象", reg: "受理后先调 redteam_atlas_target 登记调查对象（受侵主机/案件）", baseline: "证据保全清单", discipline: "先保全后分析，不超出受理范围", detail: "主机与证据明细见保全清单" },
		"cloud-security": { word: "目标", obj: "云目标", reg: "先调 redteam_atlas_target 登记云目标（账号/租户/集群）", baseline: "cloud-assets.md 测绘基线", discipline: "只读探测优先；环境改动逐项登记还原", detail: "资产明细见 cloud-assets.md 暴露面测绘" },
		"ctf-solver": { word: "对象", obj: "题目", reg: "先调 redteam_atlas_target 登记题目/赛局", baseline: "challenge-board.md 题面登记", discipline: "平台规则即边界", detail: "题面与解题进度见 challenge-board" },
	};
	function anchorLines(taxonomy: any, targets: any[]): string {
		const cfg = MODE_ANCHOR[taxonomy?.id ?? ""];
		const word = cfg ? cfg.word : "目标";
		if (!targets || targets.length === 0) {
			if (cfg) return `${cfg.word}锚定：本会话尚未登记${cfg.obj}——${cfg.reg}（与${cfg.baseline}同步），${cfg.discipline}。`;
			return "目标锚定：本会话尚未登记目标——开测前先确认授权目标（单位/资产域，组织类 kind=org）并调 redteam_atlas_target 登记（与资产清单基线 assets.md 同步），严格不超出授权范围。";
		}
		const labelOf = (t: any) => `「${t.label}」${targetKindLabel(t.kind)}`;
		const tail = cfg
			? `（${cfg.detail}；换${cfg.word}作业先 redteam_atlas_target switch 切锚再回写，回写不带 target 默认归当前锚定，异${cfg.obj}须带 target 参数注明；N-A 须注明对哪个${cfg.obj}不具备）`
			: `（资产明细见 assets.md/入口面盘点表；换目标作业先 redteam_atlas_target switch 切锚再回写，回写不带 target 默认归当前锚定，异目标须带 target 参数注明；N-A 须注明对哪个目标不具备）`;
		const act = targets.find((t) => t.active);
		if (!act) return `${word}锚定：${targets.map(labelOf).join("、")}${tail}`;
		const rest = targets.filter((t) => t !== act).map(labelOf).join("、");
		return `${word}锚定：当前锚定 ${labelOf(act)}${rest ? `；其余已登记：${rest}` : ""}${tail}`;
	}
	function triggerMessage(taxonomy: any, payload: any): string {
		const formLabel = payload.formId && payload.formId !== "all" ? `｜形态「${(taxonomy.forms.find((f: any) => f.id === payload.formId) || {}).label || payload.formId}」` : "";
		if (payload.level === "stage") {
			const stage = taxonomy.stages.find((s: any) => s.id === payload.stageId);
			return [`[AttackAtlas·阶段推进] 进入阶段「${stage ? stage.label : payload.stageId}」（${taxonomy.label}模式作战流程）。`, `按 playbook 该阶段章节执行；完成后调用 redteam_coverage_stage(stage="${payload.stageId}", state="done") 回写点亮。`, anchorLines(taxonomy, payload.targets)].join("\n");
		}
		if (payload.level === "category") {
			const category = taxonomy.categories.find((c: any) => c.id === payload.categoryId);
			return [`[AttackAtlas·主类派单] 对主类「${category ? category.label : payload.categoryId}」整组${verbOf(taxonomy)}（${taxonomy.label}模式${formLabel}）。`, requirementOf(taxonomy, trioWords(taxonomy)), anchorLines(taxonomy, payload.targets)].join("\n");
		}
		const loc = locate(taxonomy, `${payload.categoryId}/${payload.itemId}`);
		const category = loc?.category;
		const item = loc?.item;
		let refHint = "";
		if (item?.ref) { const pre = `${verbOf(taxonomy)}前先读`; refHint = item.ref.startsWith("pentest:") ? `\n知识手册：pentest refs/${item.ref.slice(8)}（${pre}）` : item.ref === "README.md" ? `\n知识手册：refs/README.md（按目标语言快速路由到对应语言手册后再读——语言类格子不预设语言）` : `\n知识手册：refs/${item.ref}（${pre}）`; }
		else if (item?.pb) refHint = `\n打法出处：本模式 playbook ${item.pb}`;
		return [`[AttackAtlas·格子派单] 对以下格子${verbOf(taxonomy)}（${taxonomy.label}模式${formLabel}）：`, `主类「${category ? category.label : payload.categoryId}」｜子项「${item ? item.label : payload.itemId}」${refHint}`, `${postureOf(taxonomy)}；终态三选一（${trioWords(taxonomy)}），完成后调用 redteam_coverage_mark 回写点亮；有发现即 redteam_finding_register 登记。`, anchorLines(taxonomy, payload.targets)].join("\n");
	}

	function parseCoverageTable(text: string): any[] {
		const rows: any[] = [];
		const lines = String(text ?? "").split(/\r?\n/);
		let cols: any = null;
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i].trim();
			if (!line.startsWith("|")) { if (cols) break; continue; }
			const cells = line.replace(/^\|/, "").split("|").map((c) => c.trim());
			if (cells.length && cells[cells.length - 1] === "") cells.pop();
			if (cells.every((c) => /^:?-{2,}:?$/.test(c))) continue;
			if (!cols) {
				const norm = cells.map((c) => normLabel(c));
				const keyCol = norm.findIndex((c) => c.includes("格子") || c === "key");
				const stateCol = norm.findIndex((c) => c.includes("终态") || c === "state");
				if (keyCol < 0 || stateCol < 0) continue;
				cols = { key: keyCol, state: stateCol, reason: norm.findIndex((c) => c.includes("原因")), finding: norm.findIndex((c) => c.includes("finding")), target: norm.findIndex((c) => c.includes("目标")) };
				continue;
			}
			const at = (idx: number) => (idx >= 0 && idx < cells.length ? cells[idx] : "");
			rows.push({ key: at(cols.key), state: at(cols.state), reason: at(cols.reason), findingRefs: at(cols.finding), target: at(cols.target), line: i + 1 });
		}
		return rows;
	}

	function applyCoverageRows(st: any, taxonomy: any, sessionId: string, mode: string, rows: any[]): { applied: string[]; failed: string[] } {
		const applied: string[] = [];
		const failed: string[] = [];
		let n = 0;
		for (const row of rows) {
			n++;
			const where = row.line ? `第 ${row.line} 行` : `rows[${n - 1}]`;
			const keyRaw = String(row.key ?? "").trim();
			const state = resolveStateLabel(row.state);
			if (!keyRaw) { failed.push(`${where}：格子列为空，跳过`); continue; }
			if (!state) { failed.push(`${where}：「${row.state}」不是合法终态，跳过`); continue; }
			let key = keyRaw;
			if (taxonomy) {
				const bad = validateCoverageRef(taxonomy, keyRaw);
				if (bad) { failed.push(`${where}：${bad}，跳过`); continue; }
				key = canonicalKey(taxonomy, keyRaw) ?? keyRaw;
			}
			try {
				markCell(st, sessionId, mode, key, { state, reason: String(row.reason ?? ""), findingRefs: String(row.findingRefs ?? ""), target: String(row.target ?? "") });
				applied.push(key);
			} catch (e: any) {
				failed.push(`${where}：${e?.message ?? e}，跳过`);
			}
		}
		return { applied, failed };
	}

	const GATE_STAGE: Record<string, Record<string, string>> = {
		pentest: { "P1": "s1", "P2": "s5", "P3": "s6" },
		"code-audit": { "A1": "s1", "A2": "s4", "A3": "s5" },
		"binary-analysis": { "B0": "s1", "B1": "s4", "B2": "s5" },
		"attack-defense": { "recon": "s1", "breach": "s2", "lateral": "s3", "persistence": "s4", "report": "s5" },
		"av-evasion": { "V1": "s2", "V2": "s4", "V3": "s5", "V4": "s6" },
		"incident-response": { "I1": "s1", "I2": "s3", "I3": "s4", "I4": "s5", "I5": "s6" },
		"cloud-security": { "C1": "s1", "C2": "s2", "C3": "s3", "C4": "s4", "C5": "s5", "C6": "s6", "C7": "s7" },
		"ctf-solver": { "board": "s1", "flag": "s3" },
	};
	const GATE_NO_FILL: Record<string, string[]> = {
		"pentest/P2": ["s3", "s5"], "pentest/P3": ["s3"],
		"code-audit/A2": ["s3", "s4"], "code-audit/A3": ["s3"],
		"binary-analysis/B1": ["s3", "s4"], "binary-analysis/B2": ["s3"],
		"av-evasion/V3": ["s5"],
	};
	function parseGatePassText(text: unknown): { mode: string; gate: string } | null {
		const m = /^stage_gate ([\w-]+)\/([\w-]+)(?:（[^）]*）)?: PASS/.exec(String(text ?? ""));
		return m ? { mode: m[1], gate: m[2] } : null;
	}
	function autoStageFromGate(st: any, taxonomy: any, sessionId: string, mode: string, gateId: string): string[] {
		const target = GATE_STAGE[mode]?.[gateId];
		if (!target) return [];
		const stages = taxonomy?.stages ?? [];
		const idx = stages.findIndex((s: any) => s.id === target);
		if (idx < 0) return [];
		const marked: string[] = [];
		const noFill = GATE_NO_FILL[`${mode}/${gateId}`] ?? [];
		for (let i = 0; i <= idx; i++) {
			if (noFill.includes(stages[i].id)) continue;
			try { markStage(st, sessionId, mode, stages[i].id, "done"); marked.push(stages[i].id); } catch { }
		}
		return marked;
	}

	const CWE_LABELS: Record<number, string> = {
		78: "命令执行", 77: "命令注入", 89: "SQL 注入", 79: "XSS", 22: "路径穿越", 918: "SSRF",
		611: "XXE", 502: "反序列化", 674: "反序列化", 94: "代码注入", 917: "表达式注入", 915: "表达式注入",
		434: "任意文件上传", 98: "文件包含", 73: "文件读写", 352: "CSRF", 287: "认证绕过", 862: "未授权访问",
		798: "硬编码凭据", 321: "硬编码凭据", 327: "密码学实现误用", 362: "并发", 840: "业务逻辑", 1336: "正则拒绝服务",
		269: "权限提升", 522: "密钥泄露", 863: "权限提升",
	};
	function cweToLabel(cwe: unknown): string {
		const m = /(\d+)/.exec(String(cwe ?? ""));
		return m ? (CWE_LABELS[Number(m[1])] ?? "") : "";
	}

	// ── 矩阵渲染 ──

	const STATE_SYMBOL: Record<string, string> = { "tested-found": "■", "tested-clear": "□", na: "⌀", "budget-stop": "×" };
	function aggregateCells(cells: any[]): Map<string, any> {
		const map = new Map<string, any>();
		for (const c of cells) {
			let agg = map.get(c.key);
			if (!agg) { agg = { state: "", reason: "", findingRefs: "", perTarget: new Map() }; map.set(c.key, agg); }
			agg.perTarget.set(c.target || "(公共)", c.state);
			const cur = STATE_PRIORITY.indexOf(agg.state);
			const next = STATE_PRIORITY.indexOf(c.state);
			if (next >= 0 && (cur < 0 || next < cur)) { agg.state = c.state; agg.reason = c.reason; agg.findingRefs = c.findingRefs; }
		}
		return map;
	}
	function stageStateOf(stages: any[], stageId: string, target?: string): string {
		const rows = stages.filter((s) => s.stage === stageId && (target === undefined || s.target === target));
		if (!rows.length) return "";
		if (rows.some((s) => s.state === "done")) return "done";
		return rows[0].state;
	}
	function esc(s: string): string { return String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " "); }
	function categoriesInForm(taxonomy: any, form?: string): any[] {
		if (!form || form === "all") return taxonomy.categories;
		const ids = new Set(taxonomy.formCategories?.[form] ?? []);
		return taxonomy.categories.filter((c: any) => ids.has(c.id));
	}
	function itemsInForm(taxonomy: any, category: any, form?: string): any[] {
		if (form && form !== "all" && category.forms && !category.forms.includes(form)) return [];
		return category.items.filter((i: any) => !i.forms || !form || form === "all" || i.forms.includes(form));
	}
	function nowStamp(): string { return new Date().toISOString().replace("T", " ").slice(0, 19); }
	function matrixFilePath(cwd: string, mode: string, target?: string): string {
		const tgt = target !== undefined ? `-${(target || "public").replace(/[^\w.-]+/g, "_").slice(0, 40)}` : "";
		return path.join(cwd, `attack-atlas-${mode}${tgt}.md`);
	}
	function renderMatrixMarkdown(opts: any): string {
		const { taxonomy, mode, cells, stages, targets, form, target, generatedAt } = opts;
		const sl = taxonomy.stateLabels ?? {};
		const legend = `■=${sl["tested-found"] ?? "tested-found"} □=${sl["tested-clear"] ?? "tested-clear"} ⌀=${sl.na ?? "na"} ×=${sl["budget-stop"] ?? "budget-stop"} ·=未测`;
		const view = target !== undefined ? `目标「${target || "(公共 scope)"}」` : "聚合并集（全部目标）";
		const formLabel = form && form !== "all" ? (taxonomy.forms.find((f: any) => f.id === form)?.label ?? form) : "全部形态";
		const anchor = targets.find((t: any) => t.active)?.label ?? "（无）";
		const scoped = target !== undefined ? cells.filter((c: any) => c.target === target) : cells;
		const agg = aggregateCells(scoped);
		const lines: string[] = [`# AttackAtlas 攻击面矩阵 — ${MODE_LABELS[mode] ?? mode}`, "", `- 生成时间：${generatedAt}`, `- 模式：${mode}（${taxonomy.label}）`, `- 视图：${view}｜形态：${formLabel}｜当前锚定：${anchor}`, `- 已登记目标：${targets.length ? targets.map((t: any) => `${t.label}${t.active ? "（锚）" : ""}`).join("、") : "（无）"}`, `- 图例：${legend}`, `- 真值分工：门禁/阶段判定真值见 gate-log.md 与 operation-state.json（dsh-stage-gate）；本矩阵是覆盖态台账。`, "", "## 阶段带", "", "| 阶段 | 状态 |", "|---|---|"];
		for (const s of taxonomy.stages) lines.push(`| ${s.id} ${esc(s.label)} | ${stageStateOf(stages, s.id, target) || "·"} |`);
		const counts: Record<string, number> = {}; let untested = 0; let total = 0;
		for (const c of categoriesInForm(taxonomy, form)) {
			for (const it of itemsInForm(taxonomy, c, form)) {
				total++;
				const a = agg.get(`${c.id}/${it.id}`);
				if (a?.state) counts[a.state] = (counts[a.state] ?? 0) + 1; else untested++;
			}
		}
		lines.push("", "## 覆盖汇总", "", "| 终态 | 格数 |", "|---|---|");
		for (const st of STATE_PRIORITY) if (counts[st]) lines.push(`| ${st}（${sl[st] ?? st}） | ${counts[st]} |`);
		lines.push(`| 未测 | ${untested} |`, `| 合计 | ${total} |`, "", "## 矩阵", "");
		const zones: any[] = taxonomy.zones ?? [];
		let lastZone: string | undefined;
		for (const c of categoriesInForm(taxonomy, form)) {
			const items = itemsInForm(taxonomy, c, form);
			if (!items.length) continue;
			if (zones.length && c.zone !== lastZone) { lastZone = c.zone; const z = zones.find((x: any) => x.id === c.zone); if (z) lines.push(`### 战场·${esc(z.label)}`, ""); }
			const capTag = c._cap ? "（自定义）" : "";
			lines.push(`#### ${esc(c.label)}${capTag} \`${c.id}\`${c.desc ? ` — ${esc(c.desc)}` : ""}`, "", "| 子项 | key | 终态 | 原因 | findingRefs | 目标明细 |", "|---|---|---|---|---|---|");
			for (const it of items) {
				const key = `${c.id}/${it.id}`;
				const a = agg.get(key);
				const state = a?.state ?? "";
				const per = a ? [...a.perTarget.entries()].map(([t, s]) => `${t}:${s}`).join(" ") : "";
				const refs = [it.ref ? `ref:${it.ref}` : "", it.pb ? `pb:${it.pb}` : ""].filter(Boolean).join(" ");
				lines.push(`| ${esc(it.label)}${it._cap ? "（自定义）" : ""} | \`${key}\` | ${state ? `${STATE_SYMBOL[state] ?? ""} ${state}` : "·"} | ${esc(a?.reason ?? "")} | ${esc(a?.findingRefs ?? "")} | ${esc(per)}${refs ? ` ${esc(refs)}` : ""} |`);
			}
			lines.push("");
		}
		return lines.join("\n");
	}
	function renderMatrixCompact(opts: any): string {
		const { taxonomy, mode, cells, stages, targets, form, target } = opts;
		const anchor = targets.find((t: any) => t.active)?.label ?? "—";
		const scoped = target !== undefined ? cells.filter((c: any) => c.target === target) : cells;
		const agg = aggregateCells(scoped);
		const stagePart = taxonomy.stages.map((s: any) => stageStateOf(stages, s.id, target) === "done" ? `${s.id}✓` : stageStateOf(stages, s.id, target) === "active" ? `${s.id}▶` : s.id).join(" ");
		const lines = [`AttackAtlas ${mode}（${taxonomy.label}）｜锚=${anchor}｜视图=${target !== undefined ? (target || "公共") : "聚合"}｜图例 ■有发现 □未命中 ⌀N-A ×让位 ·未测`, `阶段带: ${stagePart}`];
		for (const c of categoriesInForm(taxonomy, form)) {
			const items = itemsInForm(taxonomy, c, form);
			if (!items.length) continue;
			let done = 0;
			const band = items.map((it: any) => { const a = agg.get(`${c.id}/${it.id}`); if (a?.state) done++; return a?.state ? (STATE_SYMBOL[a.state] ?? "?") : "·"; }).join("");
			lines.push(`${c.id.padEnd(18)} ${band}  ${done}/${items.length} ${c.label}`);
		}
		return lines.join("\n");
	}

	function refreshStatus(ctx: ExtensionContext): void {
		if (ctx.mode !== "tui") return;
		try {
			const mode = softMode(ctx);
			if (!mode) { ctx.ui.setStatus("attack-atlas", undefined); return; }
			const cov = getCoverage(theStore(), sessionIdOf(ctx), mode);
			const anchor = cov.targets.find((t: any) => t.active)?.label ?? "—";
			const doneStages = new Set(cov.stages.filter((s: any) => s.state === "done").map((s: any) => s.stage)).size;
			const totalStages = TAXONOMIES[mode]?.stages.length ?? 0;
			ctx.ui.setStatus("attack-atlas", `Atlas ${mode} 锚=${anchor} 格=${cov.cells.length} 阶段=${doneStages}/${totalStages}`);
		} catch { }
	}
	function notify(ctx: ExtensionContext, text: string, type: "info" | "warning" | "error" = "info"): void {
		try { ctx.ui.notify(text, type); } catch { }
		// print/JSON 模式没有 UI sink；不补回显会让人以为命令未执行（命令只写了文件）。
		if (!ctx.hasUI) process.stdout.write(text + "\n");
	}

	// ── 工具注册 ──

	const modeParam = Type.Optional(Type.String({ description: `专业模式（${MODES.join("/")}）；缺省读工作区 operation-state.json 的 mode` }));

	pi.on("session_start", (_e: any, ctx: ExtensionContext) => {
		theStore();
		refreshStatus(ctx);
	});
	pi.on("session_shutdown", () => {
		if (store) { try { store.close(); } catch { } store = undefined; }
	});

	pi.registerTool({
		name: "redteam_atlas_target",
		label: "atlas target",
		description: "登记/切换/查看 AttackAtlas 作战目标。覆盖态按目标分账。add=登记（首个自动锚定并把公共 scope 存量扫入它）；switch=切锚；remove=删除目标并级联清理其数据。",
		promptSnippet: "登记/切换作战目标（锚定）",
		executionMode: "sequential",
		parameters: Type.Object({
			action: Type.Union([Type.Literal("add"), Type.Literal("switch"), Type.Literal("list"), Type.Literal("remove")]),
			label: Type.Optional(Type.String()),
			kind: Type.Optional(Type.String({ description: `目标形态（${TARGET_KINDS.join("/")}）` })),
			note: Type.Optional(Type.String()),
			seq: Type.Optional(Type.Number()),
			mode: modeParam,
		}),
		async execute(_id: any, args: any, _signal: any, _onUpdate: any, ctx: ExtensionContext) {
			const st = theStore();
			const mode = resolveMode(ctx, args.mode);
			const sessionId = sessionIdOf(ctx);
			if (args.action === "list") {
				const targets = listTargets(st, sessionId, mode);
				const anchor = targets.find((t: any) => t.active)?.label ?? "无";
				return result(`本会话目标 ${targets.length} 个（当前锚定：${anchor}）：${targets.map((t: any) => `${t.seq}.${t.label}（${targetKindLabel(t.kind)}）${t.active ? "（锚）" : ""}`).join("、") || "（无）"}`, { ok: true, targets });
			}
			if (args.action === "switch") {
				const which = args.label !== undefined && String(args.label) !== "" ? String(args.label) : Number(args.seq);
				const t = switchTarget(st, sessionId, mode, which);
				refreshStatus(ctx);
				return result(`锚定已切换：${t.label}（${targetKindLabel(t.kind)}）`, { ok: true, switched: t.seq, label: t.label });
			}
			if (args.action === "remove") {
				removeTarget(st, sessionId, mode, Number(args.seq));
				refreshStatus(ctx);
				return result(`目标已移除（含其覆盖/阶段/链路数据）：序号 ${args.seq}`, { ok: true, removed: args.seq });
			}
			const t = addTarget(st, sessionId, mode, { label: String(args.label ?? ""), kind: args.kind, note: args.note });
			refreshStatus(ctx);
			return result(`目标已登记：${t.label}（${targetKindLabel(t.kind)}，序号 ${t.seq}）${t.active ? "，已设为当前锚定" : ""}`, { ok: true, ...t });
		},
	});

	pi.registerTool({
		name: "redteam_coverage_mark",
		label: "atlas coverage mark",
		description: "把 AttackAtlas 的一个格子或主类标为终态：tested-found / tested-clear / na / budget-stop。key 接受 cat/item、cat 或中文标签。tested-found 必须附 findingRefs；na/budget-stop 必须附 reason。",
		promptSnippet: "点亮攻击面图谱格子终态（须证据/原因）",
		executionMode: "sequential",
		parameters: Type.Object({
			key: Type.String(),
			state: Type.String({ description: "终态（tested-found/tested-clear/na/budget-stop，接受中文标签）" }),
			reason: Type.Optional(Type.String()),
			findingRefs: Type.Optional(Type.String({ description: "finding id/证据编号/文件路径（tested-found 必填）" })),
			target: Type.Optional(Type.String()),
			mode: modeParam,
		}),
		async execute(_id: any, args: any, _signal: any, _onUpdate: any, ctx: ExtensionContext) {
			const st = theStore();
			const mode = resolveMode(ctx, args.mode);
			const sessionId = sessionIdOf(ctx);
			const taxonomy = taxonomyFor(st, mode);
			let key = String(args.key ?? "");
			const bad = validateCoverageRef(taxonomy, key);
			if (bad) { recordMiss(st, { mode, kind: "cell", query: key, error: bad, sessionId: liveSessionId(ctx) }); throw new Error(bad); }
			key = canonicalKey(taxonomy, key) ?? key;
			const state = resolveStateLabel(args.state) || String(args.state ?? "");
			if (!CELL_STATES.includes(state)) throw new Error(`state 必须是 ${CELL_STATES.join("/")}`);
			enforceEvidence(state, args.findingRefs);
			const cell = markCell(st, sessionId, mode, key, { state, reason: args.reason, findingRefs: args.findingRefs, target: args.target });
			refreshStatus(ctx);
			return result(`图谱已点亮：${cell.key} → ${cell.state}（目标：${cell.target || "公共 scope"}${cell.findingRefs ? `，证据：${cell.findingRefs}` : ""}）`, { ok: true, ...cell });
		},
	});

	pi.registerTool({
		name: "redteam_coverage_stage",
		label: "atlas coverage stage",
		description: "推进 AttackAtlas 阶段带：active/done。stage 接受阶段 id 或中文标签。",
		promptSnippet: "推进攻击面图谱阶段带",
		executionMode: "sequential",
		parameters: Type.Object({
			stage: Type.String(),
			state: Type.String({ description: "active=进行中 done=完成" }),
			target: Type.Optional(Type.String()),
			mode: modeParam,
		}),
		async execute(_id: any, args: any, _signal: any, _onUpdate: any, ctx: ExtensionContext) {
			const st = theStore();
			const mode = resolveMode(ctx, args.mode);
			const sessionId = sessionIdOf(ctx);
			const taxonomy = taxonomyFor(st, mode);
			let stage = String(args.stage ?? "");
			const bad = validateStageRef(taxonomy, stage);
			if (bad) { recordMiss(st, { mode, kind: "stage", query: stage, error: bad, sessionId: liveSessionId(ctx) }); throw new Error(bad); }
			stage = resolveStageId(taxonomy, stage) || stage;
			const s = String(args.state ?? "");
			if (!STAGE_STATES.includes(s)) throw new Error(`state 必须是 ${STAGE_STATES.join("/")}`);
			const marked = markStage(st, sessionId, mode, stage, s, args.target !== undefined ? String(args.target) : "");
			refreshStatus(ctx);
			return result(`阶段已点亮：${marked.stage} → ${marked.state}（目标：${marked.target || "公共 scope"}）`, { ok: true, ...marked });
		},
	});

	pi.registerTool({
		name: "redteam_coverage_list",
		label: "atlas coverage list",
		description: "读取本会话 AttackAtlas 全部覆盖终态（格子+阶段+目标，按目标分账全量）。",
		promptSnippet: "读取图谱全部覆盖终态",
		executionMode: "sequential",
		parameters: Type.Object({ mode: modeParam, target: Type.Optional(Type.String({ description: "只返回该目标的格子（缺省返回全部）" })) }),
		async execute(_id: any, args: any, _signal: any, _onUpdate: any, ctx: ExtensionContext) {
			const st = theStore();
			const mode = resolveMode(ctx, args.mode);
			const sessionId = sessionIdOf(ctx);
			const cov = getCoverage(st, sessionId, mode);
			const anchor = cov.targets.find((t: any) => t.active)?.label ?? "（无）";
			let cells = cov.cells;
			if (args.target !== undefined && args.target !== "") {
				if (!cov.targets.some((t: any) => t.label === args.target)) throw new Error(`目标未登记：${args.target}`);
				cells = cells.filter((c: any) => c.target === args.target);
			}
			const out = { ...cov, cells };
			const head = `本会话图谱终态（${mode}，锚定：${anchor}${args.target ? `，目标过滤：${args.target}` : ""}）：${cells.length} 格 / ${cov.stages.length} 阶段 / ${cov.targets.length} 目标`;
			return result(`${head}\n${clip(JSON.stringify(out, null, 2))}`, { ok: true, ...out });
		},
	});

	pi.registerTool({
		name: "redteam_coverage_sync",
		label: "atlas coverage sync",
		description: "批量回写覆盖终态。rows=[{key,state,reason,findingRefs,target}] 或 path=覆盖矩阵 markdown 文件（表头须含「格子」「终态」）。tested-found 行缺 findingRefs 会被跳过。",
		promptSnippet: "批量回写覆盖终态",
		executionMode: "sequential",
		parameters: Type.Object({ rows: Type.Optional(Type.Array(Type.Object({}, { additionalProperties: true }))), path: Type.Optional(Type.String()), mode: modeParam }),
		async execute(_id: any, args: any, _signal: any, _onUpdate: any, ctx: ExtensionContext) {
			const st = theStore();
			const mode = resolveMode(ctx, args.mode);
			const sessionId = sessionIdOf(ctx);
			let rows: any[] = Array.isArray(args.rows) ? args.rows.map((r: any) => ({ ...r })) : [];
			if (!rows.length && args.path) {
				const p = path.isAbsolute(String(args.path)) ? String(args.path) : path.join(ctx.cwd, String(args.path));
				const text = fs.readFileSync(p, "utf8");
				rows = parseCoverageTable(text);
				if (!rows.length) throw new Error("文件里没找到覆盖表");
			}
			if (!rows.length) throw new Error("rows 与 path 至少给一个");
			const evidenceFailed: string[] = [];
			rows = rows.filter((row, i) => {
				const st8 = resolveStateLabel(row.state);
				if (st8 === "tested-found" && !String(row.findingRefs ?? "").trim()) {
					evidenceFailed.push(`${row.line ? `第 ${row.line} 行` : `rows[${i}]`}：tested-found 缺证据引用，跳过`);
					return false;
				}
				return true;
			});
			const taxonomy = taxonomyFor(st, mode);
			const { applied, failed } = applyCoverageRows(st, taxonomy, sessionId, mode, rows);
			const allFailed = evidenceFailed.concat(failed);
			refreshStatus(ctx);
			return result(`批量回写：成功 ${applied.length} 格${allFailed.length ? `，跳过 ${allFailed.length} 行` : ""}`, { ok: true, applied, failed: allFailed });
		},
	});

	pi.registerTool({
		name: "redteam_atlas_chain",
		label: "atlas chain",
		description: "登记/查看 AttackAtlas 攻击链拓扑。节点/边按目标分账，缺省归当前锚定目标。",
		promptSnippet: "登记攻击链拓扑节点/边",
		executionMode: "sequential",
		parameters: Type.Object({
			action: Type.Union([Type.Literal("add-node"), Type.Literal("add-edge"), Type.Literal("list"), Type.Literal("clear")]),
			id: Type.Optional(Type.String()),
			label: Type.Optional(Type.String()),
			kind: Type.Optional(Type.String({ description: `节点类型（${CHAIN_NODE_KINDS.join("/")}）` })),
			seg: Type.Optional(Type.String()),
			note: Type.Optional(Type.String()),
			major: Type.Optional(Type.Boolean()),
			findingRef: Type.Optional(Type.String()),
			target: Type.Optional(Type.String()),
			src: Type.Optional(Type.String()),
			dst: Type.Optional(Type.String()),
			edgeLabel: Type.Optional(Type.String()),
			edgeType: Type.Optional(Type.Union([Type.Literal("discovered_on"), Type.Literal("exploits"), Type.Literal("enables"), Type.Literal("depends_on"), Type.Literal("leads_to")])),
			mode: modeParam,
		}),
		async execute(_id: any, args: any, _signal: any, _onUpdate: any, ctx: ExtensionContext) {
			const st = theStore();
			const mode = resolveMode(ctx, args.mode);
			const sessionId = sessionIdOf(ctx);
			const tgt = args.target !== undefined ? String(args.target) : "";
			if (args.action === "list") {
				const chain = listChain(st, sessionId, mode, args.target !== undefined ? String(args.target) : undefined);
				const head = `链路拓扑（${mode}）：${chain.nodes.length} 节点 / ${chain.edges.length} 边`;
				const nodeLines = chain.nodes.map((n: any) => `- ${n.id}「${n.label}」${chainKindLabel(n.kind)}${n.major ? "·重大" : ""}${n.seg ? `·${n.seg}` : ""}${n.findingRef ? `·成果 ${n.findingRef}` : ""}（目标：${n.target || "公共"}）`);
				const edgeLines = chain.edges.map((e: any) => `- ${e.src} → ${e.dst}${e.edgeType ? `（${EDGE_TYPE_LABEL[e.edgeType] ?? e.edgeType}）` : ""}${e.label ? `·${e.label}` : ""}`);
				return result(clip([head, ...nodeLines, ...edgeLines].join("\n")), { ok: true, chain });
			}
			if (args.action === "clear") {
				clearChain(st, sessionId, mode, args.target !== undefined ? String(args.target) : undefined);
				return result("链路已清空", { ok: true });
			}
			if (args.action === "add-node") {
				const n = addChainNode(st, sessionId, mode, { id: String(args.id ?? ""), label: String(args.label ?? ""), kind: args.kind, seg: args.seg, note: args.note, major: args.major, findingRef: args.findingRef, target: tgt });
				return result(`已登记：节点 ${n.label}（${chainKindLabel(n.kind)}${n.major ? "·重大" : ""}${n.findingRef ? `·关联成果 ${n.findingRef}` : ""}，目标：${n.target || "公共"}）`, { ok: true, node: n });
			}
			const e = addChainEdge(st, sessionId, mode, { src: String(args.src ?? ""), dst: String(args.dst ?? ""), label: args.edgeLabel, edgeType: args.edgeType, target: tgt });
			return result(`已登记：边 ${e.src} → ${e.dst}${e.edgeType ? `（${EDGE_TYPE_LABEL[e.edgeType]}）` : ""}${e.label ? `·${e.label}` : ""}`, { ok: true, edge: e });
		},
	});

	pi.registerTool({
		name: "redteam_atlas_dispatch",
		label: "atlas dispatch",
		description: "生成 AttackAtlas 派单信封（只返回指令文本，不自动执行任何测试或攻击）。level=cell/category/stage。",
		promptSnippet: "生成图谱派单信封（不自动执行）",
		executionMode: "sequential",
		parameters: Type.Object({
			level: Type.Union([Type.Literal("cell"), Type.Literal("category"), Type.Literal("stage")]),
			key: Type.Optional(Type.String()),
			stageId: Type.Optional(Type.String()),
			formId: Type.Optional(Type.String()),
			mode: modeParam,
		}),
		async execute(_id: any, args: any, _signal: any, _onUpdate: any, ctx: ExtensionContext) {
			const st = theStore();
			const mode = resolveMode(ctx, args.mode);
			const sessionId = sessionIdOf(ctx);
			const taxonomy = taxonomyFor(st, mode);
			const targets = listTargets(st, sessionId, mode);
			const payload: Record<string, unknown> = { level: args.level, formId: args.formId, targets };
			if (args.level === "cell" || args.level === "category") {
				if (!args.key) throw new Error(`level=${args.level} 需要 key 参数`);
				const bad = validateCoverageRef(taxonomy, args.key);
				if (bad) throw new Error(bad);
				const canonical = canonicalKey(taxonomy, args.key) ?? String(args.key);
				const [catId, itemId] = canonical.split("/");
				payload.categoryId = catId;
				if (args.level === "cell") {
					if (!itemId) throw new Error(`level=cell 需要 cat/item 形式 key（收到主类 ${canonical}；整组派单用 level=category）`);
					payload.itemId = itemId;
				}
			}
			if (args.level === "stage") {
				if (!args.stageId) throw new Error("level=stage 需要 stageId 参数");
				const bad = validateStageRef(taxonomy, args.stageId);
				if (bad) throw new Error(bad);
				payload.stageId = resolveStageId(taxonomy, args.stageId);
			}
			const envelope = triggerMessage(taxonomy, payload);
			return result(`派单信封已生成（不自动执行）：\n\n${envelope}`, { ok: true, envelope });
		},
	});

	pi.registerTool({
		name: "redteam_atlas_method",
		label: "atlas method",
		description: "自定义工作方法论（跨会话长期资产）。action：validate/save/list/get/remove/copy/export/import/run。保存前必须经 normalizeGraph/validateMethod/METHOD_LIMITS 结构校验；run 只返回信封不自动执行。",
		promptSnippet: "维护/运行自定义工作方法论",
		executionMode: "sequential",
		parameters: Type.Object({
			action: Type.Union([Type.Literal("validate"), Type.Literal("save"), Type.Literal("list"), Type.Literal("get"), Type.Literal("remove"), Type.Literal("copy"), Type.Literal("export"), Type.Literal("import"), Type.Literal("run")]),
			id: Type.Optional(Type.String()),
			name: Type.Optional(Type.String()),
			graph: Type.Optional(Type.Object({ nodes: Type.Array(Type.Any()), edges: Type.Array(Type.Any()) }, { additionalProperties: true })),
			target: Type.Optional(Type.String()),
			notes: Type.Optional(Type.String()),
			path: Type.Optional(Type.String()),
			mode: modeParam,
		}),
		async execute(_id: any, args: any, _signal: any, _onUpdate: any, ctx: ExtensionContext) {
			const st = theStore();
			const a = args.action;
			if (a === "export") {
				const mode = softMode(ctx, args.mode);
				const data = { format: "attack-atlas-methods", version: 1, methods: exportMethods(st, mode || undefined) };
				if (args.path) {
					const p = path.isAbsolute(String(args.path)) ? String(args.path) : path.join(ctx.cwd, String(args.path));
					fs.writeFileSync(p, JSON.stringify(data, null, 2));
					return result(`方法论模板已导出：${data.methods.length} 份 → ${p}`, { ok: true, count: data.methods.length, path: p });
				}
				return result(clip(JSON.stringify(data, null, 2)), { ok: true, ...data });
			}
			if (a === "import") {
				if (!args.path) throw new Error("import 需要 path（JSON 文件）");
				const p = path.isAbsolute(String(args.path)) ? String(args.path) : path.join(ctx.cwd, String(args.path));
				const doc = JSON.parse(fs.readFileSync(p, "utf8"));
				const rows = Array.isArray(doc?.methods) ? doc.methods : Array.isArray(doc) ? doc : [];
				if (!rows.length) throw new Error("文件里没找到 methods 数组");
				if (rows.length > METHOD_LIMITS.importBatch) throw new Error(`单次导入上限 ${METHOD_LIMITS.importBatch} 条`);
				const skippedV: any[] = [];
				const checked: any[] = [];
				const taxCache: Record<string, any> = {};
				for (const row of rows) {
					const m = String(row?.mode ?? "");
					if (!TAXONOMIES[m]) { checked.push(row); continue; }
					if (!taxCache[m]) taxCache[m] = taxonomyWithCaps(st, TAXONOMIES[m], m);
					const v = validateMethod(String(row?.name ?? ""), row?.graph, taxCache[m]);
					if (v.errors.length) { skippedV.push({ name: String(row?.name ?? "(无名)"), reason: `结构问题：${v.errors[0]}` }); continue; }
					checked.push(row);
				}
				const r = importMethods(st, checked, MODES);
				const skipped = skippedV.concat(r.skipped);
				return result(`方法论导入：成功 ${r.imported.length} 份${skipped.length ? `，跳过 ${skipped.length} 份` : ""}`, { ok: true, imported: r.imported, skipped });
			}
			const mode = resolveMode(ctx, args.mode);
			const taxonomy = taxonomyFor(st, mode);
			if (a === "validate" || a === "save") {
				const v = validateMethod(String(args.name ?? ""), args.graph, taxonomy);
				if (a === "validate" || v.errors.length) {
					const text = [v.errors.length ? `结构问题：\n- ${v.errors.join("\n- ")}` : "结构校验通过", v.warnings.length ? `闭环警告：\n- ${v.warnings.map((w: any) => w.msg).join("\n- ")}` : "", v.hints.length ? `提示：\n- ${v.hints.join("\n- ")}` : ""].filter(Boolean).join("\n");
					if (a === "save" && v.errors.length) throw new Error(text);
					return result(text, { ok: v.errors.length === 0, errors: v.errors, warnings: v.warnings, hints: v.hints });
				}
				const saved = saveMethod(st, { id: args.id ? String(args.id) : undefined, mode, name: v.name, target: args.target, notes: args.notes, graph: v.graph });
				return result(`方法论模板已${saved.created ? "保存" : "更新"}：「${v.name}」（${saved.id}）`, { ok: true, id: saved.id });
			}
			if (a === "list") {
				const rows = listMethods(st, mode);
				const lines = rows.map((m: any) => `- ${m.id}「${m.name}」${m.nodeCount} 模块${m.target ? `·目标 ${m.target}` : ""}·更新 ${m.updatedAt}`);
				return result(rows.length ? `方法论模板（${mode}）${rows.length} 份：\n${lines.join("\n")}` : `模式 ${mode} 暂无方法论模板`, { ok: true, methods: rows });
			}
			if (a === "get") {
				const m = getMethod(st, String(args.id ?? ""));
				if (!m) throw new Error(`模板不存在：${args.id}`);
				return result(clip(JSON.stringify(m, null, 2)), { ok: true, method: m });
			}
			if (a === "remove") {
				removeMethod(st, String(args.id ?? ""));
				return result(`模板已删除：${args.id}`, { ok: true });
			}
			if (a === "copy") {
				const r = copyMethod(st, String(args.id ?? ""));
				return result(`模板已复制：新 id ${r.id}`, { ok: true, id: r.id });
			}
			const m = getMethod(st, String(args.id ?? ""));
			if (!m) throw new Error(`模板不存在：${args.id}`);
			if (m.mode !== mode) throw new Error(`模板属于 ${MODE_LABELS[m.mode] ?? m.mode}，与当前模式 ${mode} 不符`);
			const sessionId = sessionIdOf(ctx);
			const runTarget = String(args.target ?? m.target ?? "").trim().slice(0, METHOD_LIMITS.target);
			if (runTarget) {
				if (!listTargets(st, sessionId, mode).some((t: any) => t.label === runTarget)) {
					addTarget(st, sessionId, mode, { label: runTarget, kind: inferTargetKind(runTarget) });
				}
				switchTarget(st, sessionId, mode, runTarget);
			}
			const targets = listTargets(st, sessionId, mode);
			const notes = String(args.notes ?? m.notes ?? "").trim().slice(0, METHOD_LIMITS.notes);
			const mTaxonomy = taxonomyWithCaps(st, TAXONOMIES[m.mode], m.mode);
			const envelope = methodRunMessage(mTaxonomy, m, { anchor: anchorLines(mTaxonomy, targets), notes });
			refreshStatus(ctx);
			return result(`方法论运行信封已生成（不自动执行）：\n\n${envelope}`, { ok: true, envelope, id: m.id });
		},
	});

	pi.registerTool({
		name: "redteam_atlas_caps",
		label: "atlas capabilities",
		description: "能力库（跨会话长期资产）：自定义主类/子类，挂内置主类或自定义主类下，保存即共享进方法论模块库。",
		promptSnippet: "维护能力库自定义主类/子类",
		executionMode: "sequential",
		parameters: Type.Object({
			action: Type.Union([Type.Literal("save"), Type.Literal("list"), Type.Literal("remove"), Type.Literal("export"), Type.Literal("import")]),
			id: Type.Optional(Type.String()),
			kind: Type.Optional(Type.Union([Type.Literal("category"), Type.Literal("item")])),
			cat: Type.Optional(Type.String()),
			label: Type.Optional(Type.String()),
			desc: Type.Optional(Type.String()),
			template: Type.Optional(Type.String()),
			ref: Type.Optional(Type.String()),
			pb: Type.Optional(Type.String()),
			forms: Type.Optional(Type.String()),
			path: Type.Optional(Type.String()),
			mode: modeParam,
		}),
		async execute(_id: any, args: any, _signal: any, _onUpdate: any, ctx: ExtensionContext) {
			const st = theStore();
			if (args.action === "export") {
				const mode = softMode(ctx, args.mode);
				const data = { format: "attack-atlas-caps", version: 1, capabilities: exportCaps(st, mode || undefined) };
				if (args.path) {
					const p = path.isAbsolute(String(args.path)) ? String(args.path) : path.join(ctx.cwd, String(args.path));
					fs.writeFileSync(p, JSON.stringify(data, null, 2));
					return result(`能力库已导出：${data.capabilities.length} 条 → ${p}`, { ok: true, count: data.capabilities.length, path: p });
				}
				return result(clip(JSON.stringify(data, null, 2)), { ok: true, ...data });
			}
			if (args.action === "import") {
				if (!args.path) throw new Error("import 需要 path（JSON 文件）");
				const p = path.isAbsolute(String(args.path)) ? String(args.path) : path.join(ctx.cwd, String(args.path));
				const doc = JSON.parse(fs.readFileSync(p, "utf8"));
				const rows = Array.isArray(doc?.capabilities) ? doc.capabilities : Array.isArray(doc) ? doc : [];
				if (!rows.length) throw new Error("文件里没找到 capabilities 数组");
				if (rows.length > 200) throw new Error("单次导入上限 200 条");
				const batchCats = new Map<string, Set<string>>();
				for (const row of rows) {
					const m = String(row?.mode ?? "");
					if (String(row?.kind) !== "category") continue;
					const key = String(row?.cat ?? "");
					if (TAXONOMIES[m] && /^[a-z0-9][a-z0-9-]{0,39}$/.test(key)) {
						if (!batchCats.has(m)) batchCats.set(m, new Set());
						batchCats.get(m)!.add(key);
					}
				}
				for (const [m] of batchCats) for (const c of listCaps(st, m)) if (c.kind === "category") batchCats.get(m)!.add(c.cat);
				const checked: any[] = [];
				const skippedPre: any[] = [];
				for (const row of rows) {
					const m = String(row?.mode ?? "");
					const base = TAXONOMIES[m];
					const kind = String(row?.kind ?? "");
					const label = String(row?.label ?? "(无名)");
					if (base && kind === "category") {
						const key = String(row?.cat ?? "");
						if (base.categories.some((c: any) => c.id === key)) { skippedPre.push({ name: label, reason: `主类标识与内置主类相同：${key}` }); continue; }
					}
					if (base && kind === "item") {
						const cat = String(row?.cat ?? "");
						const ik = String(row?.item ?? "");
						const hit = base.categories.find((c: any) => c.id === cat);
						if (hit && hit.items.some((i: any) => i.id === ik)) { skippedPre.push({ name: label, reason: `子类标识与内置子类相同：${cat}/${ik}` }); continue; }
						if (!hit && !(batchCats.get(m) ?? new Set()).has(cat)) { skippedPre.push({ name: label, reason: `所属主类不存在：${cat}` }); continue; }
					}
					checked.push(row);
				}
				const r = importCaps(st, checked, MODES);
				const skipped = skippedPre.concat(r.skipped);
				return result(`能力库导入：成功 ${r.imported.length} 条${skipped.length ? `，跳过 ${skipped.length} 条` : ""}`, { ok: true, imported: r.imported, skipped });
			}
			const mode = resolveMode(ctx, args.mode);
			if (args.action === "list") {
				const caps = listCaps(st, mode);
				const lines = caps.map((c: any) => `- ${c.id} [${c.kind === "category" ? "主类" : "子类"}] ${c.kind === "item" ? `${c.cat}/` : ""}${c.kind === "category" ? c.cat : c.item}「${c.label}」${c.forms ? `·形态 ${c.forms}` : ""}${c.template ? "·带打法模板" : ""}`);
				return result(caps.length ? `能力库（${mode}）${caps.length} 条：\n${lines.join("\n")}` : `模式 ${mode} 暂无自定义能力`, { ok: true, caps });
			}
			if (args.action === "remove") {
				const r = removeCap(st, String(args.id ?? ""));
				return result(`能力已删除：${r.removed}${r.cascaded ? `（级联删除 ${r.cascaded} 个子类）` : ""}`, { ok: true, ...r });
			}
			if (String(args.kind) === "item") {
				const cat = String(args.cat ?? "");
				const base = TAXONOMIES[mode];
				const okBuiltin = base.categories.some((c: any) => c.id === cat);
				const okCustom = listCaps(st, mode).some((c: any) => c.kind === "category" && c.cat === cat);
				if (!okBuiltin && !okCustom) throw new Error(`所属主类不存在：${cat || "(空)"}`);
			}
			const cap = saveCap(st, { id: args.id, mode, kind: String(args.kind ?? ""), cat: args.cat, label: String(args.label ?? ""), desc: args.desc, template: args.template, ref: args.ref, pb: args.pb, forms: args.forms });
			return result(`能力已保存：${cap.kind === "category" ? "主类" : "子类"} key=${cap.kind === "category" ? cap.cat : `${cap.cat}/${cap.item}`}（${cap.id}）`, { ok: true, ...cap });
		},
	});

	pi.registerTool({
		name: "redteam_atlas_matrix",
		label: "atlas matrix",
		description: "输出攻击面矩阵：markdown 全文矩阵落工作区文件 + 精简文本表格。target 缺省=聚合并集，显式给已登记 label 看单目标分账；form 可按形态过滤。",
		promptSnippet: "输出攻击面矩阵（md 文件+文本表）",
		executionMode: "sequential",
		parameters: Type.Object({
			form: Type.Optional(Type.String()),
			target: Type.Optional(Type.String()),
			out: Type.Optional(Type.String()),
			mode: modeParam,
		}),
		async execute(_id: any, args: any, _signal: any, _onUpdate: any, ctx: ExtensionContext) {
			const st = theStore();
			const mode = resolveMode(ctx, args.mode);
			const sessionId = sessionIdOf(ctx);
			const taxonomy = taxonomyFor(st, mode);
			const cov = getCoverage(st, sessionId, mode);
			if (args.target !== undefined && args.target !== "" && !cov.targets.some((t: any) => t.label === args.target)) {
				throw new Error(`目标未登记：${args.target}（已登记：${cov.targets.map((t: any) => t.label).join("、") || "无"}）`);
			}
			const form = args.form && args.form !== "all" ? String(args.form) : undefined;
			if (form && !taxonomy.forms.some((f: any) => f.id === form)) throw new Error(`未知形态 ${form}（合法：${taxonomy.forms.map((f: any) => f.id).join("、")}）`);
			const target = args.target !== undefined ? String(args.target) : undefined;
			const md = renderMatrixMarkdown({ taxonomy, mode, cells: cov.cells, stages: cov.stages, targets: cov.targets, form, target, generatedAt: nowStamp() });
			const outPath = args.out ? (path.isAbsolute(String(args.out)) ? String(args.out) : path.join(ctx.cwd, String(args.out))) : matrixFilePath(ctx.cwd, mode, target);
			fs.writeFileSync(outPath, md);
			const compact = renderMatrixCompact({ taxonomy, mode, cells: cov.cells, stages: cov.stages, targets: cov.targets, form, target });
			return result(`${compact}\n\nmarkdown 全文矩阵已落盘：${outPath}`, { ok: true, path: outPath, compact });
		},
	});

	pi.registerCommand("atlas", {
		description: "AttackAtlas 攻击面图谱：/atlas matrix [mode] [target] | targets <mode> | methods <mode> | caps <mode> | misses | summary [mode]",
		handler: async (args: string, ctx: ExtensionContext) => {
			const arg = args.trim();
			const sp = arg.indexOf(" ");
			const sub = (sp < 0 ? arg : arg.slice(0, sp)).toLowerCase();
			const rest = sp < 0 ? "" : arg.slice(sp + 1).trim();
			const usage = "用法：/atlas matrix [mode] [target]｜targets <mode>｜methods <mode>｜caps <mode>｜misses｜summary [mode]";
			try {
				if (sub === "" || sub === "help") { notify(ctx, usage); return; }
				const st = theStore();
				if (sub === "misses") {
					const s = missSummary(st, { limit: 50 });
					const lines = s.rows.map((r: any) => `- [${r.mode}/${r.kind}] 「${r.query}」×${r.n}（最近 ${r.last_at}）`);
					notify(ctx, s.total === 0 ? "MISS 缺口台账为空" : `MISS 缺口台账（共 ${s.total} 条）：\n${lines.join("\n")}`);
					return;
				}
				const first = rest.split(/\s+/)[0] ?? "";
				const mode = MODES.includes(first) ? first : softMode(ctx);
				if (!mode) { notify(ctx, `无法确定模式——${usage}`, "warning"); return; }
				const sessionId = sessionIdOf(ctx);
				const taxonomy = taxonomyFor(st, mode);
				if (sub === "targets") {
					const targets = listTargets(st, sessionId, mode);
					notify(ctx, targets.length ? `本会话目标（${mode}）${targets.length} 个：\n` + targets.map((t: any) => `${t.active ? "→" : " "} ${t.seq}. ${t.label}（${targetKindLabel(t.kind)}）`).join("\n") : `本会话（${mode}）尚未登记目标`);
					return;
				}
				if (sub === "methods") {
					const rows = listMethods(st, mode);
					notify(ctx, rows.length ? `方法论模板（${mode}）${rows.length} 份：\n` + rows.map((m: any) => `- ${m.id}「${m.name}」${m.nodeCount} 模块`).join("\n") : `模式 ${mode} 暂无方法论模板`);
					return;
				}
				if (sub === "caps") {
					const caps = listCaps(st, mode);
					notify(ctx, caps.length ? `能力库（${mode}）${caps.length} 条：\n` + caps.map((c: any) => `- [${c.kind === "category" ? "主类·自" : "子类"}] ${c.kind === "item" ? `${c.cat}/` : ""}${c.kind === "category" ? c.cat : c.item}「${c.label}」`).join("\n") : `模式 ${mode} 暂无自定义能力`);
					return;
				}
				const cov = getCoverage(st, sessionId, mode);
				const targetArg = MODES.includes(first) ? rest.slice(first.length).trim() : rest;
				const target = targetArg ? targetArg : undefined;
				if (target && !cov.targets.some((t: any) => t.label === target)) { notify(ctx, `目标未登记：${target}`, "warning"); return; }
				const compact = renderMatrixCompact({ taxonomy, mode, cells: cov.cells, stages: cov.stages, targets: cov.targets, target });
				if (sub === "matrix") {
					const md = renderMatrixMarkdown({ taxonomy, mode, cells: cov.cells, stages: cov.stages, targets: cov.targets, target, generatedAt: nowStamp() });
					const file = matrixFilePath(ctx.cwd, mode, target);
					fs.writeFileSync(file, md);
					notify(ctx, `${compact}\n\nmarkdown 全文矩阵：${file}`);
					if (ctx.mode === "tui") ctx.ui.setWidget("attack-atlas-matrix", compact.split("\n").slice(0, 30));
					return;
				}
				notify(ctx, compact);
				if (ctx.mode === "tui") ctx.ui.setWidget("attack-atlas-summary", compact.split("\n").slice(0, 30));
			} catch (e: any) {
				notify(ctx, `atlas 命令失败：${e?.message ?? e}`, "error");
			}
		},
	});

	pi.on("tool_result", (event: any, ctx: ExtensionContext) => {
		if (event.isError) return;
		if (event.toolName === "stage_gate") {
			const text = (event.content ?? []).find((b: any) => b.type === "text")?.text ?? "";
			const hit = parseGatePassText(text);
			if (!hit || !MODES.includes(hit.mode) || !TAXONOMIES[hit.mode]) return;
			try {
				const marked = autoStageFromGate(theStore(), TAXONOMIES[hit.mode], sessionIdOf(ctx), hit.mode, hit.gate);
				if (marked.length) { refreshStatus(ctx); notify(ctx, `AttackAtlas 阶段带级联点亮：${marked.join(" → ")}（stage_gate ${hit.mode}/${hit.gate} PASS）`); }
			} catch { }
			return;
		}
		if (event.toolName === "redteam_finding_register") {
			try {
				const input = (event.input ?? {}) as Record<string, unknown>;
				const d = (event.details ?? {}) as Record<string, unknown>;
				const mode = MODES.includes(String(d.mode ?? "")) ? String(d.mode) : softMode(ctx);
				if (!mode || !TAXONOMIES[mode]) return;
				const st = theStore();
				const sessionId = sessionIdOf(ctx);
				const taxonomy = taxonomyFor(st, mode);
				const title = String(input.title ?? "").trim();
				const typeStr = String(input.type ?? "").trim();
				const cues = [...new Set([typeStr, cweToLabel(input.cwe), title].map((c) => String(c ?? "").trim()).filter(Boolean))];
				if (!cues.length) return;
				const ref = String(d.id ?? "");
				const cov = getCoverage(st, sessionId, mode);
				const ft = String(input.target ?? "").trim().slice(0, 120);
				const scope = cov.targets.find((t: any) => t.label === ft)?.label ?? cov.targets.find((t: any) => t.active)?.label ?? "";
				const done = new Set(cov.cells.filter((c: any) => c.target === scope).map((c: any) => c.key));
				const marked: string[] = [];
				for (const cue of cues) {
					const res = resolveKey(taxonomy, cue);
					if (!res?.key || res.ambiguous || res.missingItem) continue;
					if (done.has(res.key)) continue;
					try {
						markCell(st, sessionId, mode, res.key, { state: "tested-found", reason: `自动：finding${ref ? ` ${ref}` : ""}「${title.slice(0, 40)}」类型关联点亮`, findingRefs: ref, target: scope });
						done.add(res.key);
						marked.push(res.key);
					} catch { }
				}
				if (marked.length) { refreshStatus(ctx); notify(ctx, `AttackAtlas 自动点亮 ${marked.length} 格（finding 关联）：${marked.map((k) => keyLabel(taxonomy, k)).join("、")}`); }
			} catch { }
		}
	});
}
