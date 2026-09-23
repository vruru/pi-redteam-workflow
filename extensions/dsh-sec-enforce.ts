/**
 * dsh-sec-enforce (Pi port) — 确定性工具拦截 / deterministic tool-call enforcement
 *
 * 源：~/.pi/agent/redteam-model/plugins/dsh-sec-enforce/lib/index.js (v1.4.2，只读)
 * 约定：~/.pi/agent/extensions/redteam/PORT-CONVENTIONS.md（本件逐条遵守，尤其第 8 条）
 *
 * 拦什么（与源实现逐条对齐）：
 *   killSwitch      全局熔断标记文件存在 → 拦全部工具执行（跨模式事实层），删标记即恢复
 *   reportGate      write/edit 落 <workspace>/reports/ 前，gate-log.md 必须已有本模式
 *                   「报告门」PASS 行；redteam 总控不写 reports/（专用文案）；
 *                   并叠加 operation-state.json 的未收口准则 / 未收口意图 / deny 约束三查
 *   writeBoundary   write/edit 目标限定在任务工作区内（allowDirs + 本件状态目录豁免）
 *   taskBriefGate   redteam 总控任务书 task-briefs/*.md 必须带「依据/锚点」行
 *   dangerousOps    不可逆破坏族（rm 根级 / Windows 删除族 / format·mkfs / DROP·TRUNCATE /
 *                   停机重启杀服务 / 资金类 POST）→ 硬拦并指路「呈报计划 → 征得批准」
 *   askGate         变更性但可逆族（账号权限 / 防火墙规则 / flood 压测）→ 有 UI 走确认框
 *                   （批准即执行），无 UI 或拒绝即拒（与源「拒绝/超时/无审批通道即拒」同义）
 *   rateDiscipline  裸奔扫描（nmap -p- 无速率 / masscan --rate>1000 / 裸 ffuf 无 -rate）→ 拦并给修法
 *
 * 与源实现的差异（详见同目录 PORT-NOTES 与本文件末尾 README 段）：
 *   - 模式判定：dsh 用 ctx.agentPresets.composedPreset(agent.ctx)；Pi 无 preset 概念，
 *     改为「显式开关 > 会话粘性记忆 > skill 工具实际装载 redteam playbook > 工作区安全工件
 *     > AGENTS.security.md 正文标记」五级探测，探测不到 = 完全不介入（不扩大限制面）。
 *   - 审批：dsh 走宿主 approval 服务（tools/pre-execute waterfall）；Pi 用 ctx.ui.confirm
 *     （ctx.hasUI 守卫，print/json 模式退化为拦截 + 指路文本）。
 *   - 留痕：dsh 只写 <workspace>/enforce-log.md；本件按移植约定主写
 *     ~/.pi/redteam/dsh-sec-enforce/enforce-log.md，工作区副本尽力而为。
 *   - 轮次：源实现四档判定均为纯特征、不依赖 dsh 轮次信息；本件仅额外用 Pi 的
 *     turn_start.turnIndex 做「同轮重复拦截」提示（只提示，不新增限制）。
 *   - 未移植：redteam 之外的 fetch URL 约束档保留（工具名 fetch 存在才生效）。
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { homedir, tmpdir } from "node:os";
import { Type } from "typebox";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

// ── paths (PORT-CONVENTIONS.md 第 4 条：状态一律 ~/.pi/redteam/<plugin>/，不用 ~/.dsh/) ──

const PLUGIN = "dsh-sec-enforce";
const STATE_DIR = path.join(homedir(), ".pi", "redteam", PLUGIN);
const CONFIG_FILE = path.join(STATE_DIR, "config.json");
const GLOBAL_LOG = path.join(STATE_DIR, "enforce-log.md");
const RULES_DOC = path.join(STATE_DIR, "rules.md");
const KILL_MARKER = (): string => process.env.PI_SEC_ENFORCE_KILL_FILE || path.join(STATE_DIR, "KILL");
/** 只读控制面自身：熔断期间不拦——它是 Agent 唯一的自查/自恢复通道（见 decide 的 killSwitch 分支）。 */
const SELF_TOOL = "sec_enforce_status";
const KILL_REASON = (): string =>
	`全局熔断已触发：所有工具执行暂停（一键停止）。恢复方法：sec_enforce_status action=clear（Agent 自恢复，推荐）、/sec-enforce clear（用户），或移除标记文件 ${KILL_MARKER()}。熔断期间仅回答问题与调用 ${SELF_TOOL}，不执行任何测试或攻击操作。`;

const killTripped = (): boolean => {
	try {
		return fs.existsSync(KILL_MARKER());
	} catch {
		return false;
	}
};

// ── mode table（与源实现同名同值） ──

export const SECURITY_MODES = new Set([
	"pentest",
	"code-audit",
	"binary-analysis",
	"attack-defense",
	"av-evasion",
	"redteam",
	"incident-response",
	"cloud-security",
	"ctf-solver",
	"asset-mapping",
]);

/** 每模式的「报告门」；redteam / asset-mapping 刻意不在表内（源实现同）。 */
export const REPORT_GATE: Record<string, string> = {
	pentest: "P3",
	"code-audit": "A3",
	"binary-analysis": "B2",
	"attack-defense": "report",
	"av-evasion": "V4",
	"incident-response": "I5",
	"cloud-security": "C7",
	"ctf-solver": "flag",
};

const WRITE_TOOLS = new Set(["write", "edit"]);
const SHELL_TOOLS = new Set(["bash", "powershell"]);

/** Pi 侧模式探测：技能名 → 模式（redteam-model 技能包内实际存在的名字）。 */
export const SKILL_MODE_MAP: Record<string, string> = {
	"pentest-playbook": "pentest",
	"audit-playbook": "code-audit",
	"re-playbook": "binary-analysis",
	"ad-playbook": "attack-defense",
	"av-playbook": "av-evasion",
	"ir-playbook": "incident-response",
	"cloud-playbook": "cloud-security",
	"ctf-playbook": "ctf-solver",
	"asset-mapping-playbook": "asset-mapping",
	"router-playbook": "redteam",
	"red-team-command-doctrine": "redteam",
	"redteam-boundary-policy": "redteam",
	"ecosystem-cooperation": "redteam",
};

/** 工作区安全工件（存在即认定这是安全任务工作区；模式未知时再从 gate-log 反推）。 */
export const WORKSPACE_MARKERS = [
	"gate-log.md",
	"task-ledger.md",
	"attack-paths.csv",
	"sinks.csv",
	"scan-reconcile.csv",
	"creds-cloud.txt",
	"evidence-index.md",
	"ioc.txt",
	"operation-state.json",
];

/** AGENTS.security.md（九模式工作区支撑层）正文标记——被装进系统提示即安全会话。 */
export const SECURITY_PROMPT_MARKERS = [
	"Security Testing Collaboration Support Specification",
	"authorized security task (CTF, authorized penetration testing",
	"dsh-redteam-model",
];

// ── config ──

export interface SecEnforceConfig {
	/** auto = 只在探测到安全会话时生效；on = 强制生效；off = 全关 */
	enabled: "auto" | "on" | "off";
	/** 显式模式（跳过探测） */
	mode?: string;
	reportGate: boolean;
	writeBoundary: boolean;
	dangerousOps: boolean;
	rateDiscipline: boolean;
	askGate: boolean;
	intentGate: boolean;
	constraintGate: boolean;
	taskBriefGate: boolean;
	killSwitch: boolean;
	/** 写边界豁免目录（追加在状态目录之后） */
	allowDirs: string[];
	/** ask 档确认框超时（毫秒）；超时=拒绝 */
	askTimeoutMs: number;
}

export const DEFAULT_CONFIG: SecEnforceConfig = {
	enabled: "auto",
	reportGate: true,
	writeBoundary: true,
	dangerousOps: true,
	rateDiscipline: true,
	askGate: true,
	intentGate: true,
	constraintGate: true,
	taskBriefGate: true,
	killSwitch: true,
	allowDirs: [],
	askTimeoutMs: 120000,
};

const BOOL_KEYS = [
	"reportGate",
	"writeBoundary",
	"dangerousOps",
	"rateDiscipline",
	"askGate",
	"intentGate",
	"constraintGate",
	"taskBriefGate",
	"killSwitch",
] as const;

let configCache: { mtimeMs: number; config: SecEnforceConfig } | undefined;

export function loadConfig(): SecEnforceConfig {
	let cfg: SecEnforceConfig = { ...DEFAULT_CONFIG, allowDirs: [...DEFAULT_CONFIG.allowDirs] };
	let mtimeMs = 0;
	try {
		const st = fs.statSync(CONFIG_FILE);
		mtimeMs = st.mtimeMs;
		if (configCache && configCache.mtimeMs === mtimeMs) cfg = configCache.config;
		else {
			const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
			cfg = { ...cfg, ...sanitize(raw), allowDirs: [...DEFAULT_CONFIG.allowDirs, ...readAllowDirs(raw)] };
			configCache = { mtimeMs, config: cfg };
		}
	} catch {
		/* no config file = defaults */
	}
	// env overrides win（无人值守/冒烟测试用）
	const env = (process.env.PI_SEC_ENFORCE || "").trim().toLowerCase();
	if (env === "off" || env === "0" || env === "false") cfg = { ...cfg, enabled: "off" };
	else if (env === "on" || env === "1" || env === "true") cfg = { ...cfg, enabled: "on" };
	else if (env === "auto") cfg = { ...cfg, enabled: "auto" };
	const envMode = (process.env.PI_SEC_ENFORCE_MODE || "").trim();
	if (envMode && SECURITY_MODES.has(envMode)) cfg = { ...cfg, mode: envMode, enabled: "on" };
	if (process.env.PI_SEC_ENFORCE_ALLOW) {
		cfg = { ...cfg, allowDirs: [...cfg.allowDirs, ...process.env.PI_SEC_ENFORCE_ALLOW.split(path.delimiter).filter(Boolean)] };
	}
	void mtimeMs;
	return cfg;
}

function sanitize(raw: Record<string, unknown>): Partial<SecEnforceConfig> {
	const out: Record<string, unknown> = {};
	for (const key of BOOL_KEYS) if (typeof raw[key] === "boolean") out[key] = raw[key];
	if (raw.enabled === "auto" || raw.enabled === "on" || raw.enabled === "off") out.enabled = raw.enabled;
	if (typeof raw.mode === "string" && SECURITY_MODES.has(raw.mode)) out.mode = raw.mode;
	if (typeof raw.askTimeoutMs === "number" && Number.isFinite(raw.askTimeoutMs)) out.askTimeoutMs = raw.askTimeoutMs;
	return out;
}

function readAllowDirs(raw: Record<string, unknown>): string[] {
	return Array.isArray(raw.allowDirs) ? raw.allowDirs.filter((d): d is string => typeof d === "string" && !!d) : [];
}

export function saveConfig(patch: Partial<SecEnforceConfig>): SecEnforceConfig {
	const current = loadConfig();
	const next = { ...current, ...patch };
	fs.mkdirSync(STATE_DIR, { recursive: true });
	fs.writeFileSync(CONFIG_FILE, `${JSON.stringify(next, null, 2)}\n`);
	configCache = undefined;
	return next;
}

// ── pure rule functions（特征与文案逐条移植自源 lib/index.js） ──

/** gate-log.md 表格行：`| iso | mode/stage | pass | ... |`（dsh-stage-gate appendGateLog 格式）。 */
export function gateLogHasPass(logText: string, mode: string, gateId: string): boolean {
	const needle = `${mode}/${gateId}`;
	for (const line of String(logText ?? "").split("\n")) {
		if (!line.includes("|")) continue;
		const cells = line.split("|").map((c) => c.trim());
		if (cells.includes(needle) && cells.includes("pass")) return true;
	}
	return false;
}

/** gate-log.md 里出现过的模式（用于模式未知时反推）。 */
export function modesInGateLog(logText: string): string[] {
	const out: string[] = [];
	for (const line of String(logText ?? "").split("\n")) {
		if (!line.includes("|")) continue;
		for (const cell of line.split("|").map((c) => c.trim())) {
			const idx = cell.indexOf("/");
			if (idx <= 0) continue;
			const mode = cell.slice(0, idx);
			if (SECURITY_MODES.has(mode) && !out.includes(mode)) out.push(mode);
		}
	}
	return out;
}

/**
 * 路径归一（含 realpath）：macOS /tmp → /private/tmp 这类符号链接不能把
 * 「工作区内的绝对路径」误判成越界。目标不存在时回溯最近存在的祖先再拼回。
 */
export function realish(input: string, base = process.cwd()): string {
	const abs = path.resolve(base, input);
	let cur = abs;
	const rest: string[] = [];
	for (let i = 0; i < 16; i++) {
		try {
			return path.join(fs.realpathSync(cur), ...rest.reverse());
		} catch {
			const up = path.dirname(cur);
			if (up === cur) break;
			rest.push(path.basename(cur));
			cur = up;
		}
	}
	try {
		return path.join(fs.realpathSync(cur), ...rest.reverse());
	} catch {
		return abs;
	}
}

function within(child: string, parent: string): boolean {
	const rel = path.relative(parent, child);
	return !rel.startsWith("..") && !path.isAbsolute(rel);
}

export function isReportPath(target: string, workspace: string): boolean {
	const rel = path.relative(realish(workspace), realish(target, workspace));
	return !rel.startsWith("..") && !path.isAbsolute(rel) && rel.split(path.sep)[0] === "reports";
}

export function isWritable(target: string, workspace: string, allowDirs: string[] = []): boolean {
	const norm = realish(target, workspace);
	const candidates = [workspace, ...allowDirs];
	return candidates.some((dir) => !!dir && within(norm, realish(dir)));
}

export function isTaskBriefPath(target: string, workspace: string): boolean {
	const rel = path.relative(realish(workspace), realish(target, workspace));
	return !rel.startsWith("..") && !path.isAbsolute(rel) && rel.split(path.sep)[0] === "task-briefs" && /\.md$/i.test(rel);
}

export const TASK_BRIEF_ANCHOR_RE = /^[ \t]*(?:[-*][ \t]*)?(?:依据|锚点)[：:]/m;

/** 保守高危命令特征——命中返回拒绝理由（含降级替代），未命中返回 undefined。 */
export function scanDangerous(command: string): string | undefined {
	const cmd = String(command ?? "");
	const compact = cmd.replace(/\\\n/g, " ").replace(/\s+/g, " ");
	if (/(^|[;&|]\s*)rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(\/|~|\$HOME)(\/|\s|$)/.test(compact)) {
		return "大范围删除（rm 涉及 / 或 ~ 根级路径）被确定性门禁拦截：目标侧零破坏（PORT-CONVENTIONS 第 8 条）——删除范围必须限定在任务工作区内；确需删除请先列出清单征得用户批准，再逐项执行。降级替代：cd 到工作区后限定路径逐项删除，或只生成删除清单交由用户手动执行。";
	}
	if (
		/\bremove-item\b[^|;&]*-recurse[^|;&]*([a-z]:\\|\\windows\\|\\users\\)/i.test(compact) ||
		/\b(rd|rmdir)\b\s+\/s\b[^|;&]*[a-z]:\\/i.test(compact) ||
		/\bdel\b[^|;&]*\/s\b[^|;&]*[a-z]:\\/i.test(compact)
	) {
		return "Windows 大范围删除（盘根/系统目录）被确定性门禁拦截：目标侧零破坏（PORT-CONVENTIONS 第 8 条）——删除范围必须限定在任务工作区内；确需删除请先列出清单征得用户批准，再逐项执行。降级替代：生成删除清单交由用户手动执行。";
	}
	if (/\bformat\s+[a-z]:\s/i.test(compact) || /\bmkfs(\.\w+)?\b/.test(compact)) {
		return "格式化/抹除介质属不可逆破坏，被拦截：目标侧零破坏（PORT-CONVENTIONS 第 8 条）——没有用户明确指定一律严禁；需要时只生成操作计划呈报，获明确批准后由用户执行或确认后代执行。降级替代：只读挂载核对数据现状，处置建议写入报告。";
	}
	if (/\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b/i.test(compact) && !/^\s*#/.test(compact)) {
		return "破坏数据完整性操作（DROP/TRUNCATE）被拦截：负面清单禁止破坏数据完整性；验证类需求请用 SELECT 复现影响或在对靶场快照说明并获用户批准后进行。降级替代：SELECT 只读查询复现影响；或靶场快照上验证并注明环境。";
	}
	if (/\b(shutdown\b|reboot\b|systemctl\s+(stop|restart|disable)\b|service\s+\w+\s+(stop|restart)\b|kill\s+-9\s+1\b)/i.test(compact)) {
		return "停机/重启/杀服务属变更性操作，被拦截：需先询问用户（呈报影响与理由，获批准后执行）。降级替代：systemctl status/日志只读收集根因，处置步骤列入建议清单由用户执行。";
	}
	const fundsUrl = /(pay|refund|withdraw|order|recharge|transfer)[a-z]*\/|[?&](out_trade_no|trade_no|order_id)=/i;
	const isPost =
		/(\bcurl\b[^|;&]*(-X\s*(POST|PUT)|--data(-raw|-binary)?\s|\s-d\s))|(\bwget\b[^|;&]*--post-data)/i.test(compact);
	if (isPost && fundsUrl.test(compact)) {
		return "资金类接口写请求（支付/退款/提现/下单）被拦截：不可逆操作禁止自动执行（PORT-CONVENTIONS 第 8 条）——只生成重放计划呈报用户，获明确批准后才执行。降级替代：生成只读重放计划（curl 命令+预期响应比对）呈报用户，不实际发送。";
	}
	return undefined;
}

/** ask 中间档（变更性但可逆）——命中返回呈报理由，未命中返回 undefined。 */
export function scanAsk(command: string): string | undefined {
	const cmd = String(command ?? "");
	const compact = cmd.replace(/\\\n/g, " ").replace(/\s+/g, " ");
	if (
		/\b(useradd|usermod|userdel|adduser|deluser)\b/.test(compact) ||
		/(^|[|;&]|sudo )\s*(passwd|chpasswd)\b/.test(compact) ||
		/\b(mysql|mariadb|psql|sqlplus|sqlite3)\b[^|;&]*\b(GRANT\s+|REVOKE\s+|CREATE\s+USER|DROP\s+USER|ALTER\s+USER)\b/i.test(compact)
	) {
		return "账号/权限体系变更类命令需人工审批：改的是目标环境的身份与授权面（不可轻动、影响所有后续访问）——批准即执行，拒绝则换只读方案（如 SELECT 验证权限现状）。";
	}
	if (/\biptables\s+(-F\b|--flush)|\bnft\s+(add|delete|flush)\b|\bufw\s+(enable|disable|allow|deny|insert|delete)\b/.test(compact)) {
		return "防火墙/安全规则修改需人工审批：直接改变目标网络暴露面（可能自断回连或放大暴露）——批准即执行，拒绝则先 iptables -L/nft list ruleset 只读核对再呈报变更清单。";
	}
	if (/\b(hping3|hping)\b[^|;&]*\b--flood\b|--flood\b|\bslowloris\b|\bsynflood\b/i.test(compact)) {
		return "flood 类压测命令需人工审批：显式洪水语义（--flood/slowloris/synflood）可能构成对目标的服务压力——批准即执行（确在授权范围），拒绝则改用带速率上限的常规验证。";
	}
	return undefined;
}

/** 裸奔扫描特征——命中返回带修法的拒绝理由（修法即降级替代）。 */
export function scanRate(command: string): string | undefined {
	const cmd = String(command ?? "");
	const compact = cmd.replace(/\\\n/g, " ").replace(/\s+/g, " ");
	if (/\bnmap\b/.test(compact) && /(-p-\s|--?p\s*1-65535|-p\s*1-65535)/.test(compact) && !/(--max-rate|-T[0-3]\b|--min-rate)/.test(compact)) {
		return "全端口 nmap 未带速率控制被拦截（速率纪律）：加 --max-rate（如 --max-rate 300）或 -T2/-T3 后重试；WAF/生产目标从严。降级替代：--top-ports 100 常见端口概览；或先被动侦察（子域/DNS/公开情报）再定向验证。";
	}
	const massRate = compact.match(/--rate\s+(\d+)/);
	if (/\bmasscan\b/.test(compact) && massRate && Number(massRate[1]) > 1000) {
		return `masscan --rate ${massRate[1]} 超保守上限（1000）被拦截：下调 --rate（500 起步）后重试。降级替代：--rate 500 并缩小到授权网段；或改 nmap -sS --max-rate 300 定向扫描。`;
	}
	if (/(^|\s|\/)ffuf\b/.test(compact) && /-u\s/.test(compact) && !/-rate\b/.test(compact)) {
		return "裸 ffuf 未带 -rate 被拦截：加 -rate 50（保守默认）重试，或改用已封装的 ffuf_fuzz 工具（速率纪律/防盲打/证据留痕内置）。降级替代：-rate 50 重试，或改 ffuf_fuzz 封装工具（防盲打/证据落盘内置）。";
	}
	return undefined;
}

export interface OperationState {
	criteria?: { id?: string; status?: string }[];
	intents?: { id?: string; status?: string }[];
	constraints?: { id?: string; kind?: string; text?: string; keywords?: string[] }[];
}

export function openCriteriaIds(state: OperationState | null): string[] | null {
	if (!state || !Array.isArray(state.criteria) || state.criteria.length === 0) return null;
	return state.criteria.filter((c) => c && c.status !== "met").map((c) => String(c.id ?? "?"));
}

export function openIntentsOf(state: OperationState | null): string[] {
	if (!state || !Array.isArray(state.intents)) return [];
	return state.intents.filter((i) => i && i.status === "open").map((i) => String(i.id ?? "?"));
}

export function constraintHits(subject: string, state: OperationState | null): { id: string; text: string }[] {
	if (!state || !Array.isArray(state.constraints)) return [];
	const needle = String(subject ?? "");
	if (!needle) return [];
	const out: { id: string; text: string }[] = [];
	for (const c of state.constraints) {
		if (!c || c.kind !== "deny" || !Array.isArray(c.keywords)) continue;
		if (c.keywords.some((k) => typeof k === "string" && k && needle.toLowerCase().includes(k.toLowerCase()))) {
			out.push({ id: String(c.id ?? "?"), text: String(c.text ?? "") });
		}
	}
	return out;
}

// ── decision（纯函数，可脱机自测） ──

export interface DecideEnv {
	workspace: string;
	/** 是否认定为九安全模式会话（Pi 侧探测结果，见 resolveSession） */
	armed: boolean;
	/** 具体模式；探测到安全会话但模式未知时为 undefined（走与模式无关档位 + 报告门通用文案） */
	mode: string | undefined;
	config: SecEnforceConfig;
	killTripped: boolean;
	readGateLog: () => string;
	readOperationState: () => OperationState | null;
}

export interface Decision {
	kind: "block" | "ask";
	rule: keyof SecEnforceConfig | "killSwitch";
	reason: string;
}

function constraintReason(subject: string, env: DecideEnv): string | undefined {
	if (!env.config.constraintGate) return undefined;
	const hits = constraintHits(subject, env.readOperationState());
	if (hits.length === 0) return undefined;
	return `任务约束拦截（${hits.map((h) => h.id).join(",")}）：${hits.map((h) => h.text).join("；")}——该约束为开工时登记的用户红线（operation_constraints，命中匹配词即拦）；确需此项操作，先与用户确认并修订约束台账。`;
}

/** 报告门（reports/ 落盘前）：gate pass → 准则 → 意图 三查；模式未登记报告门时走专用文案。 */
function reportGateReason(target: string, content: string | undefined, env: DecideEnv): string | undefined {
	if (!isReportPath(target, env.workspace)) return undefined;
	const mode = env.mode;
	if (mode === undefined) {
		// 安全会话但模式未定：不猜门号，只要求 gate-log.md 存在任一 pass 行
		const log0 = env.readGateLog();
		const known = modesInGateLog(log0).find((m) => gateLogHasPass(log0, m, REPORT_GATE[m] ?? "__none__"));
		if (known) return undefined;
		return `报告落盘被确定性门禁拦截：本会话模式未判定，无法确定该过哪道报告门。reports/ 落盘前 gate-log.md 需要本模式报告门的 pass 行（pentest/P3、code-audit/A3、binary-analysis/B2、attack-defense/report、av-evasion/V4、incident-response/I5、cloud-security/C7、ctf-solver/flag）。修法：显式声明模式（${CONFIG_FILE} 的 mode 或 PI_SEC_ENFORCE_MODE）后过对应门，或手工追加一行「| ${new Date().toISOString()} | <mode>/<gate> | pass | <证据路径> |」。`;
	}
	const gateId = REPORT_GATE[mode];
	if (mode === "redteam" || gateId === undefined) {
		const who = mode === "redteam" ? "redteam 主模式总控" : `${mode}（未登记报告门）`;
		return `报告落盘被拦截：${who}只消费专业模式报告（gate-pass 产物），不写 reports/——全局总结落工作区根目录（summary.md + task-ledger.md 台账），深度任务的报告由对应专业模式会话产出。`;
	}
	const log = env.readGateLog();
	if (!gateLogHasPass(log, mode, gateId)) {
		return `报告落盘被确定性门禁拦截：先过 ${mode} 的 ${gateId} 门（覆盖度/完整性），gate-log.md 出现 "${mode}/${gateId} | pass" 后才能写 reports/。Pi 侧 stage_gate 工具由 dsh-stage-gate 移植件提供；未装载时手工在 ${path.join(env.workspace, "gate-log.md")} 追加一行「| ${new Date().toISOString()} | ${mode}/${gateId} | pass | <证据路径> |」。`;
	}
	const state = env.readOperationState();
	const openIds = openCriteriaIds(state);
	if (openIds !== null && openIds.length > 0) {
		return `报告落盘被目标契约拦截：operation-state.json 尚有未收口准则（${openIds.join(", ")}）——先逐条置 met（带证据），或与用户确认修订目标后再产出 reports/。`;
	}
	if (env.config.intentGate) {
		const openIntentIds = openIntentsOf(state);
		if (openIntentIds.length > 0) {
			return `报告落盘被意图台账拦截：尚有未收口方向（${openIntentIds.join(", ")}）——逐条收口（blocked/dropped 须 note 原因），或与用户确认放弃后再产出 reports/。`;
		}
	}
	return undefined;
}

/**
 * 单条工具调用的确定性判定。mode === undefined 且 enabled!=="on" → 完全不介入。
 * 返回 block / ask / undefined（放行）。优先级与源实现一致：
 * killSwitch > 写边界 > 任务书锚点 > 报告门 > 高危 > 速率 > 约束 > ask 档。
 */
export function decide(
	exec: { toolName: string; input: Record<string, unknown> },
	env: DecideEnv,
): Decision | undefined {
	const cfg = env.config;
	// 熔断拦一切「操作」，但保留只读控制面自身：否则 Agent 连「查状态 / 解除熔断」都被拦，
	// 熔断变成只有人工能救的死锁。sec_enforce_status 不执行任何测试/攻击动作，不违反熔断语义。
	if (cfg.killSwitch && env.killTripped && exec.toolName !== SELF_TOOL)
		return { kind: "block", rule: "killSwitch", reason: KILL_REASON() };
	if (!env.armed) return undefined;

	const { toolName, input } = exec;
	let reason: string | undefined;
	let rule: Decision["rule"] = "writeBoundary";

	if (WRITE_TOOLS.has(toolName)) {
		const target = typeof input.path === "string" ? input.path : typeof input.file_path === "string" ? input.file_path : undefined;
		if (typeof target === "string" && target && env.workspace) {
			const allowDirs = [STATE_DIR, ...cfg.allowDirs];
			const content = typeof input.content === "string" ? input.content : undefined;
			if (cfg.writeBoundary && !isWritable(target, env.workspace, allowDirs)) {
				rule = "writeBoundary";
				reason = `写入目标在任务工作区之外（${realish(env.workspace)}）被拦截：安全预设写操作限工作区内（工具级最小权限）；确需写外部路径，先征得用户批准并在会话中说明（或加入 ${CONFIG_FILE} 的 allowDirs）。`;
			} else if (
				cfg.taskBriefGate &&
				env.mode === "redteam" &&
				typeof content === "string" &&
				isTaskBriefPath(target, env.workspace) &&
				!TASK_BRIEF_ANCHOR_RE.test(content)
			) {
				rule = "taskBriefGate";
				reason = "任务书缺「依据：」锚点行被拦截：写明凭什么开这单——用户目标原句引用 / 已收集材料落盘路径 / 关联成果 id（顶层任务=用户目标即锚）。在任务书末尾补一行「依据：…」后重写。";
			} else if (cfg.reportGate) {
				rule = "reportGate";
				reason = reportGateReason(target, content, env);
			}
		}
	} else if (SHELL_TOOLS.has(toolName) && typeof input.command === "string") {
		// 优先级与源实现一致：高危硬拦 > 速率纪律 > 任务约束 > ask 档（档内 rule 标注命中那一档）
		const command = input.command;
		const danger = cfg.dangerousOps ? scanDangerous(command) : undefined;
		if (danger !== undefined) return { kind: "block", rule: "dangerousOps", reason: danger };
		const rate = cfg.rateDiscipline ? scanRate(command) : undefined;
		if (rate !== undefined) return { kind: "block", rule: "rateDiscipline", reason: rate };
		const cons = constraintReason(command, env);
		if (cons !== undefined) return { kind: "block", rule: "constraintGate", reason: cons };
		if (cfg.askGate) {
			const ask = scanAsk(command);
			if (ask !== undefined) return { kind: "ask", rule: "askGate", reason: ask };
		}
		return undefined;
	} else if (toolName === "fetch" && typeof input.url === "string") {
		rule = "constraintGate";
		reason = constraintReason(input.url, env);
	}

	if (reason === undefined) return undefined;
	return { kind: "block", rule, reason };
}

// ── 会话态（模式探测结果按会话粘住；轮次计数用 Pi turn_start） ──

interface SessionState {
	mode: string | undefined;
	armed: boolean;
	via: string;
	turnIndex: number;
	blocks: Map<string, number>;
	totalBlocks: number;
	totalAsks: number;
}

const sessions = new Map<string, SessionState>();
const sessionKey = (ctx: ExtensionContext): string => {
	try {
		return `${ctx.sessionManager.getSessionId()}|${ctx.cwd}`;
	} catch {
		return ctx.cwd;
	}
};


/**
 * 工作区侧探测（与 dsh preset 平面无关）：安全工件存在 = 安全会话；
 * 模式优先从 operation-state.json（dsh-stage-gate 移植件写）取，
 * 其次从 gate-log.md 的 mode/gate 列反推（只有一个模式时可信）。
 */
export function detectWorkspaceMode(workspace: string): { armed: boolean; mode?: string; via: string } {
	const found = WORKSPACE_MARKERS.filter((m) => {
		try {
			return fs.existsSync(path.join(workspace, m));
		} catch {
			return false;
		}
	});
	if (found.length === 0) return { armed: false, via: "" };
	const st = readStateAt(path.join(workspace, "operation-state.json"));
	const stateMode = typeof st?.mode === "string" && SECURITY_MODES.has(st.mode) ? st.mode : undefined;
	if (stateMode) return { armed: true, mode: stateMode, via: `workspace:operation-state(${found[0]})` };
	const modes = modesInGateLog(safeRead(path.join(workspace, "gate-log.md")));
	if (modes.length === 1) return { armed: true, mode: modes[0], via: `workspace:gate-log(${found[0]})` };
	return { armed: true, via: `workspace:${found[0]}` };
}

function readStateAt(file: string): OperationState | null {
	try {
		return JSON.parse(fs.readFileSync(file, "utf8")) as OperationState;
	} catch {
		return null;
	}
}

/** Pi 侧模式判定（替代 dsh ctx.agentPresets.composedPreset）——见文件头差异说明。 */
function resolveSession(ctx: ExtensionContext, cfg: SecEnforceConfig): SessionState {
	const key = sessionKey(ctx);
	let st = sessions.get(key);
	if (!st) {
		st = { mode: undefined, armed: false, via: "", turnIndex: 0, blocks: new Map(), totalBlocks: 0, totalAsks: 0 };
		sessions.set(key, st);
	}
	if (st.armed || cfg.enabled === "off") return st;

	if (cfg.enabled === "on") {
		st.armed = true;
		st.via = "enabled=on";
		if (cfg.mode) st.mode = cfg.mode;
		return st;
	}

	if (cfg.mode) {
		st.mode = cfg.mode;
		st.armed = true;
		st.via = "config/env";
	} else {
		const detected = detectWorkspaceMode(ctx.cwd);
		if (detected.armed) {
			st.armed = true;
			st.mode = detected.mode;
			st.via = detected.via;
		} else {
			const prompt = safeGetSystemPrompt(ctx);
			const hit = SECURITY_PROMPT_MARKERS.find((m) => prompt.includes(m));
			if (hit) {
				st.armed = true;
				st.via = `prompt:${hit.slice(0, 24)}`;
			}
		}
	}
	// 探测到安全会话但模式未知：仍执行与模式无关的档位，
	// 报告门走「模式未判定」文案（不猜门名，不误报某个具体的门）。
	return st;
}

function safeRead(file: string): string {
	try {
		return fs.readFileSync(file, "utf8");
	} catch {
		return "";
	}
}

function safeGetSystemPrompt(ctx: ExtensionContext): string {
	try {
		return ctx.getSystemPrompt() ?? "";
	} catch {
		return "";
	}
}

// ── 留痕 ──

const LOG_HEADER = "# dsh-sec-enforce 拦截留痕（Pi port）\n\n| 时间 | 模式 | 判定 | 工具 | 规则 | 理由首段 | 轮次 |\n|---|---|---|---|---|---|---|\n";

function appendLog(workspace: string, row: string): void {
	try {
		fs.mkdirSync(STATE_DIR, { recursive: true });
		if (!fs.existsSync(GLOBAL_LOG)) fs.writeFileSync(GLOBAL_LOG, LOG_HEADER);
		fs.appendFileSync(GLOBAL_LOG, row);
	} catch {
		/* 留痕失败不影响判定 */
	}
	try {
		if (workspace && !workspace.includes("redteam/dsh-sec-enforce")) {
			const wsLog = path.join(workspace, "enforce-log.md");
			if (!fs.existsSync(wsLog)) fs.writeFileSync(wsLog, LOG_HEADER);
			fs.appendFileSync(wsLog, row);
		}
	} catch {
		/* 工作区不可写就只留全局一份 */
	}
}

function logRow(st: SessionState, decision: { kind: string; rule: Decision["rule"]; reason: string }, toolName: string): string {
	const head = decision.reason.split("：")[0].replace(/\|/g, "/").replace(/\s+/g, " ").slice(0, 120);
	return `| ${new Date().toISOString()} | ${st.mode ?? "-"} | ${decision.kind} | ${toolName} | ${decision.rule} | ${head} | ${st.turnIndex} |\n`;
}

// ── 自测（纯函数路径，脱机；PI_SEC_ENFORCE_SELFTEST=<outfile> 时执行） ──

export function runSelfTest(): { pass: number; fail: number; failures: string[] } {
	const WS = "/tmp/sec-enforce-ws";
	let pass = 0;
	const failures: string[] = [];
	const ok = (label: string, cond: boolean) => {
		if (cond) pass++;
		else failures.push(label);
	};
	const cfg = DEFAULT_CONFIG;
	const env = (over: Partial<DecideEnv> = {}): DecideEnv => ({
		workspace: WS,
		armed: true,
		mode: "pentest",
		config: cfg,
		killTripped: false,
		readGateLog: () => "",
		readOperationState: () => null,
		...over,
	});
	const write = (p: string, content?: string) => ({ toolName: "write", input: { path: p, content } });
	const bash = (command: string) => ({ toolName: "bash", input: { command } });

	// report gate
	ok("report write without gate pass blocked", decide(write(`${WS}/reports/a.md`, "x"), env())?.reason.includes("P3") === true);
	ok("report write with gate pass allowed", decide(write(`${WS}/reports/a.md`, "x"), env({ readGateLog: () => "| t | pentest/P3 | pass | - |" })) === undefined);
	ok("wrong gate pass does not unlock", decide(write(`${WS}/reports/a.md`, "x"), env({ readGateLog: () => "| t | pentest/P1 | pass | - |" }))?.kind === "block");
	ok("redteam reports/ uses controller wording", (() => {
		const r = decide(write(`${WS}/reports/a.md`, "x"), env({ mode: "redteam" }))?.reason ?? "";
		return r.includes("redteam") && r.includes("summary.md") && !r.includes("undefined");
	})());
	// write boundary
	ok("write outside ws blocked", decide(write("/etc/cron.d/x", "y"), env())?.rule === "writeBoundary");
	ok("write inside ws allowed", decide(write(`${WS}/assets.md`, "y"), env()) === undefined);
	ok("non-security session untouched", decide(write("/etc/cron.d/x", "y"), env({ armed: false, mode: undefined })) === undefined);
	ok("edit tool path checked too", decide({ toolName: "edit", input: { path: "/etc/cron.d/x", edits: [] } }, env())?.rule === "writeBoundary");
	ok("powershell dangerous checked", decide({ toolName: "powershell", input: { command: "Remove-Item -Recurse C:\\Windows\\Temp\\x" } }, env())?.kind === "block");
	ok("unknown mode still blocks outside write", decide(write("/etc/cron.d/x", "y"), env({ mode: undefined }))?.rule === "writeBoundary");
	ok("unknown mode report needs some pass line", (() => {
		const blocked = decide(write(`${WS}/reports/a.md`, "x"), env({ mode: undefined }));
		const allowed = decide(write(`${WS}/reports/a.md`, "x"), env({ mode: undefined, readGateLog: () => "| t | cloud-security/C7 | pass | - |" }));
		return blocked?.reason.includes("模式未判定") === true && allowed === undefined;
	})());
	ok("allowDirs exempts write", decide(write("/opt/tools/x.bin", "y"), env({ config: { ...cfg, allowDirs: ["/opt/tools"] } })) === undefined);
	// dangerous
	for (const [cmd, label] of [
		["rm -rf /tmp/x; rm -rf /", "rm root"],
		["rm -rf ~/everything", "rm home"],
		["powershell Remove-Item -Recurse -Force C:\\Windows\\Temp\\all", "win remove-item"],
		["cmd /c rd /s /q C:\\", "win rd /s"],
		["mkfs.ext4 /dev/sdb1", "mkfs"],
		["mysql -e 'DROP TABLE users'", "drop table"],
		["systemctl restart nginx", "restart service"],
		["curl -X POST https://x.com/api/pay/create -d 'amount=1'", "funds post"],
	] as const) {
		ok(`dangerous blocked: ${label}`, decide(bash(cmd as string), env())?.kind === "block");
	}
	ok("workspace cleanup rm allowed", decide(bash("rm -rf ./artifacts/old"), env()) === undefined);
	ok("normal SELECT allowed", decide(bash("mysql -e 'SELECT * FROM users'"), env()) === undefined);
	ok("every blocked message carries 降级替代", [
		"rm -rf /",
		"mysql -e 'DROP TABLE users'",
		"systemctl restart nginx",
		"curl -X POST https://x.com/api/pay/create -d a=1",
	].every((c) => (scanDangerous(c) ?? "").includes("降级替代")));
	// rate
	ok("nmap -p- no rate blocked", decide(bash("nmap -sS -p- 10.0.0.1"), env())?.kind === "block");
	ok("nmap -p- --max-rate allowed", decide(bash("nmap -sS -p- --max-rate 300 10.0.0.1"), env()) === undefined);
	ok("masscan --rate 5000 blocked", decide(bash("masscan -p80 --rate 5000 10.0.0.0/24"), env())?.kind === "block");
	ok("bare ffuf blocked", decide(bash("ffuf -u https://x/FUZZ -w w.txt"), env())?.kind === "block");
	ok("rate hit is labelled rateDiscipline", decide(bash("nmap -sS -p- 10.0.0.1"), env())?.rule === "rateDiscipline");
	ok("danger hit is labelled dangerousOps", decide(bash("shutdown -h now"), env())?.rule === "dangerousOps");
	ok("constraint hit is labelled constraintGate", decide(bash("sqlmap -u https://t/pay"), env({ readOperationState: () => ({ constraints: [{ id: "c1", kind: "deny", text: "不碰支付", keywords: ["pay"] }] }) }))?.rule === "constraintGate");
	ok("ffuf -rate allowed", decide(bash("ffuf -u https://x/FUZZ -w w.txt -rate 50"), env()) === undefined);
	// ask tier
	ok("useradd routed to ask", decide(bash("sudo useradd -m backdoor"), env())?.kind === "ask");
	ok("iptables -F routed to ask", decide(bash("iptables -F"), env())?.kind === "ask");
	ok("/etc/passwd read not ask", decide(bash("curl -s 'http://t/fi/?page=/etc/passwd'"), env()) === undefined);
	ok("shutdown stays hard block", decide(bash("shutdown -h now"), env())?.kind === "block");
	// criteria / intents / constraints
	ok("open criteria blocks report", (() => {
		const r = decide(write(`${WS}/reports/a.md`, "x"), env({ readGateLog: () => "| t | pentest/P3 | pass | - |", readOperationState: () => ({ criteria: [{ id: "g1", status: "met" }, { id: "g2", status: "open" }] }) }))?.reason ?? "";
		return r.includes("目标契约") && r.includes("g2");
	})());
	ok("open intent blocks report", (decide(write(`${WS}/reports/a.md`, "x"), env({ readGateLog: () => "| t | pentest/P3 | pass | - |", readOperationState: () => ({ intents: [{ id: "i1", status: "open" }] }) }))?.reason ?? "").includes("意图台账"));
	ok("deny constraint keyword blocks bash", (decide(bash("sqlmap -u https://t/api/pay/order?id=1"), env({ readOperationState: () => ({ constraints: [{ id: "c1", kind: "deny", text: "不碰支付接口", keywords: ["pay"] }] }) }))?.reason ?? "").includes("不碰支付接口"));
	ok("toggles all off = no-op", decide(bash("systemctl restart nginx"), env({ config: { ...cfg, dangerousOps: false, rateDiscipline: false, askGate: false, writeBoundary: false, reportGate: false } })) === undefined);
	// kill switch
	ok("kill switch blocks non-armed session too", decide(bash("ls"), env({ armed: false, killTripped: true }))?.kind === "block");
	ok("kill switch still blocks write tool", decide(write(`${WS}/assets.md`, "y"), env({ killTripped: true }))?.rule === "killSwitch");
	ok("kill switch does NOT block sec_enforce_status (agent self-recovery path)", decide({ toolName: "sec_enforce_status", input: { action: "clear" } }, env({ killTripped: true })) === undefined);
	ok("kill switch does NOT block sec_enforce_status when unarmed", decide({ toolName: "sec_enforce_status", input: {} }, env({ armed: false, killTripped: true })) === undefined);
	// geometry helpers
	ok("isReportPath false for outside ws", isReportPath("/other/reports/x.md", WS) === false);
	{
		let symlinkTmp = false;
		try {
			symlinkTmp = fs.realpathSync("/tmp") !== "/tmp";
		} catch {
			/* ignore */
		}
		ok("absolute path inside ws is writable", isWritable(`${WS}/a/b.md`, WS) === true);
		ok("symlinked workspace root tolerated (/tmp -> /private/tmp)", !symlinkTmp || isWritable("/tmp/sec-enforce-ws/a.md", "/private/tmp/sec-enforce-ws") === true);
		ok("report path via symlinked root still recognised", !symlinkTmp || isReportPath("/tmp/sec-enforce-ws/reports/a.md", "/private/tmp/sec-enforce-ws") === true);
	}
	ok("isTaskBriefPath only md under task-briefs", isTaskBriefPath(`${WS}/task-briefs/t.json`, WS) === false);
	ok("anchor regex tolerates list prefix", TASK_BRIEF_ANCHOR_RE.test("- 依据：材料 docs/x.md\n") === true);
	ok("task brief without anchor blocked", (() => {
		const r = decide({ toolName: "write", input: { path: `${WS}/task-briefs/t.md`, content: "# 任务书\n- 目标：x\n" } }, env({ mode: "redteam" }));
		return r?.reason.includes("依据") === true;
	})());

	ok("mode resolved from operation-state.json", (() => {
		const dir = fs.mkdtempSync(path.join(tmpdir(), "sec-detect-"));
		try {
			fs.writeFileSync(path.join(dir, "operation-state.json"), JSON.stringify({ version: 1, mode: "cloud-security", criteria: [] }));
			const d = detectWorkspaceMode(dir);
			return d.armed === true && d.mode === "cloud-security" && d.via.startsWith("workspace:operation-state");
		}
		finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	})());
	ok("mode inferred from single-mode gate-log", (() => {
		const dir = fs.mkdtempSync(path.join(tmpdir(), "sec-detect-"));
		try {
			fs.writeFileSync(path.join(dir, "gate-log.md"), "| t | av-evasion/V4 | pass | - |\n");
			const d = detectWorkspaceMode(dir);
			return d.armed === true && d.mode === "av-evasion";
		}
		finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	})());
	ok("armed without mode when markers present but ambiguous", (() => {
		const dir = fs.mkdtempSync(path.join(tmpdir(), "sec-detect-"));
		try {
			fs.writeFileSync(path.join(dir, "task-ledger.md"), "# ledger\n");
			const d = detectWorkspaceMode(dir);
			return d.armed === true && d.mode === undefined;
		}
		finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	})());
	ok("blank workspace not armed", (() => {
		const dir = fs.mkdtempSync(path.join(tmpdir(), "sec-detect-"));
		try {
			return detectWorkspaceMode(dir).armed === false;
		}
		finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	})());

	return { pass, fail: failures.length, failures };
}

// ── extension factory ──

const StatusParams = Type.Object({ action: Type.Optional(Type.String({ description: "status | rules | log | clear（默认 status）；clear=解除全局熔断（删 KILL 标记并在 enforce-log 留痕）" })) });

export default function (pi: ExtensionAPI) {
	const readGateLog = (workspace: string) => safeRead(path.join(workspace, "gate-log.md"));
	const readOperationState = (workspace: string): OperationState | null => {
		try {
			return JSON.parse(fs.readFileSync(path.join(workspace, "operation-state.json"), "utf8")) as OperationState;
		} catch {
			return null;
		}
	};

	const selfTestOut = (process.env.PI_SEC_ENFORCE_SELFTEST || "").trim();
	if (selfTestOut) {
		try {
			const r = runSelfTest();
			fs.writeFileSync(selfTestOut, `selftest pass=${r.pass} fail=${r.fail}\n${r.failures.map((f) => `FAIL ${f}`).join("\n")}${r.failures.length ? "\n" : ""}`);
		} catch (err) {
			try {
				fs.writeFileSync(selfTestOut, `selftest crashed: ${String(err)}`);
			} catch {
				/* ignore */
			}
		}
	}

	pi.on("session_start", (_event, ctx) => {
		const cfg = loadConfig();
		configCache = undefined;
		const st = resolveSession(ctx, cfg);
		try {
			pi.appendEntry("sec-enforce", { armed: st.armed, mode: st.mode ?? null, via: st.via || null, enabled: cfg.enabled, cwd: ctx.cwd });
		} catch {
			/* appendEntry 不可用时忽略 */
		}
		if (ctx.mode === "tui") {
			try {
				ctx.ui.setStatus("sec-enforce", st.armed ? `🔒 enforce:${st.mode ?? "?"}` : undefined);
			} catch {
				/* ignore */
			}
		}
	});

	pi.on("turn_start", (event, ctx) => {
		const st = sessions.get(sessionKey(ctx));
		if (st) st.turnIndex = event.turnIndex;
	});

	pi.on("tool_call", async (event, ctx) => {
		const cfg = loadConfig();
		if (cfg.enabled === "off") return undefined;
		const st = resolveSession(ctx, cfg);
		// skill 工具真实装载 redteam playbook 时把模式定下来（系统提示里的技能名录不是证据）
		const invokedSkill = event.toolName === "skill" ? String((event.input as Record<string, unknown>).name ?? "") : "";
		if (invokedSkill && SKILL_MODE_MAP[invokedSkill]) {
			st.armed = true;
			st.mode = SKILL_MODE_MAP[invokedSkill];
			st.via = `skill:${invokedSkill}`;
		}
		if (!st.armed) return undefined;

		const env: DecideEnv = {
			workspace: ctx.cwd,
			armed: st.armed,
			mode: st.mode ?? cfg.mode,
			config: cfg,
			killTripped: killTripped(),
			readGateLog: () => readGateLog(ctx.cwd),
			readOperationState: () => readOperationState(ctx.cwd),
		};

		let decision: Decision | undefined;
		try {
			decision = decide({ toolName: event.toolName, input: event.input as Record<string, unknown> }, env);
		} catch {
			// 判定内部异常不炸会话（fail-open；与「处理失败即拦」相比，避免卡死正常工作流）
			return undefined;
		}
		if (!decision) return undefined;

		// ask 档：有 UI 走宿主确认（批准即执行），拒绝/超时/无通道 → 拒
		if (decision.kind === "ask") {
			if (ctx.hasUI) {
				try {
					const approved = await ctx.ui.confirm("安全门禁：确认执行？", `${decision.reason}\n\n命令：${String((event.input as Record<string, unknown>).command ?? "")}`, {
						timeout: cfg.askTimeoutMs,
					});
					if (approved) {
						st.totalAsks++;
						appendLog(ctx.cwd, logRow(st, { kind: "ask-allow", rule: decision.rule, reason: "已批准放行" }, event.toolName));
						return undefined;
					}
				} catch {
					/* 无审批通道 → 落到拦截 */
				}
			}
			appendLog(ctx.cwd, logRow(st, { ...decision, kind: "ask-block" }, event.toolName));
			countBlock(st, decision);
			notify(ctx, `安全门禁拦截（${decision.rule}）：需人工批准`);
			return { block: true, reason: `${decision.reason}\n\n（当前会话无人工审批通道或审批被拒绝/超时；改走上述降级替代，或把命令呈报用户批准后再执行。）` };
		}

		appendLog(ctx.cwd, logRow(st, decision, event.toolName));
		countBlock(st, decision);
		notify(ctx, `安全门禁拦截（${decision.rule}）`);
		return { block: true, reason: decision.reason };
	});

	pi.registerTool({
		name: "sec_enforce_status",
		label: "sec_enforce_status",
		description:
			"查询确定性安全门禁当前是否生效、生效哪几档、以及最近拦截记录。被拦截后不确定规则时用它，不要猜。action 可省（status）；rules=规则全表；log=最近拦截行；clear=解除全局熔断（KILL 熔断期间的 Agent 自恢复通道，本工具自身不受熔断拦截）。",
		parameters: StatusParams,
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const cfg = loadConfig();
			const st = resolveSession(ctx, cfg);
			const action = (params.action || "status").trim();
			let text: string;
			if (action === "rules") text = RULES_TABLE;
			else if (action === "clear") {
				const marker = KILL_MARKER();
				const wasTripped = killTripped();
				let err = "";
				try {
					fs.rmSync(marker, { force: true });
				} catch (e) {
					err = String((e as Error)?.message ?? e);
				}
				const still = killTripped();
				appendLog(ctx.cwd, logRow(st, {
					kind: wasTripped ? "clear" : "clear-noop",
					rule: "killSwitch",
					reason: err
						? `解除全局熔断失败：${err}`
						: wasTripped ? "Agent 主动解除全局熔断：sec_enforce_status action=clear" : "全局熔断原本未触发：action=clear 幂等无副作用",
				}, SELF_TOOL));
				text = [
					wasTripped ? "全局熔断已解除（此前处于触发态）" : "全局熔断此前未触发（幂等 no-op，未产生副作用）",
					`标记文件 ${marker} 现在${still ? "仍存在" : "不存在"}${err ? `；删除报错：${err}` : ""}`,
					still ? "工具链仍被拦——请把上面的报错转给用户处理。" : `工具链已恢复；熔断判定每次工具调用重读标记文件，下一轮即生效。`,
					`留痕：${GLOBAL_LOG}（action=log 可查）`,
				].join("\n");
				return {
					content: [{ type: "text", text }],
					details: { armed: st.armed, mode: st.mode ?? null, via: st.via || null, config: cfg, blocks: st.totalBlocks, killWasTripped: wasTripped, killTrippedNow: still, clearError: err || null },
				};
			} else if (action === "log") {
				const tail = safeRead(GLOBAL_LOG).split("\n").filter((l) => l.startsWith("|")).slice(-15).join("\n") || "（暂无拦截记录）";
				text = `拦截留痕（最近 15 条，全文 ${GLOBAL_LOG}）\n${tail}`;
			} else {
				text = [
					`enabled=${cfg.enabled} armed=${st.armed} mode=${st.mode ?? "-"} via=${st.via || "-"}`,
					`workspace=${ctx.cwd}`,
					`档位: reportGate=${cfg.reportGate} writeBoundary=${cfg.writeBoundary} dangerousOps=${cfg.dangerousOps} rateDiscipline=${cfg.rateDiscipline} askGate=${cfg.askGate} intentGate=${cfg.intentGate} constraintGate=${cfg.constraintGate} taskBriefGate=${cfg.taskBriefGate} killSwitch=${cfg.killSwitch}`,
					`allowDirs=${[STATE_DIR, ...cfg.allowDirs].join(", ")}`,
					`全局熔断: ${killTripped() ? "已触发（移除 " + KILL_MARKER() + " 即恢复）" : "未触发"}`,
					`本会话累计：拦截 ${st.totalBlocks} 次 / 审批 ${st.totalAsks} 次；留痕 ${GLOBAL_LOG}`,
					"细则见 rules（action=rules）。",
				].join("\n");
			}
			return {
				content: [{ type: "text", text }],
				details: { armed: st.armed, mode: st.mode ?? null, via: st.via || null, config: cfg, blocks: st.totalBlocks },
			};
		},
	});

	pi.registerCommand("sec-enforce", {
		description: "确定性安全门禁：status | rules | log [n] | on | off | trip | clear | selftest",
		handler: async (args, ctx) => {
			const parts = args.trim().split(/\s+/);
			const sub = (parts[0] || "status").toLowerCase();
			if (sub === "on") {
				saveConfig({ enabled: "on" });
				ctx.ui.notify("dsh-sec-enforce: 已强制开启（enabled=on）", "info");
				return;
			}
			if (sub === "off") {
				saveConfig({ enabled: "off" });
				ctx.ui.notify("dsh-sec-enforce: 已全关（enabled=off）；/reload 后判定立即停", "info");
				return;
			}
			if (sub === "trip") {
				fs.mkdirSync(STATE_DIR, { recursive: true });
				fs.writeFileSync(KILL_MARKER(), "trip");
				ctx.ui.notify(`全局熔断已触发；恢复：/sec-enforce clear 或 rm ${KILL_MARKER()}`, "warning");
				return;
			}
			if (sub === "clear") {
				try {
					fs.rmSync(KILL_MARKER(), { force: true });
				} catch {
					/* ignore */
				}
				ctx.ui.notify("全局熔断已解除", "info");
				return;
			}
			if (sub === "selftest") {
				const r = runSelfTest();
				ctx.ui.notify(`selftest pass=${r.pass} fail=${r.fail}${r.failures.length ? ` → ${r.failures.join("; ")}` : ""}`, r.fail ? "error" : "info");
				return;
			}
			const cfg = loadConfig();
			const st = resolveSession(ctx, cfg);
			const summary = `enforce armed=${st.armed} mode=${st.mode ?? "-"} enabled=${cfg.enabled} blocks=${st.totalBlocks}`;
			if (sub === "rules") {
				fs.mkdirSync(STATE_DIR, { recursive: true });
				fs.writeFileSync(RULES_DOC, `${RULES_TABLE}\n`);
				ctx.ui.notify(`规则表已写入 ${RULES_DOC}`, "info");
				return;
			}
			if (sub === "log") {
				const n = Number(parts[1] || 20);
				const tail = safeRead(GLOBAL_LOG).split("\n").filter((l) => l.startsWith("|")).slice(-n).join("\n");
				ctx.ui.notify(tail || "（暂无拦截记录）", "info");
				return;
			}
			ctx.ui.notify(summary, "info");
		},
	});

	pi.on("session_shutdown", (_event, ctx) => {
		if (ctx.mode === "tui") {
			try {
				ctx.ui.setStatus("sec-enforce", undefined);
			} catch {
				/* ignore */
			}
		}
		sessions.delete(sessionKey(ctx));
	});
}

function countBlock(st: SessionState, decision: Decision): void {
	st.totalBlocks++;
	st.blocks.set(decision.rule, (st.blocks.get(decision.rule) ?? 0) + 1);
}

function notify(ctx: ExtensionContext, message: string): void {
	if (!ctx.hasUI) return;
	try {
		ctx.ui.notify(message, "warning");
	} catch {
		/* ignore */
	}
}

const RULES_TABLE = `# dsh-sec-enforce 拦截规则表（Pi port）

| 档 | 触发条件（决定性特征） | 判定 | 指路 |
|---|---|---|---|
| killSwitch | 标记文件 ${KILL_MARKER()} 存在（或 PI_SEC_ENFORCE_KILL_FILE） | 拦全部工具（跨模式） | rm 该文件 / sec_enforce_status action=clear / /sec-enforce clear |
| writeBoundary | write/edit 目标解析后不在 ${'${workspace}'}（含 allowDirs 与本件状态目录）内 | block | 改写工作区内路径，或加 allowDirs |
| taskBriefGate | 仅 redteam 模式：写 task-briefs/*.md 且正文无「依据：/锚点：」行 | block | 补「依据：…」锚点行 |
| reportGate | 写 <workspace>/reports/**：需 gate-log.md 有 "<mode>/<gate> \\| pass" 行（pentest P3 / code-audit A3 / binary-analysis B2 / attack-defense report / av-evasion V4 / incident-response I5 / cloud-security C7 / ctf-solver flag）；redteam 与 asset-mapping 无门→专用文案；再查 operation-state.json 未收口准则/意图 | block | 先过对应门（stage_gate 或手工追加 pass 行） |
| dangerousOps | rm 根级(/ ~ $HOME)、Windows 删除族（Remove-Item -Recurse/rd /s/del /s 指盘根）、format/mkfs、DROP TABLE·DATABASE、TRUNCATE TABLE、shutdown/reboot/systemctl stop·restart·disable、service stop·restart、kill -9 1、curl/wget POST 到 pay·refund·withdraw·order·recharge·transfer 路径或带 out_trade_no·trade_no·order_id 参数 | block（不可逆，禁止自动执行） | 列清单→用户批准→逐项；或按文案降级替代 |
| askGate | useradd/usermod/userdel/adduser/deluser、命令位 passwd/chpasswd、SQL GRANT·REVOKE·CREATE/DROP/ALTER USER、iptables -F/--flush、nft add·delete·flush、ufw 开关、--flood/slowloris/synflood | 有 UI → 确认框（批准即执行，拒绝/超时拒）；无 UI → block | 批准，或改只读方案 |
| rateDiscipline | nmap 全端口（-p- / -p1-65535）无 --max-rate/--min-rate/-T0..3；masscan --rate>1000；ffuf -u 无 -rate | block | 按文案加速率参数或降级 --top-ports 100 |
| constraintGate | operation-state.json 中 kind=deny 且带 keywords 的条目命中 bash 命令 / fetch URL 子串（大小写不敏感） | block | 与用户确认后修订约束台账 |

生效前提（Pi 侧模式探测，替代 dsh preset）：PI_SEC_ENFORCE=on / config.mode 显式 / 工作区存在安全工件
（gate-log.md、task-ledger.md、attack-paths.csv、sinks.csv、scan-reconcile.csv、creds-cloud.txt、evidence-index.md、ioc.txt）/
系统提示含 AGENTS.security.md 正文 / 会话实际调用 redteam-model 的 *-playbook 技能。全部不命中 = 零介入。
留痕：${GLOBAL_LOG}（工作区副本 <workspace>/enforce-log.md）。`;
