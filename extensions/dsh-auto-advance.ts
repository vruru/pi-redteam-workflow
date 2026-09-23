/**
 * dsh-auto-advance → Pi extension
 *
 * Source: ~/.pi/agent/redteam-model/plugins/dsh-auto-advance/lib/index.js
 * Contract: ~/.pi/agent/extensions/redteam/PORT-CONVENTIONS.md
 *
 * After a subagent-style execution tool returns, this extension reads the
 * dsh-stage-gate operation ledger. It asks the model to close the matching
 * open intent and, only when all guards pass, requests one follow-up turn.
 * It never performs the next action itself.
 *
 * Pi port notes:
 * - operation-state.json and the stage-gate state-index.json are consumed as
 *   read-only contracts; this extension owns no parallel intent ledger.
 * - Pi has no DSH agent preset. Existing ledgers supply `mode`; a no-ledger
 *   kickoff reminder needs explicit PI_AUTO_ADVANCE_MODE/config.mode opt-in,
 *   so ordinary sessions remain silent.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

const NAME = "dsh-auto-advance";
const STATE_FILE = "operation-state.json";
const STATE_DIR = path.join(process.env.HOME || os.homedir(), ".pi", "redteam", NAME);
const CONFIG_FILE = path.join(STATE_DIR, "config.json");
const STAGE_GATE_INDEX_FILE = path.join(process.env.HOME || os.homedir(), ".pi", "redteam", "dsh-stage-gate", "state-index.json");

/** Exact defaults from source Config in plugins/dsh-auto-advance/lib/index.js. */
export const DEFAULT_ENABLE = true;
export const DEFAULT_MAX_AUTO_TURNS = 5;
export const DEFAULT_COOLDOWN_MS = 30_000;
export const DEFAULT_KICKOFF = true;

export const MODE_IDS = [
	"pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion",
	"incident-response", "cloud-security", "ctf-solver", "asset-mapping",
] as const;
export type ModeId = (typeof MODE_IDS)[number];

type Intent = { id: string; summary?: string; status?: string };
type OperationState = { mode?: string; criteria?: unknown[]; intents?: Intent[] };
type Ledger = { total: number; openIds: string[]; summaries: string[] };
type Config = { enable: boolean; maxAutoTurns: number; cooldownMs: number; kickoff: boolean; mode?: ModeId };
type CompletedExecution = { toolName: string; argsRaw: string };
type SessionState = {
	usedTurns: number;
	lastNudgeAt: number;
	started: Map<string, string>;
	completed: CompletedExecution[];
	nudgedDirections: Set<string>;
	kickoffDone: boolean;
	lastInputWasHuman: boolean;
};

export const MODE_VOICE: Record<ModeId, { done: string; next: string }> = {
	pentest: { done: "漏洞发现或验证证据（finding id 或证据落盘路径）", next: "下一攻击面或入口方向" },
	"code-audit": { done: "finding（附 sink 指位与复现链，双链命中对账）", next: "下一模块或 sink 面" },
	"binary-analysis": { done: "能力结论或 IOC 假设（同步假设台账）", next: "下一假设或分析视角" },
	"attack-defense": { done: "阶段战果（op-traces 或 gate 产物指位）", next: "下一阶段动作或战果扩大方向" },
	"av-evasion": { done: "判定结果（过检或被检出，附判定环境）", next: "下一配对实验" },
	"incident-response": { done: "证据指位与时间线位置", next: "下一排查项" },
	"cloud-security": { done: "战果与攻击路径四要素位置", next: "下一身份或资源路径" },
	"ctf-solver": { done: "flag 与解题路径", next: "下一题或下一模块" },
	"asset-mapping": { done: "测绘阶段产物（runs/ 落盘指位或 Excel 表）", next: "下一管线阶段或补充情报源" },
};

function isMode(value: unknown): value is ModeId {
	return typeof value === "string" && (MODE_IDS as readonly string[]).includes(value);
}

function positiveInteger(value: unknown, fallback: number): number {
	const n = typeof value === "number" ? value : Number(value);
	return Number.isInteger(n) && n >= 0 ? n : fallback;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
	if (typeof value === "boolean") return value;
	if (value === "true" || value === "1") return true;
	if (value === "false" || value === "0") return false;
	return fallback;
}

/** Source config defaults plus optional Pi-local config/environment overrides. */
export function readConfig(env: NodeJS.ProcessEnv = process.env): Config {
	let stored: Record<string, unknown> = {};
	try {
		const parsed = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) stored = parsed as Record<string, unknown>;
	} catch {
		// Missing/malformed optional configuration must not affect a session.
	}
	const rawMode = env.PI_AUTO_ADVANCE_MODE ?? stored.mode;
	return {
		enable: booleanValue(env.PI_AUTO_ADVANCE_ENABLE ?? stored.enable, DEFAULT_ENABLE),
		maxAutoTurns: positiveInteger(env.PI_AUTO_ADVANCE_MAX_AUTO_TURNS ?? stored.maxAutoTurns, DEFAULT_MAX_AUTO_TURNS),
		cooldownMs: positiveInteger(env.PI_AUTO_ADVANCE_COOLDOWN_MS ?? stored.cooldownMs, DEFAULT_COOLDOWN_MS),
		kickoff: booleanValue(env.PI_AUTO_ADVANCE_KICKOFF ?? stored.kickoff, DEFAULT_KICKOFF),
		...(isMode(rawMode) ? { mode: rawMode } : {}),
	};
}

/** Source behavior: every tool whose name starts with `subagent` is an execution body. */
export function isAdvanceTool(toolName: unknown): boolean {
	return /^subagent/.test(String(toolName ?? ""));
}

/** Reads canonical dsh-stage-gate operation-state.json, never writes it. */
export function readOperationState(workspace: string): OperationState | null {
	try {
		const parsed = JSON.parse(fs.readFileSync(path.join(workspace, STATE_FILE), "utf8"));
		return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as OperationState) : null;
	} catch {
		return null;
	}
}

/** Source behavior: no file/no intents is not a ledger; only open intentions participate. */
export function readOpenIntents(workspace: string): Ledger | null {
	const state = readOperationState(workspace);
	if (!state || !Array.isArray(state.intents)) return null;
	const intents = state.intents.filter((intent): intent is Intent => Boolean(intent && typeof intent === "object" && typeof intent.id === "string"));
	const open = intents.filter((intent) => intent.status === "open");
	return {
		total: intents.length,
		openIds: open.map((intent) => intent.id),
		summaries: open.map((intent) => `${intent.id}:${String(intent.summary ?? "").slice(0, 60)}`),
	};
}

/** Matches i1...i999 in a subagent prompt and retains currently open ids only. */
export function intentHintOf(argsRaw: unknown, ledger: Ledger | null): string[] {
	const ids = new Set<string>();
	for (const match of String(argsRaw ?? "").matchAll(/\bi([0-9]{1,3})\b/g)) ids.add(`i${Number(match[1])}`);
	return [...ids].filter((id) => ledger?.openIds.includes(id)).slice(0, 5);
}

function directionKey(hint: string[], ledger: Ledger): string {
	return hint.length > 0 ? `hint:${[...hint].sort().join(",")}` : `open:${[...ledger.openIds].sort().join(",")}`;
}

export function kickoffText(mode: ModeId): string {
	return `[auto-advance] 开工提醒（${mode}）：深度任务先做开工三登记——① operation_goal（目标+可判定准则）→ ② operation_constraints（用户口头约束 deny/allow 结构化）→ ③ operation_scope（范围分母，报告门对账依据）。登记后对账/推进/门禁体系激活；快任务/问答可忽略（不登记零干扰，出口有兜底）。`;
}

export function decideAdvance(input: {
	toolName: string;
	ledger: Ledger | null;
	usedTurns: number;
	maxAutoTurns: number;
	cooldownMs: number;
	lastNudgeAt: number;
	now: number;
	hint?: string[];
	alreadyNudged?: Set<string>;
	voice?: { done?: string; next?: string };
}): { nudge: false; reason: string } | { nudge: true; text: string; direction: string } {
	if (!isAdvanceTool(input.toolName)) return { nudge: false, reason: "tool" };
	if (input.ledger === null || input.ledger.openIds.length === 0) return { nudge: false, reason: "no-open-intents" };
	if (input.usedTurns >= input.maxAutoTurns) return { nudge: false, reason: "turn-cap" };
	if (input.now - input.lastNudgeAt < input.cooldownMs) return { nudge: false, reason: "cooldown" };
	const hint = input.hint ?? [];
	const direction = directionKey(hint, input.ledger);
	if (input.alreadyNudged?.has(direction)) return { nudge: false, reason: "direction-already-nudged" };
	const openList = input.ledger.summaries.slice(0, 5).map((summary) => summary.split(":")[0]).join(",");
	const more = input.ledger.openIds.length > 5 ? " 等" : "";
	const hintLine = hint.length > 0 ? `本次执行疑似对应 ${hint.join(", ")}（以派单 prompt 提及为准）。` : "";
	const voice = input.voice ?? {};
	return {
		nudge: true,
		direction,
		text: `[auto-advance] 执行体已返回（${input.toolName}）。台账：意图 ${input.ledger.openIds.length}/${input.ledger.total} 未收口（${openList}${more}）——${hintLine}先 operation_progress 收口本次执行对应的意图（intent_done 附产出指位${voice.done ? `：${voice.done}` : ""} / intent_blocked 附原因），再依锚 operation_intent 派下一步${voice.next ? `（${voice.next}）` : ""}或收工（无下一步即静默收尾，不硬造方向）。本条为自动推进（第 ${input.usedTurns + 1}/${input.maxAutoTurns} 轮），人工输入随时接管。`,
	};
}

/** Same session key scheme as dsh-stage-gate's state-index contract. */
function sessionKeyOf(ctx: ExtensionContext): string {
	try {
		const id = ctx.sessionManager.getSessionId();
		if (id) return String(id);
		const file = ctx.sessionManager.getSessionFile();
		if (file) return path.basename(file);
	} catch {
		// Tests/non-session invocations use the cwd fallback below.
	}
	return `cwd:${path.resolve(ctx.cwd)}`;
}

/** Exact-session index use only; never fallback to index.last (unrelated sessions stay silent). */
function indexedWorkspace(ctx: ExtensionContext): string | undefined {
	try {
		const index = JSON.parse(fs.readFileSync(STAGE_GATE_INDEX_FILE, "utf8")) as { sessions?: Record<string, { workspace?: unknown }> };
		const workspace = index.sessions?.[sessionKeyOf(ctx)]?.workspace;
		return typeof workspace === "string" && workspace ? workspace : undefined;
	} catch {
		return undefined;
	}
}

function workspaceOf(ctx: ExtensionContext): string {
	const cwd = path.resolve(ctx.cwd);
	if (readOperationState(cwd) !== null) return cwd;
	const indexed = indexedWorkspace(ctx);
	return indexed && readOperationState(indexed) !== null ? path.resolve(indexed) : cwd;
}

function getSessionState(states: Map<string, SessionState>, key: string): SessionState {
	let state = states.get(key);
	if (!state) {
		state = { usedTurns: 0, lastNudgeAt: 0, started: new Map(), completed: [], nudgedDirections: new Set(), kickoffDone: false, lastInputWasHuman: false };
		states.set(key, state);
	}
	return state;
}

export default function (pi: ExtensionAPI) {
	const states = new Map<string, SessionState>();

	pi.on("session_start", async (_event, ctx) => {
		getSessionState(states, sessionKeyOf(ctx));
	});

	/** Pi interactive/RPC input is the source equivalent of a human user message. */
	pi.on("input", (event, ctx) => {
		const state = getSessionState(states, sessionKeyOf(ctx));
		state.lastInputWasHuman = event.source === "interactive" || event.source === "rpc";
		if (state.lastInputWasHuman) state.usedTurns = 0;
	});

	/** One-time kickoff is explicit mode opt-in only; unarmed sessions stay silent. */
	pi.on("before_agent_start", (_event, ctx) => {
		const cfg = readConfig();
		const state = getSessionState(states, sessionKeyOf(ctx));
		const workspace = workspaceOf(ctx);
		if (!cfg.enable || !cfg.kickoff || !cfg.mode || state.kickoffDone || !state.lastInputWasHuman || readOperationState(workspace) !== null) return;
		state.kickoffDone = true;
		return { message: { customType: "auto-advance-kickoff", content: kickoffText(cfg.mode), display: false, details: { mode: cfg.mode } } };
	});

	pi.on("tool_execution_start", (event, ctx) => {
		if (!isAdvanceTool(event.toolName)) return;
		const state = getSessionState(states, sessionKeyOf(ctx));
		state.started.set(event.toolCallId, JSON.stringify(event.args ?? {}));
	});

	pi.on("tool_execution_end", (event, ctx) => {
		if (!isAdvanceTool(event.toolName)) return;
		const state = getSessionState(states, sessionKeyOf(ctx));
		const argsRaw = state.started.get(event.toolCallId) ?? "{}";
		state.started.delete(event.toolCallId);
		// Failed executors also need an intent_blocked closure, matching source behavior.
		state.completed.push({ toolName: event.toolName, argsRaw });
	});

	pi.on("agent_before_settle", (event, ctx) => {
		const cfg = readConfig();
		const state = getSessionState(states, sessionKeyOf(ctx));
		const completed = state.completed.splice(0);

		// Hard guard: no candidate, no resumable boundary, no valid ledger, or any
		// failed decision MUST NOT request `continue`.
		if (!cfg.enable || !event.context.canContinue || completed.length === 0) return;
		const workspace = workspaceOf(ctx);
		const operation = readOperationState(workspace);
		if (!operation || !isMode(operation.mode)) return;
		const ledger = readOpenIntents(workspace);
		const candidate = completed[completed.length - 1];
		const hint = intentHintOf(candidate.argsRaw, ledger);
		const decision = decideAdvance({
			toolName: candidate.toolName,
			ledger,
			usedTurns: state.usedTurns,
			maxAutoTurns: cfg.maxAutoTurns,
			cooldownMs: cfg.cooldownMs,
			lastNudgeAt: state.lastNudgeAt,
			now: Date.now(),
			hint,
			alreadyNudged: state.nudgedDirections,
			voice: MODE_VOICE[operation.mode],
		});
		if (!decision.nudge) return;

		state.usedTurns += 1;
		state.lastNudgeAt = Date.now();
		state.nudgedDirections.add(decision.direction);
		pi.appendEntry("auto-advance", { workspace, mode: operation.mode, direction: decision.direction, usedTurns: state.usedTurns, at: new Date().toISOString() });
		return {
			entries: [{ type: "custom_message", customType: "auto-advance", content: decision.text, display: false, details: { workspace, mode: operation.mode, direction: decision.direction } }],
			continue: true,
		};
	});

	pi.on("session_shutdown", async (_event, ctx) => {
		states.delete(sessionKeyOf(ctx));
	});
}
