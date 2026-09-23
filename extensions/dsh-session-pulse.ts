/**
 * dsh-session-pulse → Pi extension
 *
 * 源：~/.pi/agent/redteam-model/plugins/dsh-session-pulse/lib/index.js + pulse.js（只读）
 * 约定：~/.pi/agent/extensions/redteam/PORT-CONVENTIONS.md
 *
 * Web 面板降级为「工具 + 命令 + 状态行/文本汇总 + markdown 台账」：
 *   - session_pulse 工具：返回当前会话状态摘要（模式判定、任务进度、子代理目录分组）。
 *   - /session-pulse 命令：将会话状态写成 markdown 文件。
 *   - 子代理目录通过拦截 tool_execution_start/end 事件维护轻量运行图；
 *     任务进度优先读 operation-state.json（dsh-stage-gate 的准则/待办），其次扫描会话中的 todo 工具结果。
 *   - 原 web 通道、抽屉、提示词栏等 UI 行为全部移除。
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

//#region constants

const PLUGIN = "dsh-session-pulse";
const DATA_DIR = path.join(os.homedir(), ".pi", "redteam", PLUGIN);

const PULSE_MODES = [
	"redteam",
	"pentest",
	"code-audit",
	"binary-analysis",
	"attack-defense",
	"av-evasion",
	"incident-response",
	"cloud-security",
	"ctf-solver",
	"asset-mapping",
] as const;

const MODE_LABELS: Record<string, string> = {
	redteam: "安全研究员",
	pentest: "渗透测试",
	"code-audit": "代码审计",
	"binary-analysis": "二进制分析",
	"attack-defense": "攻防评估",
	"av-evasion": "免杀对抗",
	"incident-response": "应急溯源",
	"cloud-security": "云安全攻防",
	"ctf-solver": "CTF 解题",
	"asset-mapping": "资产测绘",
};

const SUBAGENT_TOOLS = new Set([
	"subagent",
	"subagent_spawn",
	"subagent_resume",
	"delegate_task",
]);

interface TrackedSubagent {
	toolCallId: string;
	name: string;
	running: boolean;
	startedAt: string;
	endedAt?: string;
	error?: boolean;
}

//#endregion

//#region helpers

function ensureDir(dir: string) {
	if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function sessionMode(ctx: ExtensionContext | undefined): { id: string; mode: string } | undefined {
	const id = ctx?.sessionManager?.getSessionId?.();
	if (!id) return undefined;
	const header = ctx?.sessionManager?.getHeader?.();
	const preset = header?.agentPreset || "redteam";
	return { id: String(id), mode: PULSE_MODES.includes(preset as (typeof PULSE_MODES)[number]) ? preset : "redteam" };
}

function result<T>(text: string, details: T) {
	return { content: [{ type: "text" as const, text }], details };
}

interface OperationState {
	mode?: string;
	goal?: string;
	criteria?: { id: string; status: "open" | "met" | "failed" }[];
	pending?: string[];
	scope?: { id: string; label: string }[];
	tested?: { id: string; evidence: string }[];
	intents?: { id: string; status: string }[];
}

function readOperationState(cwd: string): OperationState | undefined {
	const file = path.join(cwd, "operation-state.json");
	try {
		return JSON.parse(fs.readFileSync(file, "utf8")) as OperationState;
	} catch {
		return undefined;
	}
}

function progressFromState(st: OperationState | undefined) {
	if (!st) return undefined;
	const criteria = st.criteria ?? [];
	const total = criteria.length;
	const done = criteria.filter((c) => c.status === "met" || c.status === "failed").length;
	const met = criteria.filter((c) => c.status === "met").length;
	const failed = criteria.filter((c) => c.status === "failed").length;
	const pending = st.pending?.length ?? 0;
	const scopeTotal = st.scope?.length ?? 0;
	const scopeTested = st.tested?.length ?? 0;
	const openIntents = (st.intents ?? []).filter((i) => i.status === "open").length;
	return {
		total,
		done,
		met,
		failed,
		pct: total ? Math.round((done / total) * 100) : 0,
		pending,
		scopeTotal,
		scopeTested,
		openIntents,
	};
}

function scanTodoProgress(ctx: ExtensionContext | undefined) {
	if (!ctx?.sessionManager?.getBranch) return null;
	try {
		let total = 0;
		let done = 0;
		for (const entry of ctx.sessionManager.getBranch()) {
			if (entry.type !== "message") continue;
			const msg = entry.message;
			if (msg.role !== "toolResult" || msg.toolName !== "todo") continue;
			const details = msg.details as { todos?: { done?: boolean }[] } | undefined;
			if (details?.todos) {
				total = Math.max(total, details.todos.length);
				done = Math.max(done, details.todos.filter((t) => t.done).length);
			}
		}
		return total > 0 ? { total, done, pct: Math.round((done / total) * 100) } : null;
	} catch {
		return null;
	}
}

function buildPulse(
	ctx: ExtensionContext | undefined,
	catalog: TrackedSubagent[],
): {
	sessionId?: string;
	mode?: string;
	modeLabel?: string;
	progress?: ReturnType<typeof progressFromState>;
	todoProgress?: { total: number; done: number; pct: number } | null;
	subagents: { running: TrackedSubagent[]; finished: TrackedSubagent[] };
} {
	const session = sessionMode(ctx);
	const cwd = ctx?.cwd ?? process.cwd();
	const st = readOperationState(cwd);
	const progress = progressFromState(st);
	const todoProgress = scanTodoProgress(ctx);
	const running = catalog.filter((s) => s.running);
	const finished = catalog.filter((s) => !s.running);
	return {
		sessionId: session?.id,
		mode: session?.mode,
		modeLabel: session?.mode ? MODE_LABELS[session.mode] : undefined,
		progress,
		todoProgress,
		subagents: { running, finished },
	};
}

function renderPulse(pulse: ReturnType<typeof buildPulse>) {
	const lines: string[] = [];
	lines.push(`会话：${pulse.sessionId ?? "未知"}`);
	lines.push(`模式：${pulse.modeLabel ?? pulse.mode ?? "未知"}`);
	if (pulse.progress) {
		const p = pulse.progress;
		lines.push(
			`目标进度：${p.done}/${p.total}（met ${p.met} / failed ${p.failed}） ${p.pct}% | 待办 ${p.pending} 项 | 覆盖 ${p.scopeTested}/${p.scopeTotal} | 未收口意图 ${p.openIntents}`,
		);
	}
	if (pulse.todoProgress) {
		lines.push(`任务清单：${pulse.todoProgress.done}/${pulse.todoProgress.total} ${pulse.todoProgress.pct}%`);
	}
	lines.push(`子代理：运行中 ${pulse.subagents.running.length} / 已结束 ${pulse.subagents.finished.length}`);
	if (pulse.subagents.running.length) {
		for (const s of pulse.subagents.running) {
			lines.push(`  ▶ ${s.name}（${s.toolCallId}，起 ${s.startedAt}）`);
		}
	}
	if (pulse.subagents.finished.length) {
		for (const s of pulse.subagents.finished) {
			lines.push(`  ✓ ${s.name}（${s.toolCallId}${s.error ? "，异常" : ""}，止 ${s.endedAt ?? "-"}）`);
		}
	}
	return lines.join("\n");
}

function toMarkdown(pulse: ReturnType<typeof buildPulse>) {
	const lines = ["# 会话状态面板", ""];
	lines.push(`- 会话：${pulse.sessionId ?? "未知"}`);
	lines.push(`- 模式：${pulse.modeLabel ?? pulse.mode ?? "未知"}`);
	if (pulse.progress) {
		const p = pulse.progress;
		lines.push(`- 目标进度：${p.done}/${p.total}（met ${p.met} / failed ${p.failed}） ${p.pct}%`);
		lines.push(`- 待办：${p.pending} 项`);
		lines.push(`- 覆盖：${p.scopeTested}/${p.scopeTotal}`);
		lines.push(`- 未收口意图：${p.openIntents}`);
	}
	if (pulse.todoProgress) {
		lines.push(`- 任务清单：${pulse.todoProgress.done}/${pulse.todoProgress.total} ${pulse.todoProgress.pct}%`);
	}
	lines.push("");
	lines.push("## 子代理目录", "");
	lines.push(`运行中：${pulse.subagents.running.length}，已结束：${pulse.subagents.finished.length}`, "");
	if (pulse.subagents.running.length) {
		lines.push("### 运行中", "");
		for (const s of pulse.subagents.running) {
			lines.push(`- **${s.name}** \`${s.toolCallId}\` 起 ${s.startedAt}`);
		}
		lines.push("");
	}
	if (pulse.subagents.finished.length) {
		lines.push("### 已结束", "");
		for (const s of pulse.subagents.finished) {
			lines.push(`- **${s.name}** \`${s.toolCallId}\` 起 ${s.startedAt} 止 ${s.endedAt ?? "-"}${s.error ? "（异常）" : ""}`);
		}
		lines.push("");
	}
	return lines.join("\n");
}

//#endregion

//#region extension

export default function (pi: ExtensionAPI) {
	const catalog = new Map<string, TrackedSubagent>();

	pi.on("tool_execution_start", async (event) => {
		if (SUBAGENT_TOOLS.has(event.toolName)) {
			const name = (event.args?.name as string) || (event.args?.agent as string) || event.toolName;
			catalog.set(event.toolCallId, {
				toolCallId: event.toolCallId,
				name,
				running: true,
				startedAt: new Date().toISOString(),
			});
		}
	});

	pi.on("tool_execution_end", async (event) => {
		const tracked = catalog.get(event.toolCallId);
		if (tracked) {
			tracked.running = false;
			tracked.endedAt = new Date().toISOString();
			tracked.error = event.isError;
		}
	});

	pi.registerTool({
		name: "session_pulse",
		label: "session pulse",
		description: "取得当前会话作战状态摘要：模式、目标进度（operation-state.json 准则/待办）、任务清单进度、子代理目录分组。",
		promptSnippet: "取得会话状态进度与子代理目录",
		executionMode: "parallel",
		parameters: Type.Object({
			includeHistory: Type.Optional(Type.Boolean({ description: "是否包含已结束子代理详情" })),
		}),
		async execute(_id, _p, _signal, _onUpdate, ctx) {
			const pulse = buildPulse(ctx, [...catalog.values()]);
			return result(renderPulse(pulse), pulse);
		},
	});

	pi.registerCommand("session-pulse", {
		description: "输出当前会话状态 markdown（模式/进度/子代理目录）",
		handler: async (_args, ctx) => {
			const pulse = buildPulse(ctx, [...catalog.values()]);
			const md = toMarkdown(pulse);
			ensureDir(DATA_DIR);
			const file = path.join(DATA_DIR, `pulse-${pulse.sessionId ?? "unknown"}-${Date.now()}.md`);
			let written = file;
			try {
				fs.writeFileSync(file, md);
			} catch (e) {
				written = `(写盘失败：${(e as Error).message})`;
			}
			ctx.ui.notify(`session-pulse 已输出：${written}`, "info");
			if (ctx.mode === "tui") ctx.ui.setWidget("session-pulse", md.split("\n").slice(0, 40));
		},
	});
}

//#endregion
