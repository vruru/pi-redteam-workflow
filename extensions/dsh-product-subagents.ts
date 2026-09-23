/**
 * dsh-product-subagents (Pi port): nested-model cross-harness review with optional CLI backends.
 * Source: ~/.pi/agent/redteam-model/plugins/dsh-product-subagents/lib/index.js (read-only).
 *
 * Default review path: Pi's own model via ctx.modelRegistry.streamSimple().
 * Optional enhancement paths: local Claude CLI / Codex CLI (detected, not required).
 */
import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import * as path from "node:path";
import { Type } from "typebox";
import { uuidv7 } from "@earendil-works/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { Model, Usage } from "@earendil-works/pi-ai";

const PLUGIN = "dsh-product-subagents";
const STATE_DIR = path.join(homedir(), ".pi", "redteam", PLUGIN);
const TRACE_DIR = path.join(STATE_DIR, "traces");
const RUN_LOG = path.join(STATE_DIR, "run-log.md");
const CONFIG_FILE = path.join(STATE_DIR, "config.json");
const DEFAULT_TIMEOUT_MS = 600_000;
const KILL_GRACE_MS = 5_000;
const OUTPUT_CAP = 64 * 1024;
const STREAM_CAP = 2 * 1024 * 1024;

const REVIEW_SYSTEM_PROMPT = [
	"你是一名独立复核员，必须对给定的结论（claim）进行逐项审查。",
	"",
	"纪律：",
	"1. 仅根据下方提供的原始证据得出结论；无证据的附和不可采信。",
	"2. 对 claim 中的每一项断言，给出「确认 / 挑战 / 证据不足无法判断」之一。",
	"3. 每条结论必须引用具体证据：文件路径、行号、命令输出片段、代码位置或证据文本。",
	"4. 不得仅因为任务要求你附和就附和；证据不足时必须明确说明缺什么。",
	"5. 先给出总体结论，再给出逐项审查表。",
].join("\n");

const discipline = "复核纪律：无证据的附和不可采信；结论必须逐项引用原始证据、命令输出或文件位置。";

type Backend = "claude" | "codex";
type StopReason = "completed" | "aborted" | "error";
type ToolArgs = { prompt: string; cwd?: string; timeoutMs?: number; sandbox?: string; streamTrace?: boolean };
type Outcome = { backend: Backend; stopReason: StopReason; text: string; stderr: string; unavailable: boolean; command: string[]; traceFile?: string };
type CliConfig = { bin: string; timeoutMs: number; extraArgs: string[]; env: Record<string, string>; sandbox?: string; streamTrace?: boolean };
type Config = { claudeCode: CliConfig; codex: CliConfig };

const DEFAULT_CONFIG: Config = {
	claudeCode: { bin: "claude", timeoutMs: DEFAULT_TIMEOUT_MS, extraArgs: [], env: {}, streamTrace: true },
	codex: { bin: "codex", timeoutMs: DEFAULT_TIMEOUT_MS, extraArgs: [], env: {}, sandbox: "workspace-write" },
};

function ensureState(): void { fs.mkdirSync(TRACE_DIR, { recursive: true }); }
function loadConfig(): Config {
	try {
		const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8")) as Partial<Config>;
		const safe = (value: Partial<CliConfig> | undefined, base: CliConfig): CliConfig => ({
			bin: typeof value?.bin === "string" && value.bin ? value.bin : base.bin,
			timeoutMs: typeof value?.timeoutMs === "number" && value.timeoutMs > 0 ? value.timeoutMs : base.timeoutMs,
			extraArgs: Array.isArray(value?.extraArgs) ? value.extraArgs.filter((item): item is string => typeof item === "string") : base.extraArgs,
			env: value?.env && typeof value.env === "object" ? Object.fromEntries(Object.entries(value.env).filter(([, item]) => typeof item === "string")) : base.env,
			sandbox: typeof value?.sandbox === "string" ? value.sandbox : base.sandbox,
			streamTrace: typeof value?.streamTrace === "boolean" ? value.streamTrace : base.streamTrace,
		});
		return { claudeCode: safe(raw.claudeCode, DEFAULT_CONFIG.claudeCode), codex: safe(raw.codex, DEFAULT_CONFIG.codex) };
	} catch { return DEFAULT_CONFIG; }
}
function tail(value: string, limit = 2_000): string { return value.length > limit ? `…${value.slice(-limit)}` : value; }
function modelText(value: string): string {
	return value.length > OUTPUT_CAP ? `${value.slice(0, OUTPUT_CAP)}\n…[输出截断；完整过程流见留痕路径]` : value;
}
function checkCliAvailable(bin: string): boolean {
	try {
		const result = spawnSync(bin, ["--version"], { shell: false, encoding: "utf-8", timeout: 5_000, stdio: ["ignore", "pipe", "pipe"] });
		return result.status === 0 || result.status === null;
	} catch {
		return false;
	}
}

/** Original order: claude -p --output-format stream-json --verbose + extras. */
export function buildClaudeArgs(extraArgs: string[] = [], streamTrace = true): string[] {
	return streamTrace ? ["-p", "--output-format", "stream-json", "--verbose", ...extraArgs] : ["-p", ...extraArgs];
}
/** Original order: codex exec --skip-git-repo-check --sandbox mode -C cwd -o file + extras. */
export function buildCodexArgs(sandbox: string, cwd: string, outFile: string, extraArgs: string[] = []): string[] {
	return ["exec", "--skip-git-repo-check", "--sandbox", sandbox, "-C", cwd, "-o", outFile, ...extraArgs];
}
/** Original stream-json parser: the final result event wins; bad NDJSON is ignored. */
export function finalTextFromStreamJson(stream: string): string | null {
	for (const line of stream.split("\n").reverse()) {
		try {
			const event = JSON.parse(line.trim());
			if (event?.type === "result" && typeof event.result === "string") return event.result;
		} catch { /* malformed lines fall back to stdout */ }
	}
	return null;
}

function appendLog(outcome: Outcome, cwd: string, fallback?: string): void {
	try {
		ensureState();
		const lines = [
			`## ${new Date().toISOString()} · ${outcome.backend} · ${outcome.stopReason}`,
			`- cwd: ${cwd}`,
			`- command: ${[outcome.backend, ...outcome.command].map((part) => JSON.stringify(part)).join(" ")}`,
			`- unavailable: ${outcome.unavailable}`,
			outcome.traceFile ? `- trace: ${outcome.traceFile}` : "- trace: Codex process flow remains in ~/.codex/sessions/; this ledger records outcome only.",
			fallback ? `- fallback: ${fallback}` : "",
			outcome.stderr ? `- stderr tail:\n\n\`\`\`\n${tail(outcome.stderr)}\n\`\`\`` : "",
			"",
		].filter(Boolean);
		fs.appendFileSync(RUN_LOG, `${lines.join("\n")}\n`, "utf8");
	} catch { /* audit output is best effort and never masks the actual result */ }
}

async function runCli(options: {
	backend: Backend; bin: string; args: string[]; input: string; cwd: string; timeoutMs: number; env: NodeJS.ProcessEnv; signal?: AbortSignal;
	collectFile?: string; traceFile?: string; parseStreamJson?: boolean;
}): Promise<Outcome> {
	const { backend, bin, args, input, cwd, timeoutMs, env, signal, collectFile, traceFile, parseStreamJson } = options;
	let child: ReturnType<typeof spawn>;
	try { child = spawn(bin, args, { cwd, env, stdio: ["pipe", "pipe", "pipe"] }); }
	catch (error) {
		return { backend, stopReason: "error", text: `无法启动 ${bin}：${error instanceof Error ? error.message : String(error)}`, stderr: "", unavailable: true, command: args };
	}
	return new Promise((resolve) => {
		let stdout = "", stderr = "", killedBy = "", settled = false;
		let killer: NodeJS.Timeout | undefined;
		let trace: fs.WriteStream | undefined;
		if (traceFile) {
			try { fs.mkdirSync(path.dirname(traceFile), { recursive: true }); trace = fs.createWriteStream(traceFile, { flags: "a" }); trace.on("error", () => undefined); }
			catch { trace = undefined; }
		}
		const finish = async (stopReason: StopReason, unavailable = false): Promise<void> => {
			if (settled) return;
			settled = true;
			if (timer) clearTimeout(timer);
			if (killer) clearTimeout(killer);
			signal?.removeEventListener("abort", onAbort);
			await new Promise<void>((done) => { if (!trace) return done(); const stream = trace; trace = undefined; stream.end(() => done()); });
			let finalText = stdout.trim();
			if (stopReason === "completed" && collectFile) {
				try { finalText = (await readFile(collectFile, "utf8")).trim() || finalText; } catch { /* original stdout fallback */ }
			}
			if (stopReason === "completed" && parseStreamJson && traceFile) {
				try { finalText = finalTextFromStreamJson(await readFile(traceFile, "utf8")) ?? finalText; } catch { /* original stdout fallback */ }
			}
			if (stopReason === "aborted") finalText = "跨 harness 复核已因调用取消而终止。";
			if (stopReason === "error" && killedBy) finalText = `子代理进程被终止（${killedBy}）${stderr ? `\nstderr 尾部：\n${tail(stderr)}` : ""}`;
			if (stopReason === "error" && !finalText) finalText = stderr ? `CLI 失败：\n${tail(stderr)}` : "CLI 无输出地失败。";
			if (stopReason === "completed" && !finalText) finalText = "(CLI 无输出)";
			resolve({ backend, stopReason, text: modelText(finalText), stderr, unavailable, command: args, traceFile });
		};
		const stop = (reason: string): void => {
			if (settled || killedBy) return;
			killedBy = reason;
			child.kill("SIGTERM");
			killer = setTimeout(() => child.kill("SIGKILL"), KILL_GRACE_MS);
		};
		const onAbort = (): void => stop("abort");
		const timer = setTimeout(() => stop("timeout"), timeoutMs);
		signal?.addEventListener("abort", onAbort, { once: true });
		child.stdout.on("data", (chunk: Buffer) => { const text = chunk.toString(); if (stdout.length < STREAM_CAP) stdout += text; trace?.write(text); });
		child.stderr.on("data", (chunk: Buffer) => { if (stderr.length < STREAM_CAP) stderr += chunk.toString(); });
		child.on("error", (error: NodeJS.ErrnoException) => { void finish("error", error.code === "ENOENT"); });
		child.on("close", (code) => { if (killedBy === "abort") void finish("aborted"); else if (killedBy) void finish("error"); else void finish(code === 0 ? "completed" : "error"); });
		child.stdin.on("error", () => undefined);
		child.stdin.end(input);
	});
}

function cwdOf(ctx: ExtensionContext, requested?: string): string {
	const cwd = path.resolve(ctx.cwd, requested || ".");
	if (!fs.existsSync(cwd) || !fs.statSync(cwd).isDirectory()) throw new Error(`cwd 不存在或不是目录：${cwd}`);
	return cwd;
}

async function runBackend(backend: Backend, args: ToolArgs, ctx: ExtensionContext, cwd: string): Promise<Outcome> {
	const config = loadConfig();
	const provider = backend === "claude" ? config.claudeCode : config.codex;
	const timeoutMs = args.timeoutMs ?? provider.timeoutMs;
	const env = { ...process.env, ...provider.env };
	if (backend === "claude") {
		const streamTrace = args.streamTrace ?? provider.streamTrace ?? true;
		const traceFile = streamTrace ? path.join(TRACE_DIR, `${new Date().toISOString().replace(/[:.]/g, "-")}-${randomUUID().slice(0, 8)}.ndjson`) : undefined;
		return runCli({ backend, bin: provider.bin, args: buildClaudeArgs(provider.extraArgs, streamTrace), input: args.prompt, cwd, timeoutMs, env, signal: ctx.signal, traceFile, parseStreamJson: streamTrace });
	}
	const dir = await mkdtemp(path.join(tmpdir(), "pi-product-subagents-codex-"));
	try {
		return await runCli({ backend, bin: provider.bin, args: buildCodexArgs(args.sandbox ?? provider.sandbox ?? "workspace-write", cwd, path.join(dir, "last-message.txt"), provider.extraArgs), input: args.prompt, cwd, timeoutMs, env, signal: ctx.signal, collectFile: path.join(dir, "last-message.txt") });
	} finally { await rm(dir, { recursive: true, force: true }); }
}

function cliResult(outcome: Outcome, requested: Backend, fallback?: string) {
	const backend = outcome.stopReason === "completed"
		? `实际复核后端：${outcome.backend} CLI${outcome.backend !== requested ? `（${requested} CLI 不可用后自动降级）` : ""}；这是可选的跨 harness 复核通道。`
		: `实际执行后端：${outcome.backend} CLI（${outcome.stopReason}）。`;
	return {
		content: [{ type: "text" as const, text: [backend, outcome.text, outcome.traceFile ? `过程流留痕：${outcome.traceFile}` : `运行留痕：${RUN_LOG}`, fallback, discipline].filter(Boolean).join("\n\n") }],
		details: { requestedBackend: requested, actualBackend: outcome.backend, stopReason: outcome.stopReason, unavailable: outcome.unavailable, traceFile: outcome.traceFile, runLog: RUN_LOG, fallback },
	};
}

function parseModelSpec(spec: string): { provider: string; modelId: string } | undefined {
	const parts = spec.split("/");
	if (parts.length !== 2 || !parts[0] || !parts[1]) return undefined;
	return { provider: parts[0], modelId: parts[1] };
}

function selectReviewModel(ctx: ExtensionContext, explicit?: string): { model: Model<any>; source: string } | undefined {
	if (explicit) {
		const parsed = parseModelSpec(explicit);
		if (!parsed) return undefined;
		const found = ctx.modelRegistry.find(parsed.provider, parsed.modelId);
		if (!found) return undefined;
		return { model: found, source: `explicit:${explicit}` };
	}
	if (ctx.model) return { model: ctx.model, source: "session-current" };
	const available = ctx.modelRegistry.getAvailable();
	if (available.length === 0) return undefined;
	return { model: available[0], source: "first-available" };
}

function buildHomologyNote(reviewModel: Model<any>, sessionModel: Model<any> | undefined): string {
	if (!sessionModel) return "无法获取主会话模型，同源性按「同源互证」保守记账。";
	const sameProvider = reviewModel.provider === sessionModel.provider;
	const sameModel = sameProvider && reviewModel.id === sessionModel.id;
	if (sameModel) return `复核模型 ${reviewModel.provider}/${reviewModel.id} 与主会话模型相同，属于同源互证，而非异构双签。`;
	if (sameProvider) return `复核模型 ${reviewModel.provider}/${reviewModel.id} 与主会话模型 ${sessionModel.provider}/${sessionModel.id} 同 provider 但不同 model，属于同族异构互证。`;
	return `复核模型 ${reviewModel.provider}/${reviewModel.id} 与主会话模型 ${sessionModel.provider}/${sessionModel.id} 不同 provider，属异构双签。`;
}

function usageSummary(usage: Usage | undefined): string {
	if (!usage) return "用量：未返回";
	return `用量：input=${usage.input} output=${usage.output} cacheRead=${usage.cacheRead} cacheWrite=${usage.cacheWrite} totalTokens=${usage.totalTokens} cost=$${usage.cost.total.toFixed(6)}`;
}

async function runPiReview(args: {
	evidence: string;
	claim: string;
	model?: string;
	timeoutMs?: number;
}, ctx: ExtensionContext) {
	ensureState();
	const selected = selectReviewModel(ctx, args.model);
	if (!selected) {
		throw new Error(args.model ? `显式指定的复核模型 ${args.model} 不可用或格式错误（应为 provider/model-id）。` : "当前会话没有可用模型，无法执行复核。");
	}
	const { model, source } = selected;
	if (!ctx.modelRegistry.hasConfiguredAuth(model)) {
		throw new Error(`复核模型 ${model.provider}/${model.id} 未配置认证。`);
	}

	const messages = [
		{
			role: "user" as const,
			content: [{ type: "text" as const, text: `<evidence>\n${args.evidence}\n</evidence>\n\n<claim>\n${args.claim}\n</claim>\n\n请按系统提示的复核纪律审查上述 claim，仅依据 evidence 中的内容得出结论。` }],
			timestamp: Date.now(),
		},
	];

	const timeoutMs = args.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const stream = ctx.modelRegistry.streamSimple(
		model,
		{ systemPrompt: REVIEW_SYSTEM_PROMPT, messages },
		{ signal: ctx.signal, timeoutMs, sessionId: uuidv7(), cacheRetention: "none" },
	);
	const response = await stream.result();

	const text = response.content
		.filter((c): c is { type: "text"; text: string } => c.type === "text")
		.map((c) => c.text)
		.join("\n");

	const homology = buildHomologyNote(model, ctx.model);
	const usage = response.usage;
	const summary = [
		`复核模型：${model.provider}/${model.id}（来源：${source}）`,
		`模型返回状态：${response.stopReason}${response.errorMessage ? ` / ${response.errorMessage}` : ""}`,
		homology,
		usageSummary(usage),
		"",
		"--- 复核结论 ---",
		modelText(text),
	].join("\n");

	return {
		content: [{ type: "text" as const, text: summary }],
		details: {
			model: `${model.provider}/${model.id}`,
			modelSource: source,
			sessionModel: ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : undefined,
			homology,
			stopReason: response.stopReason,
			errorMessage: response.errorMessage,
			usage,
		},
	};
}

export default function (pi: ExtensionAPI): void {
	const cliParameters = Type.Object({
		prompt: Type.String({ description: "交给独立 CLI 复核员的完整任务与证据锚点；不能只要求附和。" }),
		cwd: Type.Optional(Type.String({ description: "CLI 工作目录；默认当前 Pi 工作区。" })),
		timeoutMs: Type.Optional(Type.Integer({ minimum: 1000, maximum: DEFAULT_TIMEOUT_MS, description: "毫秒，默认 600000；超时 SIGTERM，5 秒后 SIGKILL。" })),
		sandbox: Type.Optional(Type.String({ description: "仅 Codex：原 --sandbox 参数，默认 workspace-write。" })),
		streamTrace: Type.Optional(Type.Boolean({ description: "仅 Claude：默认 true，stream-json 过程流写入状态目录。" })),
	});

	const reviewParameters = Type.Object({
		evidence: Type.String({ description: "原始证据文本、命令输出、代码片段或证据锚点（文件路径等）。" }),
		claim: Type.String({ description: "需要复核的结论/主张。" }),
		model: Type.Optional(Type.String({ description: "可选：显式指定复核模型，格式 provider/model-id。默认使用当前会话模型。" })),
		timeoutMs: Type.Optional(Type.Integer({ minimum: 1000, maximum: DEFAULT_TIMEOUT_MS, description: "毫秒，默认 600000。" })),
	});

	const executeCli = async (requested: Backend, args: ToolArgs, ctx: ExtensionContext) => {
		ensureState();
		const cwd = cwdOf(ctx, args.cwd);
		const config = loadConfig();
		const bin = requested === "claude" ? config.claudeCode.bin : config.codex.bin;
		if (!checkCliAvailable(bin)) {
			appendLog({ backend: requested, stopReason: "error", text: `本机未检测到 ${bin} CLI。`, stderr: "", unavailable: true, command: [] }, cwd);
			return cliResult({ backend: requested, stopReason: "error", text: `本机未检测到 ${bin} CLI，可选增强通道不可用。`, stderr: "", unavailable: true, command: [] }, requested, `默认复核通道请使用 subagent_review（Pi 自身模型）。`);
		}
		let outcome = await runBackend(requested, args, ctx, cwd);
		appendLog(outcome, cwd);
		if (outcome.stopReason === "aborted") return cliResult(outcome, requested);
		if (requested === "claude" && outcome.unavailable) {
			const first = outcome;
			if (checkCliAvailable(config.codex.bin)) {
				outcome = await runBackend("codex", args, ctx, cwd);
				appendLog(outcome, cwd, "claude unavailable → codex");
				if (outcome.stopReason === "completed") return cliResult(outcome, requested, "自动降级已执行：Claude CLI 不可用，Codex CLI 已完成复核。");
			}
			if (outcome.unavailable) return cliResult(outcome, requested, `本机 Codex CLI 亦不可用；默认复核通道请使用 subagent_review（Pi 自身模型）。（Claude 失败：${tail(first.text, 300)}）`);
			return cliResult(outcome, requested, "Claude CLI 不可用，已自动尝试 Codex CLI；Codex 本次未完成，未静默回退。");
		}
		if (requested === "codex" && outcome.unavailable) return cliResult(outcome, requested, "默认复核通道请使用 subagent_review（Pi 自身模型）。");
		return cliResult(outcome, requested);
	};

	pi.registerTool({
		name: "subagent_review", label: "Pi 模型独立复核（默认通道）",
		description: "使用 Pi 自身模型对给定的证据和结论进行独立复核。默认使用当前会话模型，可显式指定其他模型。无证据不得附和。",
		promptSnippet: "Pi 模型独立复核（默认通道）：传入 evidence 与 claim，返回逐项审查结论。",
		executionMode: "sequential", parameters: reviewParameters,
		async execute(_id, args, _signal, _onUpdate, ctx) { return runPiReview(args, ctx); },
	});

	pi.registerTool({
		name: "subagent_claude_code", label: "Claude CLI cross-harness review（可选增强）",
		description: "User-triggered local Claude CLI cross-harness review. If the CLI is unavailable, returns unavailable status quietly without failing; does not block the default Pi-model review path.",
		promptSnippet: "可选增强：本机 Claude CLI 跨 harness 复核；缺失时返回不可用，不阻塞默认 Pi 模型复核。", executionMode: "sequential", parameters: cliParameters,
		async execute(_id, args, _signal, _onUpdate, ctx) { return executeCli("claude", args, ctx); },
	});

	pi.registerTool({
		name: "subagent_codex", label: "Codex CLI cross-harness review（可选增强）",
		description: "User-triggered local Codex CLI cross-harness review. If the CLI is unavailable, returns unavailable status quietly without failing; does not block the default Pi-model review path.",
		promptSnippet: "可选增强：本机 Codex CLI 跨 harness 复核；缺失时返回不可用，不阻塞默认 Pi 模型复核。", executionMode: "sequential", parameters: cliParameters,
		async execute(_id, args, _signal, _onUpdate, ctx) { return executeCli("codex", args, ctx); },
	});

	pi.on("session_start", async () => { ensureState(); });
}
