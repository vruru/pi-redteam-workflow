/** dsh-semgrep-audit (Pi port): local, offline Semgrep plus scan-reconcile dual-write. */
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

const BIN_HINT = "未检测到 semgrep——三级兜底：①使用已连接 MCP 的 semgrep 引擎（只替引擎不替本规则集，命中面收窄须如实标注）；②征得用户批准后由用户在会话外执行 `pip install semgrep`；③按审计规则降级章采用通用模式/脚本。本工具绝不自动安装。";
const PREVIEW_CHARS = 6000;
const TIMEOUT_MS = 600000;
const RULE_ROOT_CANDIDATES = [
	path.join(os.homedir(), ".pi", "agent", "redteam-model", "modes", "code-audit", "refs"),
	path.join(os.homedir(), ".pi", "agent", "redteam-model", "deploy", "modes", "code-audit", "refs"),
	path.join(os.homedir(), ".pi", "redteam", "code-audit", "refs"),
];

/** Original three offline layers; current bundle locates OSS below standards/. */
export const RULE_LAYERS = {
	"builtin-java": ["lang/java-audit/semgrep-rules"],
	"builtin-php": ["lang/php-audit/semgrep-rules"],
	oss: ["semgrep-oss", "standards/semgrep-oss"],
} as const;
type Layer = keyof typeof RULE_LAYERS | "custom";
type Hit = { rule: string; file: string; line: number; severity: string; message: string };
type ProcessResult = { status: number | null; stdout: string; stderr: string; error?: Error };

function toolResult(text: string, details: Record<string, unknown>) { return { content: [{ type: "text" as const, text }], details }; }

/** Probe only: no brew/pip/npm installer exists in this extension. */
export function hasBin(bin: string): boolean {
	const result = process.platform === "win32" ? spawnSync("where", [bin]) : spawnSync("/usr/bin/which", [bin]);
	return result.status === 0;
}

function runProcess(bin: string, args: string[]): Promise<ProcessResult> {
	return new Promise((resolve) => {
		let child;
		try { child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"], windowsHide: true }); }
		catch (cause) { resolve({ status: null, stdout: "", stderr: "", error: cause instanceof Error ? cause : new Error(String(cause)) }); return; }
		let stdout = "", stderr = "", done = false;
		const finish = (result: ProcessResult) => { if (!done) { done = true; clearTimeout(timer); resolve(result); } };
		child.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
		child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
		child.on("error", (error) => finish({ status: null, stdout, stderr, error }));
		child.on("close", (status) => finish({ status, stdout, stderr }));
		const timer = setTimeout(() => { try { child.kill("SIGTERM"); } catch { /* already exited */ } finish({ status: null, stdout, stderr, error: new Error(`semgrep 执行超时 ${TIMEOUT_MS / 1000}s`) }); }, TIMEOUT_MS);
	});
}

/** Bundled → deployed → Pi-state candidate order; a candidate must contain one shipped rule layer. */
export function findRefsDir(candidates = RULE_ROOT_CANDIDATES): string {
	for (const root of candidates) {
		try {
			if (!fs.statSync(root).isDirectory()) continue;
			if (Object.values(RULE_LAYERS).some((paths) => paths.some((relative) => fs.existsSync(path.join(root, relative))))) return root;
		} catch { /* try the next distribution layout */ }
	}
	return "";
}

function builtinConfig(layer: Exclude<Layer, "custom">, refsDir: string): string {
	const found = RULE_LAYERS[layer].map((relative) => path.join(refsDir, relative)).find((candidate) => fs.existsSync(candidate));
	if (!found) throw new Error(`规则层 ${layer} 在 refs/ 中缺失`);
	return found;
}

export function buildArgs(layer: Layer, target: string, rulesPath: string | undefined, refsDir: string) {
	const configs = layer === "custom" ? [String(rulesPath ?? "")] : [builtinConfig(layer, refsDir)];
	return { args: ["scan", "--json", "--metrics=off", "--quiet", ...configs.flatMap((config) => ["--config", config]), target], configs };
}

export function parseSemgrepJson(raw: string, cap = 200) {
	let document: { results?: unknown; errors?: unknown };
	try { document = JSON.parse(raw) as { results?: unknown; errors?: unknown }; } catch { return { ok: false as const, error: "semgrep 输出非 JSON（引擎异常或执行失败）" }; }
	const results = Array.isArray(document.results) ? document.results as Array<Record<string, any>> : [];
	const bySeverity: Record<string, number> = {}, byRule: Record<string, number> = {}, seen = new Set<string>(), hits: Hit[] = [];
	for (const result of results) {
		const rule = String(result.check_id ?? "?"), severity = String(result.extra?.severity ?? "?"), file = String(result.path ?? "?"), line = Number(result.start?.line ?? 0);
		bySeverity[severity] = (bySeverity[severity] ?? 0) + 1; byRule[rule] = (byRule[rule] ?? 0) + 1;
		const key = `${rule}|${file}|${line}`;
		if (!seen.has(key)) { seen.add(key); if (hits.length < cap) hits.push({ rule, file, line, severity, message: String(result.extra?.message ?? "").slice(0, 160) }); }
	}
	const top = Object.entries(byRule).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([rule, count]) => `${rule}×${count}`).join("、");
	return { ok: true as const, total: results.length, unique: seen.size, bySeverity, hits, errors: Array.isArray(document.errors) ? document.errors.length : 0,
		summaryText: `semgrep 命中 ${results.length} 条（去重 ${seen.size}${hits.length < seen.size ? `，展示前 ${hits.length}` : ""}）${top ? `；Top 规则：${top}` : ""}——已写对账待处置（命中≠漏洞；复核并补真实调用链后才可登记为 scan-confirmed 或 scan-false-positive）` };
}

function contained(parent: string, candidate: string): boolean { return candidate === parent || candidate.startsWith(parent + path.sep); }
/** Realpath both operands: an external source target or a target symlink leaving workspace is rejected. */
export function resolveScope(workspaceInput: string, targetInput: string): { workspace: string; target: string } | { error: string } {
	let workspace: string, target: string;
	try { workspace = fs.realpathSync(path.resolve(workspaceInput)); target = fs.realpathSync(path.resolve(workspace, targetInput)); }
	catch { return { error: "任务工作区或扫描目标不存在；target 必须显式给出且位于现有工作区内" }; }
	if (!fs.statSync(workspace).isDirectory()) return { error: `工作区不是目录：${workspace}` };
	if (!contained(workspace, target)) return { error: `扫描目标越出工作区或经 symlink 指向工作区外：${target}` };
	try { assertNoExternalSymlink(workspace, target); } catch (cause) { return { error: cause instanceof Error ? cause.message : String(cause) }; }
	return { workspace, target };
}

/** Do not hand Semgrep an in-workspace tree that contains a symlink escaping it. */
function assertNoExternalSymlink(workspace: string, root: string): void {
	const stat = fs.statSync(root);
	if (!stat.isDirectory()) return;
	const pending = [root];
	while (pending.length) {
		const directory = pending.pop()!;
		for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
			const candidate = path.join(directory, entry.name);
			if (entry.isSymbolicLink()) {
				const resolved = fs.realpathSync(candidate);
				if (!contained(workspace, resolved)) throw new Error(`扫描范围含指向工作区外的 symlink：${candidate} → ${resolved}`);
			} else if (entry.isDirectory()) pending.push(candidate);
		}
	}
}

function nextEvidenceId(workspace: string): string {
	let highest = 0;
	try { for (const match of fs.readFileSync(path.join(workspace, "evidence-index.md"), "utf8").matchAll(/\| E(\d+) \|/g)) highest = Math.max(highest, Number(match[1])); } catch { /* first evidence row */ }
	return `E${highest + 1}`;
}
function appendEvidence(workspace: string, evidenceId: string, command: string, output: string): void {
	const file = path.join(workspace, "evidence-index.md");
	let text: string;
	try { text = fs.readFileSync(file, "utf8"); } catch { text = "# 证据索引\n\n| 编号 | 时间 | 证据 | 产生方式 | 交接/消费 |\n|---|---|---|---|---|\n"; }
	fs.writeFileSync(file, `${text}| ${evidenceId} | ${new Date().toISOString()} | ${output} | ${command} | 扫描产物 |\n`);
}
/** Source format preserved: human markdown + machine CSV, both initially marked pending. */
export function appendReconcile(workspace: string, rows: Hit[]): number {
	if (!rows.length) return 0;
	const mdFile = path.join(workspace, "scan-reconcile.md"), csvFile = path.join(workspace, "scan-reconcile.csv");
	let markdown: string, csv: string;
	try { markdown = fs.readFileSync(mdFile, "utf8"); } catch { markdown = "# 扫描命中对账（scan-reconcile）\n\n| 来源 | 命中 | 终态 |\n|---|---|---|\n"; }
	fs.writeFileSync(mdFile, `${markdown}${rows.map((row) => `| semgrep | ${row.rule} @ ${row.file}:${row.line} [${row.severity}] | 待处置（命中≠漏洞，须复核+补真实调用链） |`).join("\n")}\n`);
	try { csv = fs.readFileSync(csvFile, "utf8"); } catch { csv = "scanner,rule,file,line,verdict,reason\n"; }
	const escape = (value: unknown) => /[",\n]/.test(String(value)) ? `"${String(value).replace(/"/g, '""')}"` : String(value);
	fs.writeFileSync(csvFile, `${csv}${rows.map((row) => ["semgrep", row.rule, row.file, row.line, "待处置", "命中≠漏洞，复核后经 register 升格"].map(escape).join(",")).join("\n")}\n`);
	return rows.length;
}
function preview(raw: string) { return raw.length <= PREVIEW_CHARS ? { text: raw, truncated: false } : { text: `${raw.slice(0, PREVIEW_CHARS)}\n\n[输出已截断：显示前 ${PREVIEW_CHARS}/${raw.length} 字符；完整 JSON 见产物路径]`, truncated: true }; }

export async function runSemgrep(input: { workspace: string; target: string; layer: Layer; rulesPath?: string }): Promise<Record<string, unknown>> {
	if (!hasBin("semgrep")) return { ok: false, stage: "missing-bin", error: BIN_HINT };
	const scoped = resolveScope(input.workspace, input.target);
	if ("error" in scoped) return { ok: false, stage: "scope", error: scoped.error };
	if (input.layer === "custom" && !input.rulesPath) return { ok: false, stage: "rules", error: "layer=custom 时 rules_path 必填（规则文件或目录）" };
	if (input.layer === "custom" && !fs.existsSync(String(input.rulesPath))) return { ok: false, stage: "rules", error: `规则路径不存在：${input.rulesPath}` };
	const refsDir = input.layer === "custom" ? "" : findRefsDir();
	if (input.layer !== "custom" && !refsDir) return { ok: false, stage: "rules", error: "未定位到预设离线规则集（builtin-java / builtin-php / oss）——请检查 Pi 预设资源，或改用 layer=custom + rules_path。" };
	let built: { args: string[]; configs: string[] };
	try { built = buildArgs(input.layer, scoped.target, input.rulesPath, refsDir); } catch (cause) { return { ok: false, stage: "rules", error: cause instanceof Error ? cause.message : String(cause) }; }
	const outputDir = path.join(scoped.workspace, "artifacts", "scans"); fs.mkdirSync(outputDir, { recursive: true });
	const output = path.join(outputDir, `semgrep-${new Date().toISOString().replace(/[-:T.]/g, "").slice(0, 14)}.json`);
	const processResult = await runProcess("semgrep", built.args), command = `semgrep ${built.args.join(" ")}`;
	if (processResult.error) return { ok: false, stage: "exec", error: processResult.error.message, command };
	const parsed = parseSemgrepJson(processResult.stdout);
	if (!parsed.ok) return { ok: false, stage: "parse", error: `${parsed.error}${processResult.stderr.trim() ? `；stderr：${processResult.stderr.trim().slice(0, 1000)}` : ""}`, command };
	fs.writeFileSync(output, processResult.stdout);
	const file = path.relative(scoped.workspace, output), evidenceId = nextEvidenceId(scoped.workspace);
	appendEvidence(scoped.workspace, evidenceId, `${command}（规则层 ${input.layer}：${built.configs.join("、")}）`, file);
	const rendered = preview(processResult.stdout);
	return { ok: processResult.status === 0, stage: processResult.status === 0 ? "executed" : "nonzero-exit", exit: processResult.status, layer: input.layer, configs: built.configs, evidenceId, file, total: parsed.total, unique: parsed.unique, bySeverity: parsed.bySeverity, reconciled: appendReconcile(scoped.workspace, parsed.hits), summaryText: parsed.summaryText, preview: rendered.text, truncated: rendered.truncated, stderr: processResult.stderr.slice(0, 2000), command };
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "semgrep_scan", label: "semgrep_scan",
		description: "Local semgrep scan with offline preset rules (builtin-java, builtin-php, oss, or explicit custom rules). target is explicit and must resolve inside the task workspace. Uses --metrics=off. Full JSON persists only under <workspace>/artifacts/scans/, while model output is capped with its full path. Hits dual-write scan-reconcile.md/.csv as 待处置: hit ≠ vulnerability; review plus a real call chain are required before scan-confirmed or scan-false-positive promotion. Never auto-installs semgrep.",
		parameters: Type.Object({
			workspace: Type.Optional(Type.String({ description: "Task workspace root (defaults to current workspace); all artifacts and reconciliation files remain here" })),
			target: Type.String({ description: "Explicit file/directory scan scope; must resolve inside workspace (external symlink targets are refused)" }),
			layer: Type.Union([Type.Literal("builtin-java"), Type.Literal("builtin-php"), Type.Literal("oss"), Type.Literal("custom")], { description: "builtin-java=Java custom rules; builtin-php=PHP rules; oss=shipped OSS rules; custom=rules_path" }),
			rules_path: Type.Optional(Type.String({ description: "Required when layer=custom: existing rules file or directory" })),
		}), executionMode: "sequential",
		promptSnippet: "semgrep_scan：本机 semgrep + 预设离线规则；--metrics=off；命中双写 scan-reconcile.md/.csv（命中≠漏洞）。",
		promptGuidelines: ["semgrep 缺失时仅返回三级兜底建议，绝不自动安装；target 必须显式给定且位于任务工作区内。"],
		async execute(_id: string, raw: unknown, _signal: AbortSignal | undefined, _onUpdate: unknown, ctx: ExtensionContext) {
			const params = raw as { workspace?: string; target: string; layer: Layer; rules_path?: string };
			const result = await runSemgrep({ workspace: params.workspace ?? ctx.cwd, target: params.target, layer: params.layer, rulesPath: params.rules_path });
			if (!result.ok) return toolResult(`semgrep 拒绝/失败：${result.error}`, result);
			return toolResult(`semgrep：${result.summaryText}（证据 ${result.evidenceId}；全文 ${result.file}${result.truncated ? "；返回体已截断" : ""}）${result.preview ? `\n${result.preview}` : ""}`, result);
		},
	});
}
