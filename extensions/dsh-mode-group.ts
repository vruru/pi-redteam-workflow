/**
 * dsh-mode-group -> Pi extension
 *
 * Source: ~/.pi/agent/redteam-model/plugins/dsh-mode-group/lib/client.js + index.js (read-only)
 * Conventions: ~/.pi/agent/extensions/redteam/PORT-CONVENTIONS.md
 *
 * Web panel (new-session mode selector) downgraded to "tools + commands + text summary + markdown list":
 *   - /modes command: list ten security modes, mapped playbook skill names, one-line descriptions, write markdown.
 *   - mode_group tool: model queries supported mode mapping or recommends a mode/playbook for a task.
 *   - Data comes from ~/.pi/agent/redteam-model/modes/<mode>/preset.yml and skills/ directories.
 *   - Original UI chip/hover/submenu behaviors removed.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

//#region constants

const PLUGIN = "dsh-mode-group";
const DATA_DIR = path.join(os.homedir(), ".pi", "redteam", PLUGIN);
const MODES_ROOT = path.join(os.homedir(), ".pi", "agent", "redteam-model", "modes");

const PRO_MODE_ORDER = [
	"attack-defense",
	"pentest",
	"code-audit",
	"av-evasion",
	"incident-response",
	"binary-analysis",
	"cloud-security",
	"ctf-solver",
	"asset-mapping",
] as const;

interface ModeInfo {
	id: string;
	name: string;
	description: string;
	skills: string[];
}

//#endregion

//#region helpers

function ensureDir(dir: string) {
	if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function parsePreset(file: string): { name: string; description: string } | undefined {
	try {
		const text = fs.readFileSync(file, "utf8");
		const name = text.match(/^name:\s*(.+)$/m)?.[1]?.trim();
		const description = text.match(/^description:\s*(.+)$/m)?.[1]?.trim();
		if (name) return { name, description: description ?? "" };
	} catch {
		/* ignore */
	}
	return undefined;
}

function listSkills(modeDir: string): string[] {
	const skillsDir = path.join(modeDir, "skills");
	try {
		return fs.readdirSync(skillsDir, { withFileTypes: true })
			.filter((d) => d.isDirectory())
			.map((d) => d.name);
	} catch {
		return [];
	}
}

function loadModes(): ModeInfo[] {
	const out: ModeInfo[] = [];
	for (const id of ["redteam", ...PRO_MODE_ORDER]) {
		const dir = path.join(MODES_ROOT, id);
		const preset = parsePreset(path.join(dir, "preset.yml"));
		const skills = listSkills(dir);
		out.push({
			id,
			name: preset?.name ?? id,
			description: preset?.description ?? "",
			skills,
		});
	}
	return out;
}

function result<T>(text: string, details: T) {
	return { content: [{ type: "text" as const, text }], details };
}

function renderModes(modes: ModeInfo[], compact = false) {
	const lines: string[] = [];
	lines.push("十个安全模式入口：");
	lines.push("");
	for (const m of modes) {
		const pro = PRO_MODE_ORDER.includes(m.id as (typeof PRO_MODE_ORDER)[number]);
		const badge = m.id === "redteam" ? "[研究员/总入口]" : pro ? "[专业模式]" : "";
		lines.push(`${badge} ${m.name}（${m.id}）`);
		if (!compact) {
			lines.push(`  描述：${m.description}`);
			if (m.skills.length) lines.push(`  playbook 技能：${m.skills.join(", ")}`);
		}
	}
	return lines.join("\n");
}

function toMarkdown(modes: ModeInfo[]) {
	const lines = ["# 安全模式入口", ""];
	lines.push("| 模式 ID | 名称 | 类型 | 描述 | Playbook 技能 |");
	lines.push("|---|---|---|---|---|");
	for (const m of modes) {
		const pro = PRO_MODE_ORDER.includes(m.id as (typeof PRO_MODE_ORDER)[number]);
		const type = m.id === "redteam" ? "研究员/总入口" : pro ? "专业安全模式" : "";
		lines.push(`| ${m.id} | ${m.name} | ${type} | ${m.description} | ${m.skills.join(", ")} |`);
	}
	lines.push("");
	lines.push("## 如何进入", "");
	lines.push("- 在 Pi 中新建会话后，使用 `/scoped-models` 或模型指令选择对应模式；");
	lines.push("- 本机移植件按模式预设加载对应 playbook 技能与门禁 schema；");
	lines.push("- 研究员模式（redteam）为通用总入口，适合多任务协同与轻量安全任务。");
	lines.push("");
	return lines.join("\n");
}

function recommendMode(modes: ModeInfo[], query: string): ModeInfo | undefined {
	const q = query.toLowerCase();
	for (const m of modes) {
		if (m.id === q) return m;
	}
	for (const m of modes) {
		if (m.name.toLowerCase().includes(q)) return m;
	}
	for (const m of modes) {
		if (m.description.toLowerCase().includes(q)) return m;
	}
	return undefined;
}

//#endregion

//#region extension

export default function (pi: ExtensionAPI) {
	const modes = loadModes();

	pi.registerTool({
		name: "mode_group",
		label: "mode group",
		description: "查询十个安全模式入口清单，或根据任务描述推荐应进入的模式与对应 playbook 技能。",
		promptSnippet: "查询安全模式入口与 playbook 映射",
		executionMode: "parallel",
		parameters: Type.Object({
			action: Type.Optional(Type.Union([Type.Literal("list"), Type.Literal("recommend")], { description: "list=列全部模式（默认），recommend=按 query 推荐" })),
			query: Type.Optional(Type.String({ description: "任务描述或模式 ID（recommend 用）" })),
		}),
		async execute(_id, p, _signal, _onUpdate, _ctx) {
			if (p.action === "recommend" && p.query) {
				const m = recommendMode(modes, p.query);
				if (!m) return result(`未找到与「${p.query}」匹配的模式`, { action: "recommend", query: p.query, matched: null });
				return result(
					`推荐模式：${m.name}（${m.id}）\n描述：${m.description}\nplaybook 技能：${m.skills.join(", ")}`,
					{ action: "recommend", query: p.query, matched: m },
				);
			}
			return result(renderModes(modes), { action: "list", modes });
		},
	});

	pi.registerCommand("modes", {
		description: "列出十个安全模式入口与对应 playbook 技能映射",
		handler: async (args, ctx) => {
			const compact = args.trim().includes("--compact") || args.trim().includes("-c");
			const md = toMarkdown(modes);
			const text = renderModes(modes, compact);
			ensureDir(DATA_DIR);
			const file = path.join(DATA_DIR, `modes-${Date.now()}.md`);
			let written = file;
			try {
				fs.writeFileSync(file, md);
			} catch (e) {
				written = `(写盘失败：${(e as Error).message})`;
			}
ctx.ui.notify(`modes 清单已输出：${written}`, "info");
if (ctx.mode === "tui") ctx.ui.setWidget("mode-group", text.split("\n").slice(0, 40));
else if (!ctx.hasUI) process.stdout.write(text + "\n"); // print/JSON 模式无 UI，直接回显表格
		},
	});
}

//#endregion
