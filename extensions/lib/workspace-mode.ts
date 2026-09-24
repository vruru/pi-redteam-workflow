import * as fs from "node:fs";
import * as path from "node:path";
// Read-only workspace classification; no tool hooks, blocking, or approval logic.

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

function readStateAt(file: string): { mode?: string } | null {
	try {
		return JSON.parse(fs.readFileSync(file, "utf8")) as { mode?: string };
	} catch {
		return null;
	}
}

function safeRead(file: string): string {
	try {
		return fs.readFileSync(file, "utf8");
	} catch {
		return "";
	}
}

