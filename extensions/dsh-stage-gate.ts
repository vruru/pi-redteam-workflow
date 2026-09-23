/**
 * dsh-stage-gate → Pi extension
 *
 * 源：~/.pi/agent/redteam-model/plugins/dsh-stage-gate/lib/index.js（只读，v1.5.0）
 * 约定：~/.pi/agent/extensions/redteam/PORT-CONVENTIONS.md
 *
 * 九个安全预设「阶段门禁纪律」中的**结构检查**变成模型必须调用、不能自评的工具：
 *   stage_gate / gates_list —— 文件存在与非空、必需标记、表格行完整、产物哈希登记；
 *   operation_goal / operation_progress / operation_scope / operation_constraints /
 *   operation_intent —— 目标契约（可判定准则）、进度收口、覆盖度分母、约束台账、意图锚点，
 *   全部落 <workspace>/operation-state.json（中断可恢复；下游 sec-enforce 报告门读它）。
 *
 * 判定追加进 <workspace>/gate-log.md（审计 trail）。结构通过 ≠ 完整通过：
 * 语义门禁逐条列在返回体 manual 里，归复核员。
 *
 * Pi 侧差异（详见移植报告）：
 *  - DSH host 平面 ctx.tools.register → pi.registerTool（保留同名工具与参数语义）。
 *  - DSH 会话 preset → Pi 无 preset 概念：mode 由「显式参数 → operation-state.json 已记录
 *    mode」两级回退（拆分理论注入据此）。
 *  - 门禁**顺序**在 Pi 侧升级为硬性 reject（原实现只自动回写 done，不拦）：见 previousGateViolation。
 *  - 跨库锚点解析器（dsh-redteam-results / dsh-attack-atlas 在 ~/.dsh/）在 Pi 侧不可达，
 *    走原实现既有的格式校验降级路径（validateAnchor resolvers 缺省）。
 *  - 插件自身状态/日志目录：~/.pi/redteam/dsh-stage-gate/（约定第 4 条），不使用 ~/.dsh/。
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Dirent } from "node:fs";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { truncateHead, withFileMutationQueue } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

//#region types

type CheckKind = "file" | "markers" | "hexHash" | "table" | "provenance";

interface GateCheck {
	kind: CheckKind;
	/** workspace-relative path, or "$file" for the gate-scoped file argument */
	file?: string;
	dir?: string;
	markers?: string[];
	minRows?: number;
	minCells?: number;
}

interface Gate {
	title: string;
	requiresFile?: boolean;
	fileHint?: string;
	checks: GateCheck[];
	manual: string[];
}

type GatesSchema = Record<string, Record<string, Gate>>;

interface CheckResult {
	id: string;
	ok: boolean;
	detail: string;
	kind?: string;
	file?: string;
}

interface Verdict {
	mode: string;
	stage: string;
	title: string;
	pass: boolean;
	checks: CheckResult[];
	manual: string[];
	missing: string[];
	/** Pi 侧新增：本次判定发生时仍未判定的前序门（不拦，只surface） */
	pendingPrior?: string[];
}

export interface Criterion {
	id: string;
	text: string;
	status: "open" | "met" | "failed";
	evidence: string;
}
export interface ScopeItem {
	id: string;
	label: string;
}
export interface TestedItem {
	id: string;
	evidence: string;
	at?: string;
}
export interface IntentItem {
	id: string;
	summary: string;
	anchor: { kind: string; ref: string };
	status: "open" | "done" | "blocked" | "dropped";
	note?: string;
	created_at?: string;
	closed_at?: string;
}
export interface ConstraintItem {
	id: string;
	kind: "deny" | "allow";
	text: string;
	keywords: string[];
}
export interface GateRecord {
	pass: boolean;
	at: string;
	missing?: string[];
}
export interface OperationState {
	version: number;
	mode: string;
	goal: string;
	criteria: Criterion[];
	gates: Record<string, GateRecord>;
	pending: string[];
	created_at?: string;
	updated_at?: string;
	note?: string;
	scope?: ScopeItem[];
	tested?: TestedItem[];
	intents?: IntentItem[];
	constraints?: ConstraintItem[];
}

/** fs 注入面：生产用 node:fs，自测用内存假 fs。 */
type FsLike = Pick<typeof fs, "readFileSync" | "writeFileSync" | "readdirSync" | "mkdirSync" | "statSync">;

//#endregion

//#region gate schema（32 道门，逐字迁移自 plugins/dsh-stage-gate/lib/index.js 的 GATES）

/**
 * 检查类型（v1，仅结构）：
 *  - file        : 文件存在且非空
 *  - markers     : 文件含全部标记串
 *  - hexHash     : 文件含 64 位十六进制串（sha256）
 *  - table       : 文件含 >= minRows 行表格，每行 >= minCells 个非空单元格
 *  - provenance  : artifacts/ 下至少一个 <sub>/provenance.md 带 64 位哈希
 * 注意：对象键序即门禁判定顺序（av-evasion 的 V1→V3→V2→V4 是有意次序）。
 */
const GATES: GatesSchema = {
	pentest: {
		P1: {
			title: "资产与环境基线",
			checks: [
				{ kind: "file", file: "assets.md" },
				{ kind: "markers", file: "assets.md", markers: ["WAF", "速率"] },
				{ kind: "table", file: "assets.md", minRows: 2, minCells: 2 },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "markers", file: "evidence-index.md", markers: ["tool-plane", "MCP"] },
				{ kind: "table", file: "evidence-index.md", minRows: 1, minCells: 2 },
			],
			manual: [],
		},
		P2: {
			title: "finding 对照三件套 + 复核记录",
			requiresFile: true,
			fileHint: "该 finding 的六字段报告文件路径",
			checks: [{ kind: "markers", file: "$file", markers: ["基线", "差分", "marker", "复核"] }],
			manual: ["对照三件套的语义成立（差分真实翻转、marker 逐字回显）与复核员确认/双签记录由复核员判定"],
		},
		P3: {
			title: "覆盖度（资产×漏洞类全集）+ 复核汇总账",
			checks: [
				{ kind: "file", file: "coverage-matrix.md" },
				{ kind: "table", file: "coverage-matrix.md", minRows: 3, minCells: 3 },
				{ kind: "file", file: "review-log.md" },
				{ kind: "markers", file: "review-log.md", markers: ["复核"] },
			],
			manual: [
				"N-A 格理由是否成立由复核员抽查",
				"review-log 复核结论（确认/挑战）语义由复核员判定；跨 harness 双签（DSH+claude/codex 复核一致）才可在行内标「双签」",
			],
		},
	},
	"code-audit": {
		A1: {
			title: "前置识别 + 面映射",
			checks: [
				{ kind: "file", file: "surface-map.md" },
				{ kind: "markers", file: "surface-map.md", markers: ["入口", "sink", "深度"] },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "markers", file: "evidence-index.md", markers: ["tool-plane", "MCP"] },
			],
			manual: ["已知漏洞核对结论与深度分级合理性"],
		},
		A2: {
			title: "双链一致（审计工人链 vs 追踪员链）",
			requiresFile: true,
			fileHint: "该 finding 的调用链记录文件路径",
			checks: [{ kind: "markers", file: "$file", markers: ["entry", "sink"] }],
			manual: ["两条链语义一致由复核员判定；不一致退回重追或降疑似"],
		},
		A3: {
			title: "覆盖度（模块×sink 全集）+ 扫描命中对账",
			checks: [
				{ kind: "file", file: "audit-coverage-matrix.md" },
				{ kind: "table", file: "audit-coverage-matrix.md", minRows: 3, minCells: 3 },
				{ kind: "file", file: "scan-reconcile.md" },
				{ kind: "markers", file: "scan-reconcile.md", markers: ["确认", "误报"] },
			],
			manual: ["命中数量守恒（扫描器报告数=终态数）由复核员核对"],
		},
	},
	"binary-analysis": {
		B0: {
			title: "样本登记门",
			checks: [{ kind: "provenance", dir: "artifacts" }],
			manual: ["来源与日期的真实性"],
		},
		B1: {
			title: "还原完整性三验",
			requiresFile: true,
			fileHint: "该还原产物的验证记录文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["dex", "IAT", "可运行"] },
				{ kind: "hexHash", file: "$file" },
			],
			manual: ["三项验证的语义结论（通过/不通过）由复核员判定；不过=疑似"],
		},
		B2: {
			title: "分析维度覆盖 + 假设台账终态",
			checks: [
				{ kind: "file", file: "analysis-coverage.md" },
				{ kind: "table", file: "analysis-coverage.md", minRows: 3, minCells: 3 },
				{ kind: "file", file: "hypothesis-ledger.md" },
				{ kind: "markers", file: "hypothesis-ledger.md", markers: ["确认", "证伪"] },
			],
			manual: ["未决假设不得写成事实"],
		},
	},
	"attack-defense": {
		recon: {
			title: "阶段①侦察产物",
			checks: [
				{ kind: "file", file: "assets.md" },
				{ kind: "table", file: "assets.md", minRows: 2, minCells: 2 },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "markers", file: "evidence-index.md", markers: ["tool-plane", "MCP"] },
				{ kind: "table", file: "evidence-index.md", minRows: 1, minCells: 2 },
			],
			manual: [],
		},
		breach: {
			title: "阶段②突破产物（路径台账）",
			checks: [
				{ kind: "file", file: "paths-ledger.md" },
				{ kind: "markers", file: "paths-ledger.md", markers: ["candidate", "chosen"] },
				{ kind: "table", file: "paths-ledger.md", minRows: 1, minCells: 3 },
			],
			manual: ["已验证 finding 的证据由复核员 gate-pass 判定"],
		},
		lateral: {
			title: "阶段③横向（前置=已验证突破）",
			requiresFile: true,
			fileHint: "横向证据记录文件路径",
			checks: [{ kind: "markers", file: "$file", markers: ["授权"] }],
			manual: ["前置突破已验证、范围合规由复核员判定"],
		},
		persistence: {
			title: "阶段④持久化登记",
			checks: [
				{ kind: "file", file: "persistence-registry.md" },
				{ kind: "markers", file: "persistence-registry.md", markers: ["手动排除"] },
				{ kind: "table", file: "persistence-registry.md", minRows: 1, minCells: 4 },
			],
			manual: ["登记即满足；排除步骤可执行性由用户验收"],
		},
		report: {
			title: "阶段⑤报告完整性",
			requiresFile: true,
			fileHint: "总评估报告文件路径",
			checks: [
				{
					kind: "markers",
					file: "$file",
					markers: ["漏洞名称", "ATT&CK", "detection gap", "持久化清单", "路径台账", "阶段终态"],
				},
				{ kind: "file", file: "op-traces.md" },
				{ kind: "markers", file: "op-traces.md", markers: ["shell 地址", "ssh 密钥", "创建的用户"] },
				{ kind: "table", file: "op-traces.md", minRows: 1, minCells: 4 },
			],
			manual: [
				"每个 finding 带复核 gate-pass 签名由报告员保证",
				"操作痕迹台账须覆盖全部已登记 webshell/ssh 密钥/新建用户（无则填「无」行）",
			],
		},
	},
	"av-evasion": {
		V1: {
			title: "实验计划门（三声明）",
			checks: [
				{ kind: "file", file: "experiment-plan.md" },
				{ kind: "markers", file: "experiment-plan.md", markers: ["测试环境", "产物去向", "持久化预案"] },
			],
			manual: [
				"三声明语义成立由总控判定：测试环境为本地或任务授权目标；产物去向（实验室目录或任务工作区）如实；涉及持久化则预案与登记制（persistence-registry，含手动排除步骤）一致",
			],
		},
		V3: {
			title: "配对完整（技术↔检测双向镜像）",
			requiresFile: true,
			fileHint: "该轮实验报告文件路径",
			checks: [{ kind: "markers", file: "$file", markers: ["技术侧", "检测侧"] }],
			manual: ["镜像两侧语义对称（同一技术同一实现）由复核员判定"],
		},
		V2: {
			title: "证据三件",
			requiresFile: true,
			fileHint: "判定日志文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["构建", "判定"] },
				{ kind: "hexHash", file: "$file" },
			],
			manual: ["哈希一致、时间戳合理由复核员核对"],
		},
		V4: {
			title: "结论外推检查",
			requiresFile: true,
			fileHint: "实验结论文件路径",
			checks: [{ kind: "markers", file: "$file", markers: ["已测环境"] }],
			manual: ["结论范围 ≤ 已测环境范围——语义判断由总控/复核员执行"],
		},
	},
	"incident-response": {
		I1: {
			title: "证据保全登记",
			checks: [
				{ kind: "file", file: "evidence-preservation.md" },
				{ kind: "markers", file: "evidence-preservation.md", markers: ["保全项", "取证命令"] },
				{ kind: "table", file: "evidence-preservation.md", minRows: 1, minCells: 4 },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "table", file: "evidence-index.md", minRows: 1, minCells: 2 },
			],
			manual: ["保全动作可追溯、取证只读优先由复核员判定"],
		},
		I2: {
			title: "时间线与攻击链还原",
			checks: [
				{ kind: "file", file: "attack-timeline.md" },
				{ kind: "markers", file: "attack-timeline.md", markers: ["时间节点", "可疑IP", "证据"] },
				{ kind: "table", file: "attack-timeline.md", minRows: 3, minCells: 4 },
			],
			manual: ["链上断点如实标注「未知」；节点证据编号可追溯由复核员判定"],
		},
		I3: {
			title: "失陷定性收口",
			checks: [
				{ kind: "file", file: "compromise-verdict.md" },
				{ kind: "markers", file: "compromise-verdict.md", markers: ["定性", "证据"] },
				{ kind: "table", file: "compromise-verdict.md", minRows: 1, minCells: 4 },
			],
			manual: ["confirmed/疑似/排除三态语义由复核员判定；疑似不得进 confirmed"],
		},
		I4: {
			title: "处置建议（清理清单完整性）",
			checks: [
				{ kind: "file", file: "remediation-checklist.md" },
				{ kind: "markers", file: "remediation-checklist.md", markers: ["处置步骤", "验证方式", "用户确认"] },
				{ kind: "table", file: "remediation-checklist.md", minRows: 1, minCells: 4 },
			],
			manual: ["删除类操作标注「用户确认后执行」；步骤可执行性由用户验收"],
		},
		I5: {
			title: "报告完整性",
			requiresFile: true,
			fileHint: "应急溯源报告文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["时间线", "失陷原因", "ATT&CK", "处置建议", "证据索引"] },
			],
			manual: ["每个 finding 带复核 gate-pass 签名由报告员保证"],
		},
	},
	"cloud-security": {
		C1: {
			title: "云资产与暴露面测绘",
			checks: [
				{ kind: "file", file: "cloud-assets.md" },
				{ kind: "markers", file: "cloud-assets.md", markers: ["资产", "暴露面", "凭证", "基线快照"] },
				{ kind: "table", file: "cloud-assets.md", minRows: 2, minCells: 4 },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "table", file: "evidence-index.md", minRows: 1, minCells: 2 },
			],
			manual: ["暴露面完整、凭证来源可追溯、基线快照可还原由复核员判定"],
		},
		C2: {
			title: "攻击路径验证",
			checks: [
				{ kind: "file", file: "attack-paths.md" },
				{ kind: "markers", file: "attack-paths.md", markers: ["入口", "身份", "权限", "资源", "影响", "证据"] },
				{ kind: "table", file: "attack-paths.md", minRows: 1, minCells: 6 },
			],
			manual: ["每条路径影响证明级证据、四要素闭环无悬空由复核员判定"],
		},
		C3: {
			title: "横向与持久化",
			checks: [
				{ kind: "file", file: "lateral-persistence.md" },
				{ kind: "markers", file: "lateral-persistence.md", markers: ["授权", "验证状态", "证据", "排除步骤"] },
				{ kind: "table", file: "lateral-persistence.md", minRows: 1, minCells: 5 },
			],
			manual: ["超范围项标「未执行」零虚构；授权内持久化已登记手动排除步骤"],
		},
		C4: {
			title: "权限链收口",
			checks: [
				{ kind: "file", file: "privilege-chains.md" },
				{ kind: "markers", file: "privilege-chains.md", markers: ["起点", "权限", "终点", "证据"] },
				{ kind: "table", file: "privilege-chains.md", minRows: 1, minCells: 4 },
			],
			manual: ["每链独立证据、无悬空链、疑似不得进 confirmed 由复核员判定"],
		},
		C5: {
			title: "检测缺口评估",
			checks: [
				{ kind: "file", file: "detection-gap.md" },
				{ kind: "markers", file: "detection-gap.md", markers: ["审计", "检测", "终态"] },
				{ kind: "table", file: "detection-gap.md", minRows: 1, minCells: 3 },
			],
			manual: ["每关键路径配检测侧结论、终态三选一禁留空由复核员判定"],
		},
		C6: {
			title: "环境还原",
			checks: [
				{ kind: "file", file: "environment-restore.md" },
				{ kind: "markers", file: "environment-restore.md", markers: ["对象", "还原方式", "验证状态"] },
				{ kind: "table", file: "environment-restore.md", minRows: 1, minCells: 3 },
			],
			manual: ["测试改动全登记、还原可验证、删除类标「用户确认后执行」"],
		},
		C7: {
			title: "报告完整性",
			requiresFile: true,
			fileHint: "云安全评估报告文件路径",
			checks: [
				{
					kind: "markers",
					file: "$file",
					markers: ["攻击路径", "配置缺陷", "权限链", "检测缺口", "环境还原", "证据索引", "阶段终态"],
				},
			],
			manual: ["每条攻击路径带复核 gate-pass 签名由报告员保证"],
		},
	},
	"ctf-solver": {
		board: {
			title: "题面登记",
			checks: [
				{ kind: "file", file: "challenge-board.md" },
				{ kind: "markers", file: "challenge-board.md", markers: ["题名", "模块", "线索"] },
				{ kind: "table", file: "challenge-board.md", minRows: 1, minCells: 3 },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "markers", file: "evidence-index.md", markers: ["tool-plane", "MCP"] },
				{ kind: "table", file: "evidence-index.md", minRows: 1, minCells: 2 },
			],
			manual: ["每行线索已梳理、模块判定合理由总控判定"],
		},
		flag: {
			title: "flag 台账收口",
			checks: [
				{ kind: "file", file: "flag-ledger.md" },
				{ kind: "markers", file: "flag-ledger.md", markers: ["flag", "验证", "状态"] },
				{ kind: "table", file: "flag-ledger.md", minRows: 1, minCells: 4 },
			],
			manual: ["每个「已解」flag 带验证证据；未解标卡点——不猜不撞不伪造由复核员判定"],
		},
	},
};

/** 每模式的报告门（与 sec-enforce REPORT_GATE 对齐）——覆盖度算术对账挂在这些门里。 */
const REPORT_GATES: Record<string, string> = {
	pentest: "P3",
	"code-audit": "A3",
	"binary-analysis": "B2",
	"attack-defense": "report",
	"av-evasion": "V4",
	"incident-response": "I5",
	"cloud-security": "C7",
	"ctf-solver": "flag",
};

//#endregion

//#region decomposition（九模式拆分理论，逐字迁移）

export const DECOMPOSITION: Record<string, { theory: string; criteriaGuide: string; scopeSemantics: string; constraintHints: string; example: string }> = {
	pentest: {
		theory: "作战流程×资产×漏洞类矩阵：被动收集→入口面盘点→验证",
		criteriaGuide: "准则按「每入口资产一条终态 + 漏洞类覆盖格全终态」拆，覆盖矩阵格不落空",
		scopeSemantics: "分母=入口资产面（主机/站点/API/客户端），每行一项资产单元",
		constraintHints: "速率纪律/资金类只读重放/破坏操作禁执行/授权边界",
		example: "①demo 站 Web 面每漏洞类格有终态 ②10.0.0.5 服务面终态 ③高危发现附 PoC 复现",
	},
	"code-audit": {
		theory: "对象形态→triage→模块×sink 矩阵→双链（全量扫描链+深度审计链）",
		criteriaGuide: "准则按「每模块终态 + sink 类覆盖 + 扫描命中对账守恒（扫描器报告数=终态数）」拆",
		scopeSemantics: "分母=模块/路由/文件全集，每行一个审计单元",
		constraintHints: "审计对象只读/semgrep 禁网/不修被审代码",
		example: "①全部 12 条路由每条给终态 ②sink 五类各有覆盖结论 ③扫描命中 100% 对账",
	},
	"binary-analysis": {
		theory: "样本登记→家族指纹分诊→假设台账循环→多视角→IOC",
		criteriaGuide: "准则按「每样本每分析维度终态 + 假设台账全收口（未决不得写成事实）」拆",
		scopeSemantics: "分母=样本集×分析维度，每行一个样本或一个维度面",
		constraintHints: "干净 VM 铁律/样本外传登记/活体处置 SOP",
		example: "①样本 A 静态+动态两维度终态 ②假设台账全部 confirmed/dismissed ③IOC 输出可机读",
	},
	"attack-defense": {
		theory: "五阶段编排（侦察→突破→横向→持久化→报告），每阶段只基于上一阶段已验证结果",
		criteriaGuide: "准则按「每阶段产物过门 + 链级分布（L1-L5）+ 战果登记」拆",
		scopeSemantics: "分母=授权网段/凭据面/高价值线，每行一个作战面",
		constraintHints: "监测姿态分叉（§0.5 姿态卡）/破坏性步骤默认关/痕迹双轨",
		example: "①外网拿到初始访问 ②横向覆盖授权网段 80% ③链级分布呈报",
	},
	"av-evasion": {
		theory: "配对实验：载荷↔判定引擎矩阵，四类载荷标准时序",
		criteriaGuide: "准则按「每载荷类×引擎终态（过检/被检出附指纹）」拆——配对完整是硬约束",
		scopeSemantics: "分母=载荷类×引擎矩阵（登记制，不自动派生）",
		constraintHints: "授权立场/产物限实验室目录/清痕顺序纪律",
		example: "①CS 载荷过 360 全家桶（附指纹）②四类载荷各至少一引擎终态",
	},
	"incident-response": {
		theory: "证据保全→时间线重建→定性→处置建议→报告（I1-I5 五门）",
		criteriaGuide: "准则按「时间线节点收口 + 五维定损 + IOC 富化」拆",
		scopeSemantics: "分母=主机/时间窗/案件范围，每行一台主机或一个调查面",
		constraintHints: "只读优先/证据四级/先固定后分析",
		example: "①入口点定位附证据 ②完整时间线（含横向路径）③影响范围五维定损",
	},
	"cloud-security": {
		theory: "资产测绘→攻击路径四要素（身份→权限→资源→影响）→场景卡",
		criteriaGuide: "准则按「每条攻击路径验证 + 权限链收口 + 场景卡终态」拆",
		scopeSemantics: "分母=账号/区域/服务面，每行一个云资源或信任面",
		constraintHints: "只读 API 优先/写操作过门/环境还原义务",
		example: "①目标账号权限链收口 ②至少一条路径打通到影响 ③环境还原登记",
	},
	"ctf-solver": {
		theory: "题面登记→模块路由→board/solve 两门→flag 台账",
		criteriaGuide: "准则按「每题终态（已解附平台验证/卡点附原因）」拆",
		scopeSemantics: "分母=题目集（含分值权重），每行一题（登记制，不自动派生）",
		constraintHints: "flag 真实性=平台回显/不猜不撞/爆破限速最后手段",
		example: "①全部题目终态三选一（已解/卡点/放弃附因）②flag 全部平台验证",
	},
	"asset-mapping": {
		theory: "五入口（单位名/域名/IP/关键字/CIDR）→多平台引擎查询→子域/DNS 校验→备案归属→指纹识别→清册收口",
		criteriaGuide: "准则按「每入口一条终态 + 清册字段完整（资产×归属×指纹）」拆",
		scopeSemantics: "分母=入口清单（单位/域名/IP 段），每行一个测绘入口",
		constraintHints: "止步测绘与指纹不攻击/引擎配额纪律（画像先行省配额）/key 缺失先问",
		example: "①集团名入口全平台查询有终态 ②子域清单 DNS 校验全量 ③Excel 清册字段齐备可审计",
	},
	redteam: {
		theory: "任务分类路由→轻重判→任务书（依据锚+模式理论摘要）；总控不设自身准则——消费专业模式 gate-pass 产物",
		criteriaGuide: "（总控不拆准则——路由到专业模式后由其按自身理论登记）",
		scopeSemantics: "（总控不设分母——由接手模式登记）",
		constraintHints: "三边界：不越权 gate 判定/只消费 gate-pass 产物/读盘可见性",
		example: "任务书带依据锚与建议模式的理论摘要行，接手模式照此开工三登记",
	},
};

export const ANCHOR_KINDS = ["boot", "criterion", "scope", "finding", "chain"] as const;
export const CONSTRAINT_KINDS = ["deny", "allow"] as const;

//#endregion

//#region paths（约定第 4 条：插件态在 ~/.pi/redteam/<plugin>/，工作区产物留在任务工作区）

export const STATE_FILE = "operation-state.json";
const GATE_LOG = "gate-log.md";

const STATE_DIR = path.join(process.env.HOME || os.homedir(), ".pi", "redteam", "dsh-stage-gate");
const LOG_DIR = path.join(STATE_DIR, "logs");
const INDEX_FILE = path.join(STATE_DIR, "state-index.json");
/** 新建会话时，索引里多旧的「上次工作区」仍值得提示继续（小时）。 */
const RESUME_TTL_HOURS = 24;

function ensureDir(dir: string): void {
	try {
		fs.mkdirSync(dir, { recursive: true });
	} catch {
		/* 目录已存在或不可建：调用方各自降级 */
	}
}

function readSafe(fsm: FsLike, p: string): string | undefined {
	try {
		return fsm.readFileSync(p, "utf8") as string;
	} catch {
		return undefined;
	}
}

//#endregion

//#region pure validators（结构判定必须由工具完成——模型不能自评门禁）

const HEX64 = /[a-f0-9]{64}/i;

/** 解析 markdown 表格行；分隔行（|---|）排除。返回每行的非空单元格数。 */
export function tableRows(text: string): { line: number; nonEmpty: number }[] {
	const rows: { line: number; nonEmpty: number }[] = [];
	const lines = text.split(/\r?\n/);
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i].trim();
		if (!line.startsWith("|")) continue;
		const cells = line.split("|").slice(1, line.endsWith("|") ? -1 : undefined).map((c) => c.trim());
		if (cells.length > 0 && cells.every((c) => /^:?-{2,}:?$/.test(c))) continue;
		rows.push({ line: i + 1, nonEmpty: cells.filter((c) => c.length > 0).length });
	}
	return rows;
}

function runCheck(fsm: FsLike, check: GateCheck, resolve: { workspace: (f: string) => string; file?: string }): CheckResult {
	const file = check.file === "$file" ? resolve.file : check.file && resolve.workspace(check.file);
	const id = `${check.kind}:${check.file ?? check.dir}`;
	switch (check.kind) {
		case "file": {
			const text = file && readSafe(fsm, file);
			return { id, ok: !!text && text.trim().length > 0, detail: file ?? "(missing $file)" };
		}
		case "markers": {
			const text = file && readSafe(fsm, file);
			if (!text) return { id, ok: false, detail: `${file ?? "(missing $file)"} 不存在` };
			const missing = (check.markers ?? []).filter((m) => !text.includes(m));
			return { id, ok: missing.length === 0, detail: missing.length ? `${file} 缺标记: ${missing.join(", ")}` : String(file) };
		}
		case "hexHash": {
			const text = file && readSafe(fsm, file);
			return { id, ok: !!text && HEX64.test(text), detail: file ?? "(missing $file)" };
		}
		case "table": {
			const text = file && readSafe(fsm, file);
			if (!text) return { id, ok: false, detail: `${file ?? "(missing $file)"} 不存在` };
			const rows = tableRows(text);
			const incomplete = rows.filter((r) => r.nonEmpty < (check.minCells ?? 1)).map((r) => `L${r.line}`);
			const ok = rows.length >= (check.minRows ?? 1) && incomplete.length === 0;
			return { id, ok, detail: `${file}: ${rows.length} 行（要求 ≥${check.minRows}），未填满行: ${incomplete.join(",") || "无"}` };
		}
		case "provenance": {
			const dir = resolve.workspace(check.dir ?? "artifacts");
			let entries: Dirent[] = [];
			try {
				entries = fsm.readdirSync(dir, { withFileTypes: true });
			} catch {
				return { id, ok: false, detail: `${dir} 不存在` };
			}
			for (const e of entries) {
				if (!e.isDirectory()) continue;
				const p = path.join(dir, String(e.name), "provenance.md");
				const text = readSafe(fsm, p);
				if (text && HEX64.test(text)) return { id, ok: true, detail: p };
			}
			return { id, ok: false, detail: `${dir}/*/provenance.md 无带哈希登记` };
		}
		default:
			return { id, ok: false, detail: `unknown check kind ${String(check.kind)}` };
	}
}

/** 门序列（对象键序即判定次序）。 */
export function gateSequence(mode: string): string[] {
	return Object.keys(GATES[mode] ?? {});
}

/**
 * 门禁顺序硬性 reject（Pi 侧新增，原实现只回写 done 不拦）：
 *  1) 前序门已判过且 FAIL → 拦（必须先收口，禁止绕过未过门继续推进）；
 *  2) 前序门从未判定且该门是**工作区结构性门**（不要求 file 参数）→ 拦（结构性产物不齐谈不上后段）；
 *  3) 前序门是**逐产物门**（requiresFile：逐 finding / 逐轮实验）且未判定 → 不拦（可能确无该类产物），
 *     但在返回体 pendingPrior 里列明，模型无法把它当成「已过门」。
 * @returns 非空 = 拒绝理由；空串 = 放行
 */
export function previousGateViolation(mode: string, stage: string, st: OperationState | null): string {
	const seq = gateSequence(mode);
	const idx = seq.indexOf(stage);
	if (idx <= 0) return "";
	const gates = st?.gates ?? {};
	for (const prev of seq.slice(0, idx)) {
		const rec = gates[prev];
		if (rec?.pass === true) continue;
		if (rec?.pass === false) {
			return `前序门 ${mode}/${prev} 上次判定 FAIL 未收口${rec.missing?.length ? `（缺项：${rec.missing.join(" ; ")}）` : ""}——先补齐并重新 stage_gate ${mode}/${prev} 通过，才判 ${mode}/${stage}`;
		}
		if (!GATES[mode][prev].requiresFile) {
			return `前序门 ${mode}/${prev}（${GATES[mode][prev].title}）尚未判定——结构性门须先过：stage_gate(mode=${mode}, stage=${prev}, workspace=…)`;
		}
	}
	return "";
}

/** 未判定前序门清单（逐产物门，放行但要 surface）。 */
export function pendingPriorGates(mode: string, stage: string, st: OperationState | null): string[] {
	const seq = gateSequence(mode);
	const idx = seq.indexOf(stage);
	if (idx <= 0) return [];
	const gates = st?.gates ?? {};
	return seq.slice(0, idx).filter((p) => gates[p]?.pass !== true && GATES[mode][p].requiresFile);
}

/**
 * 校验一道门。除 `fsm` 外纯函数（生产注入 node:fs，自测注入假 fs）。
 * 未知门 / 缺 file 参数 / 传入 file 不可读 → throw（硬性 reject，不由模型自评）。
 */
export function runGate(fsm: FsLike, args: { mode: string; stage: string; workspace: string; file?: string }): Verdict {
	const { mode, stage, workspace } = args;
	if (!GATES[mode]) throw new Error(`unknown mode ${mode}; valid: ${Object.keys(GATES).join(", ")}`);
	const gate = GATES[mode][stage];
	if (!gate) throw new Error(`unknown gate ${mode}/${stage}; valid stages: ${gateSequence(mode).join(", ") || "(unknown mode)"}`);
	if (gate.requiresFile && !args.file) throw new Error(`gate ${mode}/${stage} 需要 file 参数（${gate.fileHint}）`);
	const resolve = {
		workspace: (f: string) => path.resolve(workspace, f),
		file: args.file ? (path.isAbsolute(args.file) ? path.resolve(args.file) : path.resolve(workspace, args.file)) : undefined,
	};
	if (args.file && resolve.file && readSafe(fsm, resolve.file) === undefined) {
		throw new Error(`file 参数指向的文件读不到：${resolve.file}（${gate.fileHint ?? "gate-scoped file"}）——先落盘产物再判门，路径别用相对 cwd 猜`);
	}
	const results: CheckResult[] = gate.checks.map((check) => runCheck(fsm, check, resolve));
	// 报告门追加覆盖度算术对账：scope 已登记才激活（未登记=零影响）。
	// 目标文件：传参 file 优先，否则门 schema 的第一个固定文件。
	if (REPORT_GATES[mode] === stage) {
		let reportFile = resolve.file;
		if (!reportFile) {
			const fixed = gate.checks.find((c) => c.file && c.file !== "$file");
			if (fixed?.file) reportFile = path.resolve(workspace, fixed.file);
		}
		if (reportFile) {
			const cov = coverageCheck(fsm, workspace, reportFile);
			if (cov) results.push({ id: "coverage:report", kind: "coverage", file: path.basename(reportFile), ok: cov.ok, detail: cov.detail });
		}
	}
	return {
		mode,
		stage,
		title: gate.title,
		pass: results.every((r) => r.ok),
		checks: results,
		manual: gate.manual,
		missing: results.filter((r) => !r.ok).map((r) => `${r.id} — ${r.detail}`),
	};
}

/** gates_list 的 schema 摘要（含门数，便于核对 32 道门一条不少）。 */
export function listGates(mode?: string): Record<string, Record<string, { title: string; files: string[]; requiresFile: boolean; manual: string[] }>> {
	if (mode && !GATES[mode]) throw new Error(`unknown mode ${mode}; valid: ${Object.keys(GATES).join(", ")}`);
	const modes = mode ? { [mode]: GATES[mode] } : GATES;
	const out: Record<string, Record<string, { title: string; files: string[]; requiresFile: boolean; manual: string[] }>> = {};
	for (const [m, stages] of Object.entries(modes)) {
		const perMode: Record<string, { title: string; files: string[]; requiresFile: boolean; manual: string[] }> = {};
		for (const [s, g] of Object.entries(stages)) {
			const files = [...new Set(g.checks.filter((c) => c.file && c.file !== "$file").map((c) => String(c.file)))];
			perMode[s] = { title: g.title, files, requiresFile: !!g.requiresFile, manual: g.manual };
		}
		out[m] = perMode;
	}
	return out;
}

/** 门总数（自测/审计用：八模式 32 道门）。 */
export function gateCount(): { modes: number; gates: number; perMode: Record<string, number> } {
	const perMode: Record<string, number> = {};
	let gates = 0;
	for (const m of Object.keys(GATES)) {
		const n = gateSequence(m).length;
		perMode[m] = n;
		gates += n;
	}
	return { modes: Object.keys(GATES).length, gates, perMode };
}

//#endregion

//#region operation state（目标契约 / 中断恢复的文件契约）

const cleanLine = (s: unknown, max: number): string => String(s ?? "").trim().slice(0, max);
const parseIds = (s: unknown): string[] => String(s ?? "").split(/[,，;\s]+/).map((x) => x.trim()).filter(Boolean);

function writeState(workspace: string, st: OperationState): void {
	ensureDir(workspace);
	fs.writeFileSync(path.join(workspace, STATE_FILE), JSON.stringify(st, null, 2) + "\n");
}

/** 读工作区运行状态；不存在/损坏返回 null（纯函数，导出供 sec-enforce 等下游与自测复用）。 */
export function readOperationState(fsm: FsLike, workspace: string): OperationState | null {
	try {
		const raw = String(fsm.readFileSync(path.join(workspace, STATE_FILE), "utf8"));
		const st = JSON.parse(raw) as OperationState;
		if (st && typeof st === "object" && Array.isArray(st.criteria)) return st;
	} catch {
		/* 缺失或损坏都按无状态处理 */
	}
	return null;
}

/** stage_gate 判定后同步 gates 进度（无契约时也落骨架——恢复盘先于契约也能工作）；失败静默。 */
export function syncOperationState(workspace: string, verdict: Verdict): void {
	try {
		let st = readOperationState(fs, workspace);
		if (st === null) st = { version: 1, mode: verdict.mode, goal: "", criteria: [], gates: {}, pending: [], created_at: new Date().toISOString() };
		st.mode = verdict.mode;
		st.gates = st.gates && typeof st.gates === "object" ? st.gates : {};
		st.gates[verdict.stage] = { pass: verdict.pass, at: new Date().toISOString(), missing: verdict.pass ? [] : verdict.missing.slice(0, 8) };
		st.updated_at = new Date().toISOString();
		writeState(workspace, st);
	} catch {
		/* 状态同步失败不影响门禁判定 */
	}
}

/** 追加判定行进 gate-log.md（审计 trail）；写失败绝不翻转型判定结果。 */
export function appendGateLog(workspace: string, verdict: Verdict): string {
	const line = `| ${new Date().toISOString()} | ${verdict.mode}/${verdict.stage} | ${verdict.pass ? "pass" : "fail"} | ${verdict.missing.join(" ; ") || "-"} |\n`;
	const log = path.join(workspace, GATE_LOG);
	const head = readSafe(fs, log) ?? `# gate-log（阶段门禁判定审计 trail）\n\n| 时间 | 门 | 结果 | 缺项 |\n|---|---|---|---|\n`;
	ensureDir(workspace);
	fs.writeFileSync(log, head.endsWith("\n") ? head + line : head + "\n" + line);
	return log;
}

/**
 * 登记目标契约：criteria 为多行文本，每行一条成功准则（可判定表述）。
 * mode = 调用方解析好的模式（显式参数 → 状态文件既有 mode），非空即回写 st.mode。
 * 缺陷修复：原先 operation_goal 不落 mode，route-boost 注入与报告对账要等第一次 stage_gate 才有真值。
 * 仍由 writeState 单一写者落盘，字段与 syncOperationState 完全同格式（不造第二份真值）。
 */
export function setGoal(workspace: string, goal: string, criteriaText: string, mode?: string): OperationState {
	const lines = String(criteriaText ?? "")
		.split(/\r?\n/)
		.map((l) => cleanLine(l, 200))
		.filter(Boolean);
	if (!cleanLine(goal, 500)) throw new Error("goal required（目标一句话）");
	if (lines.length === 0) throw new Error("criteria required（至少一条成功准则，每行一条）");
	if (lines.length > 20) throw new Error("criteria 最多 20 条");
	const prev = readOperationState(fs, workspace);
	const st: OperationState = prev ?? { version: 1, mode: "", goal: "", criteria: [], gates: {}, pending: [], created_at: new Date().toISOString() };
	st.goal = cleanLine(goal, 500);
	st.criteria = lines.map((text, i) => ({ id: `g${i + 1}`, text, status: "open" as const, evidence: "" }));
	const modeNorm = String(mode ?? "").trim();
	if (modeNorm) st.mode = modeNorm;
	st.updated_at = new Date().toISOString();
	writeState(workspace, st);
	return st;
}

export interface ProgressArgs {
	met?: string;
	failed?: string;
	reopened?: string;
	pending?: string;
	note?: string;
	tested?: string;
	evidence?: string;
	intent_done?: string;
	intent_blocked?: string;
	intent_dropped?: string;
}

/** 收口准则 / 维护待办；返回摘要（verdict=all-met 表示目标契约已全部达成）。 */
export function updateProgress(workspace: string, args: ProgressArgs): Record<string, unknown> {
	const st = readOperationState(fs, workspace);
	if (st === null) throw new Error("operation-state.json 不存在——先 operation_goal 登记目标契约");
	const byId = new Map(st.criteria.map((c) => [c.id, c]));
	const unknown: string[] = [];
	for (const [list, status] of [
		[args.met ?? "", "met"],
		[args.failed ?? "", "failed"],
		[args.reopened ?? "", "open"],
	] as [string, Criterion["status"]][]) {
		for (const id of parseIds(list)) {
			const c = byId.get(id);
			if (c === undefined) unknown.push(id);
			else {
				c.status = status;
				if (status === "open") c.evidence = "";
			}
		}
	}
	if (unknown.length) throw new Error(`未知准则 id：${unknown.join(", ")}（有效：${[...byId.keys()].join(", ") || "无"}）`);
	// 硬性 reject：声明 met 必带证据指位（结构可机判部分，语义真伪仍归复核员）
	if (cleanLine(args.met, 200) && !cleanLine(args.evidence, 300)) {
		throw new Error(`met 需要 evidence 指位（${cleanLine(args.met, 80)} 凭什么算达成？evidence=evidence-index 编号/覆盖矩阵行/输出文件路径）`);
	}
	for (const id of parseIds(args.met)) {
		const c = byId.get(id);
		if (c) c.evidence = cleanLine(args.evidence, 300);
	}
	// 意图收口：done=有产出收口 / blocked=受阻终态 / dropped=放弃（blocked/dropped 须在 note 说明原因）
	const intents = normalizeIntents(st);
	if (intents.length > 0 || args.intent_done || args.intent_blocked || args.intent_dropped) {
		const byIntent = new Map(intents.map((i) => [i.id, i]));
		const unknownIntents: string[] = [];
		for (const [list, status] of [
			[args.intent_done ?? "", "done"],
			[args.intent_blocked ?? "", "blocked"],
			[args.intent_dropped ?? "", "dropped"],
		] as [string, IntentItem["status"]][]) {
			for (const id of parseIds(list)) {
				const i = byIntent.get(id);
				if (i === undefined) unknownIntents.push(id);
				else {
					i.status = status;
					i.closed_at = new Date().toISOString();
				}
			}
		}
		if (unknownIntents.length) throw new Error(`未知意图 id：${unknownIntents.join(", ")}（有效：${[...byIntent.keys()].join(", ") || "无"}）`);
		if ((args.intent_blocked || args.intent_dropped) && !args.note) throw new Error("blocked/dropped 收口须在 note 说明原因（受阻依据/放弃理由——终态可追溯）");
		st.intents = intents;
	}
	if (args.pending !== undefined && args.pending !== "") st.pending = args.pending.split(/\r?\n/).map((l) => cleanLine(l, 200)).filter(Boolean);
	else if (args.pending === "") st.pending = [];
	if (args.note) st.note = cleanLine(args.note, 500);
	st.updated_at = new Date().toISOString();
	writeState(workspace, st);
	const openIds = st.criteria.filter((c) => c.status !== "met").map((c) => c.id);
	return {
		goal: st.goal,
		total: st.criteria.length,
		met: st.criteria.length - openIds.length,
		open: openIds.length,
		openIds,
		pending: st.pending,
		intents: intentSummary(st),
		verdict: openIds.length === 0 ? "all-met" : "open-remaining",
	};
}

//#endregion

//#region 覆盖度台账（scope/分子登记 + 报告门算术对账）

function normalizeScope(st?: OperationState | null): ScopeItem[] {
	if (!Array.isArray(st?.scope)) return [];
	return st.scope
		.filter((s): s is ScopeItem => Boolean(s && typeof s === "object" && typeof s.id === "string" && s.id))
		.map((s) => ({ id: s.id, label: String(s.label ?? s.id).slice(0, 200) }));
}

function normalizeTested(st?: OperationState | null): TestedItem[] {
	if (!Array.isArray(st?.tested)) return [];
	return st.tested
		.filter((t): t is TestedItem => Boolean(t && typeof t === "object" && typeof t.id === "string" && t.id))
		.map((t) => ({ id: t.id, evidence: String(t.evidence ?? "").slice(0, 300), at: t.at }));
}

/** 登记范围台账（分母）：items 每行一项（「标签」或「id: 标签」），重登记整表替换。 */
export function setScope(workspace: string, itemsText: string): ReturnType<typeof scopeSummary> {
	const lines = String(itemsText ?? "")
		.split(/\r?\n/)
		.map((l) => cleanLine(l, 200))
		.filter(Boolean);
	if (lines.length === 0) throw new Error("items required（至少一项，每行一条：标签 或 id: 标签）");
	if (lines.length > 200) throw new Error("scope 最多 200 项");
	const seen = new Set<string>();
	const items: ScopeItem[] = lines.map((line, i) => {
		const m = /^([A-Za-z0-9_-]{1,16}):\s*(.+)$/.exec(line);
		const id = m ? m[1] : `s${i + 1}`;
		if (seen.has(id)) throw new Error(`scope id 重复：${id}`);
		seen.add(id);
		return { id, label: (m ? m[2] : line).slice(0, 200) };
	});
	const st = readOperationState(fs, workspace);
	if (st === null) throw new Error("operation-state.json 不存在——先 operation_goal 登记目标契约，再 operation_scope 登记范围");
	st.scope = items;
	if (!Array.isArray(st.tested)) st.tested = [];
	// 重登记范围后，越界的 tested 行剔除（id 不在新 scope 内的丢弃）
	st.tested = normalizeTested(st).filter((t) => seen.has(t.id));
	st.updated_at = new Date().toISOString();
	writeState(workspace, st);
	return scopeSummary(st);
}

/** 标记已测（分子）：ids 来自 scope，evidence 必填。幂等（重复标记刷新证据与时间）。 */
export function markTested(workspace: string, ids: string, evidence: string): ReturnType<typeof scopeSummary> {
	const list = parseIds(ids);
	if (list.length === 0) throw new Error("tested ids required");
	if (!cleanLine(evidence, 300)) throw new Error("evidence required（tested 必须带证据指位——evidence 编号/矩阵行/输出文件）");
	const st = readOperationState(fs, workspace);
	if (st === null) throw new Error("operation-state.json 不存在——先 operation_goal 登记目标契约");
	const scope = normalizeScope(st);
	if (scope.length === 0) throw new Error("scope 未登记——先 operation_scope 登记范围分母");
	const known = new Set(scope.map((s) => s.id));
	const unknown = list.filter((id) => !known.has(id));
	if (unknown.length) throw new Error(`未知 scope id：${unknown.join(", ")}（有效：${[...known].join(", ")}）`);
	const tested = normalizeTested(st).filter((t) => !list.includes(t.id));
	const at = new Date().toISOString();
	for (const id of list) tested.push({ id, evidence: cleanLine(evidence, 300), at });
	st.tested = tested;
	st.updated_at = at;
	writeState(workspace, st);
	return scopeSummary(st);
}

/** 覆盖度摘要（tested 只计 scope 内 id）。 */
export function scopeSummary(st: OperationState | null) {
	const scope = normalizeScope(st);
	const tested = normalizeTested(st);
	const testedIds = new Set(tested.map((t) => t.id));
	const untestedIds = scope.filter((s) => !testedIds.has(s.id)).map((s) => s.id);
	return { scope: scope.length, tested: tested.filter((t) => testedIds.has(t.id)).length, untested: untestedIds.length, untestedIds };
}

/** 报告门覆盖度对账（纯函数）。scope 未登记返回 null（对账不激活）。 */
export function coverageCheck(fsm: FsLike, workspace: string, reportFile: string): { ok: boolean; detail: string } | null {
	let st: OperationState;
	try {
		st = JSON.parse(String(fsm.readFileSync(path.join(workspace, STATE_FILE), "utf8"))) as OperationState;
	} catch {
		return null;
	}
	const scope = normalizeScope(st);
	if (scope.length === 0) return null;
	const summary = scopeSummary(st);
	let text: string;
	try {
		text = String(fsm.readFileSync(reportFile, "utf8"));
	} catch {
		return { ok: false, detail: `覆盖度对账：报告文件不可读（${path.basename(reportFile)}）` };
	}
	const m = /覆盖度?\s*[：:]\s*(\d+)\s*[/／]\s*(\d+)|coverage\s*[：:]\s*(\d+)\s*[/／]\s*(\d+)/i.exec(text);
	if (!m) {
		return { ok: false, detail: `覆盖度对账：scope 已登记 ${summary.scope} 项（已测 ${summary.tested}），报告须声明「覆盖：${summary.tested}/${summary.scope}」——部分覆盖照实声明可过（未测项 ${summary.untestedIds.join(", ") || "无"} 须列入未覆盖清单），虚报或漏报拦截` };
	}
	const declaredTested = Number(m[1] ?? m[3]);
	const declaredTotal = Number(m[2] ?? m[4]);
	if (declaredTested !== summary.tested || declaredTotal !== summary.scope) {
		return { ok: false, detail: `覆盖度对账：报告声明 ${declaredTested}/${declaredTotal} 与台账不符——程序实测：已测 ${summary.tested} / 共 ${summary.scope}（未测：${summary.untestedIds.join(", ") || "无"}）。先 operation_progress tested 补登记，或修正报告声明` };
	}
	return { ok: true, detail: `覆盖度对账通过：${summary.tested}/${summary.scope}${summary.untested > 0 ? `（部分覆盖，未测 ${summary.untested} 项照实声明）` : ""}` };
}

//#endregion

//#region 意图台账（锚 + 收口联动）

function normalizeIntents(st?: OperationState | null): IntentItem[] {
	if (!Array.isArray(st?.intents)) return [];
	return st.intents.filter((i): i is IntentItem => Boolean(i && typeof i === "object" && typeof i.id === "string" && i.id));
}

export interface AnchorResolvers {
	findingExists?: (sessionId: string, id: string) => boolean;
	chainExists?: (sessionId: string, mode: string, id: string) => boolean;
}

/** 锚点校验（纯函数，跳库解析器注入）。返回 "" = 通过；非空 = 拒绝理由。 */
export function validateAnchor(st: OperationState | null, anchor: { kind: string; ref?: string }, resolvers: AnchorResolvers = {}, sessionId = "", mode = ""): string {
	const k = (ANCHOR_KINDS as readonly string[]).includes(anchor.kind) ? anchor.kind : "";
	if (!k) return `anchor_kind 非法：${anchor.kind}（合法：${ANCHOR_KINDS.join(" / ")}——boot=开局豁免、criterion=准则 id、scope=范围 id、finding=成果 id、chain=链路节点 id）`;
	if (k === "boot") return "";
	const r = String(anchor.ref ?? "").trim();
	if (!r) return `anchor_ref 必填（${k} 锚必须带具体 id；顶层全新方向才用 boot 豁免）`;
	if (k === "criterion") {
		const ids = new Set((Array.isArray(st?.criteria) ? st.criteria : []).map((c) => c?.id).filter(Boolean));
		return ids.has(r) ? "" : `准则 id 不存在：${r}（有效：${[...ids].join(", ") || "无——先 operation_goal 登记"}）`;
	}
	if (k === "scope") {
		const ids = new Set(normalizeScope(st).map((s) => s.id));
		return ids.has(r) ? "" : `scope id 不存在：${r}（有效：${[...ids].join(", ") || "无——先 operation_scope 登记"}）`;
	}
	if (k === "finding") {
		if (typeof resolvers.findingExists === "function") {
			try {
				if (resolvers.findingExists(sessionId, r)) return "";
				return `finding 不存在（当前会话）：${r}——成果 id 形如 pentest-3（本会话 redteam_finding_register 登记；跳会话成果不可锚，改用 chain 或材料路径）`;
			} catch {
				return ""; // 解析器故障降级放行（不 brick 意图登记）
			}
		}
		return /^[a-z][a-z0-9-]*-\d+$/.test(r) ? "" : `finding id 形如 pentest-3（模式-序号）：${r} 格式不符`;
	}
	if (k === "chain") {
		if (typeof resolvers.chainExists === "function") {
			try {
				if (resolvers.chainExists(sessionId, mode, r)) return "";
				return `链路节点不存在（当前会话）：${r}——链路节点由 redteam_chain_node 登记`;
			} catch {
				return "";
			}
		}
		return /^[\w-]{1,64}$/.test(r) ? "" : `链路节点 id 格式不符：${r}`;
	}
	return "";
}

/** 登记意图（方向带锚）。返回摘要；校验失败 throw。 */
export function registerIntent(workspace: string, args: { summary: string; anchorKind: string; anchorRef?: string; note?: string }, resolvers: AnchorResolvers = {}): ReturnType<typeof intentSummary> & { id: string } {
	const s = cleanLine(args.summary, 200);
	if (!s) throw new Error("summary required（一句话方向，≤200 字符）");
	const st = readOperationState(fs, workspace);
	const bad = validateAnchor(st, { kind: args.anchorKind, ref: args.anchorRef }, resolvers);
	if (bad) throw new Error(bad);
	if (st === null) throw new Error("operation-state.json 不存在——先 operation_goal 登记目标契约");
	const intents = normalizeIntents(st);
	const id = `i${intents.length + 1}`;
	intents.push({ id, summary: s, anchor: { kind: args.anchorKind, ref: cleanLine(args.anchorRef, 80) }, status: "open", note: cleanLine(args.note, 300), created_at: new Date().toISOString() });
	st.intents = intents;
	st.updated_at = new Date().toISOString();
	writeState(workspace, st);
	return { id, ...intentSummary(st) };
}

export function intentSummary(st: OperationState | null) {
	const intents = normalizeIntents(st);
	const openIds = intents.filter((i) => i.status === "open").map((i) => i.id);
	return { total: intents.length, open: openIds.length, openIds };
}

//#endregion

//#region 约束层（deny/allow）+ scope 保守派生

export function normalizeConstraints(st?: OperationState | null): ConstraintItem[] {
	if (!Array.isArray(st?.constraints)) return [];
	return st.constraints
		.filter((c): c is ConstraintItem => Boolean(c && typeof c === "object" && (CONSTRAINT_KINDS as readonly string[]).includes(c.kind) && typeof c.text === "string" && c.text.trim()))
		.map((c) => ({ id: String(c.id), kind: c.kind, text: c.text.slice(0, 200), keywords: Array.isArray(c.keywords) ? c.keywords.filter((k) => typeof k === "string" && k).slice(0, 12) : [] }));
}

/** 登记约束（整表替换）。行格式：`deny: 文本` / `allow: 文本`，可选匹配词 `deny: 文本 :: kw1,kw2`。 */
export function setConstraints(workspace: string, itemsText: string): ReturnType<typeof constraintSummary> {
	const lines = String(itemsText ?? "")
		.split(/\r?\n/)
		.map((l) => l.trim())
		.filter(Boolean);
	if (lines.length === 0) throw new Error("items required（至少一条，每行：deny: 文本 [:: 匹配词]）");
	if (lines.length > 30) throw new Error("约束最多 30 条");
	const items: ConstraintItem[] = lines.map((line, i) => {
		const m = /^(deny|allow)\s*[：:]\s*(.+)$/.exec(line);
		if (!m) throw new Error(`行 ${i + 1} 格式非法：「${line.slice(0, 40)}」——须以 deny: 或 allow: 开头`);
		let text = m[2];
		let keywords: string[] = [];
		const kw = /\s*::\s*(.+)$/.exec(text);
		if (kw) {
			keywords = kw[1].split(/[,，]/).map((k) => k.trim()).filter(Boolean).slice(0, 12);
			text = text.slice(0, kw.index ?? text.length).trim();
		}
		return { id: `c${i + 1}`, kind: m[1] as "deny" | "allow", text: text.slice(0, 200), keywords };
	});
	const st = readOperationState(fs, workspace);
	if (st === null) throw new Error("operation-state.json 不存在——先 operation_goal 登记目标契约");
	st.constraints = items;
	st.updated_at = new Date().toISOString();
	writeState(workspace, st);
	return constraintSummary(st);
}

/** 约束摘要（guard 与信封消费的数据面）。 */
export function constraintSummary(st: OperationState | null) {
	const list = normalizeConstraints(st);
	const deny = list.filter((c) => c.kind === "deny");
	return {
		total: list.length,
		deny: deny.length,
		allow: list.length - deny.length,
		denyGuarded: deny.filter((c) => c.keywords.length > 0).length,
		lines: list.map((c) => `${c.kind === "deny" ? "禁" : "允"}：${c.text}${c.keywords.length ? `（匹配词 ${c.keywords.join("/")}）` : ""}`),
	};
}

/** scope 保守派生（纯函数，模式感知）：只出草稿不落库，模型确认后 operation_scope 登记。 */
export function deriveScopeDraft(texts: string | string[], mode = ""): string[] {
	const raw = Array.isArray(texts) ? texts.join("\n") : String(texts ?? "");
	const hosts = new Set<string>();
	for (const m of raw.matchAll(/https?:\/\/([A-Za-z0-9.-]+)[:/]/gi)) hosts.add(m[1].toLowerCase());
	for (const m of raw.matchAll(/https?:\/\/([A-Za-z0-9.-]+)(?:$|[\s。）)，,；;])/gm)) hosts.add(m[1].toLowerCase());
	for (const m of raw.matchAll(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g)) {
		const ip = m[1];
		if (ip.split(".").every((o) => Number(o) <= 255)) hosts.add(ip);
	}
	for (const m of raw.matchAll(/(?:^|[\s（(，,【\[])((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,12})(?:$|[\s。）)，,】\]:：/])/gm)) {
		const h = m[1].toLowerCase();
		if (!/^\d+(\.\d+)+$/.test(h)) hosts.add(h);
	}
	const skip = new Set(["e.g", "example.com", "localhost"]);
	const unified = () => [...hosts].filter((h) => !skip.has(h) && h.includes(".")).sort();

	switch (mode) {
		case "code-audit": {
			const out = new Set<string>();
			for (const m of raw.matchAll(/[\w.-]+(?:\/[\w.-]+){1,6}\.(?:js|ts|py|java|go|php|rb|rs|cs|vue|jsx|tsx)/g)) out.add(m[0]);
			for (const m of raw.matchAll(/(?:^|[\s（(，,])(\/[a-z][\w-]*(?:\/[a-z][\w-]*){1,4})(?:$|[\s。）)，,])/gim)) out.add(m[1].toLowerCase());
			return [...out].sort().slice(0, 50);
		}
		case "binary-analysis": {
			const out = new Set<string>();
			for (const m of raw.matchAll(/\b[0-9a-f]{32}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b/gi)) out.add(m[0].toLowerCase());
			for (const m of raw.matchAll(/[\w.-]+\.(?:exe|dll|bin|elf|so|dylib|apk|ipa|dmg|sys)\b/gi)) out.add(m[0]);
			return [...out].sort().slice(0, 50);
		}
		case "cloud-security": {
			const out = new Set<string>(unified());
			for (const m of raw.matchAll(/\barn:(?:aws|acs):[a-z0-9-]*:[a-z0-9-]*:\d{6,}:[\w:/.-]+/gi)) out.add(m[0]);
			for (const m of raw.matchAll(/\b(?:aws|aliyun|tencent|huawei)\s*[_-]?\s*(?:account|uid)\s*[=:=]?\s*(\d{8,20})\b|(?:账号|账户)\s*[=:=]?\s*(\d{8,20})\b/gi)) {
				const id = m[1] ?? m[2];
				if (id) out.add("account:" + id);
			}
			for (const m of raw.matchAll(/\b(ap-[a-z]+-\d|cn-[a-z]+[a-z]|us-[a-z]+-\d|eu-[a-z]+-\d)\b/g)) out.add(m[1]);
			return [...out].sort().slice(0, 50);
		}
		case "attack-defense": {
			const out = new Set<string>(unified());
			for (const m of raw.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}\b/g)) {
				const mask = Number(m[0].split("/")[1]);
				if (mask >= 8 && mask <= 32) {
					out.add(m[0]);
					out.delete(m[0].split("/")[0]);
				}
			}
			return [...out].sort().slice(0, 50);
		}
		case "av-evasion":
		case "ctf-solver":
		case "redteam":
			return [];
		default:
			return unified().slice(0, 50);
	}
}

//#endregion

//#region Pi 会话索引（中断恢复的定位件）

interface IndexEntry {
	workspace: string;
	mode?: string;
	goal?: string;
	open?: number;
	at: string;
}
interface StateIndex {
	version: number;
	sessions: Record<string, IndexEntry>;
	last?: IndexEntry;
}

function readIndex(): StateIndex {
	try {
		const idx = JSON.parse(fs.readFileSync(INDEX_FILE, "utf8")) as StateIndex;
		if (idx && typeof idx === "object" && idx.sessions && typeof idx.sessions === "object") return idx;
	} catch {
		/* 首次运行/损坏都按空索引 */
	}
	return { version: 1, sessions: {} };
}

/** 记住「本会话 → 任务工作区」，session_start 恢复时才能找到 operation-state.json。 */
function recordWorkspace(sessionKey: string, workspace: string, st: OperationState | null): void {
	try {
		const idx = readIndex();
		const entry: IndexEntry = {
			workspace,
			mode: st?.mode || undefined,
			goal: st?.goal ? cleanLine(st.goal, 160) : undefined,
			open: Array.isArray(st?.criteria) ? st.criteria.filter((c) => c.status !== "met" && c.status !== "failed").length : undefined,
			at: new Date().toISOString(),
		};
		idx.sessions[sessionKey] = entry;
		idx.last = entry;
		const keys = Object.keys(idx.sessions);
		if (keys.length > 64) for (const k of keys.slice(0, keys.length - 64)) delete idx.sessions[k];
		ensureDir(STATE_DIR);
		fs.writeFileSync(INDEX_FILE, JSON.stringify(idx, null, 2) + "\n");
	} catch {
		/* 索引失败不影响工具结果 */
	}
}

function sessionKeyOf(ctx: ExtensionContext | undefined): string {
	try {
		const id = ctx?.sessionManager?.getSessionId?.();
		if (id) return String(id);
		const file = ctx?.sessionManager?.getSessionFile?.();
		if (file) return path.basename(String(file));
	} catch {
		/* 无会话管理（单测路径） */
	}
	return "unknown";
}

/** mode 解析：显式参数 → operation-state.json 已记录 mode → 无（不注入理论）。 */
function resolveMode(explicit: string | undefined, st: OperationState | null): string {
	const e = String(explicit ?? "").trim();
	if (DECOMPOSITION[e]) return e;
	const s = String(st?.mode ?? "").trim();
	return DECOMPOSITION[s] ? s : "";
}

//#endregion

//#region 输出截断（大输出落全文文件，给模型路径）

const MAX_TEXT_BYTES = 8000;
const MAX_TEXT_LINES = 200;

function packText(label: string, text: string): string {
	const t = truncateHead(text, { maxBytes: MAX_TEXT_BYTES, maxLines: MAX_TEXT_LINES });
	if (!t.truncated) return text;
	let fullPath = "(全文落盘失败)";
	try {
		ensureDir(LOG_DIR);
		fullPath = path.join(LOG_DIR, `${label}-${new Date().toISOString().replace(/[:.]/g, "-")}.txt`);
		fs.writeFileSync(fullPath, text);
	} catch (e) {
		fullPath = `(全文落盘失败：${String((e as Error)?.message ?? e)})`;
	}
	return `${t.content}\n\n[输出已截断：${t.outputLines}/${t.totalLines} 行、${t.outputBytes}/${t.totalBytes} 字节（上限 ${MAX_TEXT_BYTES} 字节）。全文：${fullPath}，用 read 工具读它]`;
}

function result<T>(text: string, details: T) {
	return { content: [{ type: "text" as const, text }], details };
}

function stamp(): string {
	return new Date().toISOString().replace(/[:.]/g, "-");
}

//#endregion

//#region extension

export default function (pi: ExtensionAPI) {
	const MODE_VALUES = Object.keys(GATES) as [string, ...string[]];
	const modeSchema = Type.Union(MODE_VALUES.map((m) => Type.Literal(m)));

	/** 统一包一层：工作区路径解析 + 会话索引回写 */
	const withState = async (
		ctx: ExtensionContext | undefined,
		workspaceArg: string,
		fn: (workspace: string) => { text: string; details: unknown },
	): Promise<{ content: { type: "text"; text: string }[]; details: unknown }> => {
		const workspace = path.resolve(ctx?.cwd ?? process.cwd(), workspaceArg);
		const out = await withFileMutationQueue(path.join(workspace, STATE_FILE), async () => fn(workspace));
		recordWorkspace(sessionKeyOf(ctx), workspace, readOperationState(fs, workspace));
		return result(out.text, out.details);
	};

	// ── stage_gate ─────────────────────────────────────────────────────────
	pi.registerTool({
		name: "stage_gate",
		label: "stage gate",
		description:
			"Validate a task-workspace stage artifact against the security presets' gate schemas (structural checks: files present/non-empty, required markers, complete table rows, hashed provenance). Call it BEFORE advancing a stage or accepting a finding/report into the final report; the verdict appends to <workspace>/gate-log.md and syncs gate progress into <workspace>/operation-state.json. Structural pass ≠ full pass — the `manual` entries list what reviewers must still judge. 门禁不能自评：未知门/缺 file/前序门未过都会硬性 reject。",
		promptSnippet: "阶段门禁结构校验（八模式 32 道门，判定落 gate-log.md）",
		promptGuidelines: [
			"阶段推进/报告落盘前必须调 stage_gate 拿判定，不得自评门禁已过。",
			"stage_gate 返回的 manual 条目列的是复核员职责，结构通过 ≠ 完整通过。",
		],
		executionMode: "sequential",
		parameters: Type.Object({
			mode: modeSchema,
			stage: Type.String({ description: "Gate id: pentest P1/P2/P3 · code-audit A1/A2/A3 · binary-analysis B0/B1/B2 · attack-defense recon/breach/lateral/persistence/report · av-evasion V1/V3/V2/V4 · incident-response I1..I5 · cloud-security C1..C7 · ctf-solver board/flag" }),
			workspace: Type.String({ description: "Task workspace root (absolute, or relative to cwd)" }),
			file: Type.Optional(Type.String({ description: "Gate-scoped file path (report / chain / verdict log / plan) — required by per-finding gates; a relative path resolves against the workspace" })),
		}),
		async execute(_id, p, _signal, _onUpdate, ctx) {
			const workspace = path.resolve(ctx?.cwd ?? process.cwd(), p.workspace);
			return withState(ctx, p.workspace, (ws) => {
				const st = readOperationState(fs, ws);
				const violation = previousGateViolation(p.mode, p.stage, st);
				if (violation) throw new Error(`门禁顺序硬性 reject：${violation}`);
				const verdict: Verdict = runGate(fs, { mode: p.mode, stage: p.stage, workspace: ws, file: p.file });
				verdict.pendingPrior = pendingPriorGates(p.mode, p.stage, st);
				let logPath = path.join(ws, GATE_LOG);
				try {
					logPath = appendGateLog(ws, verdict);
				} catch {
					/* 审计写失败不翻转型判定 */
				}
				try {
					syncOperationState(ws, verdict);
				} catch {
					/* 状态同步失败不翻转型判定 */
				}
				const head = `stage_gate ${verdict.mode}/${verdict.stage}（${verdict.title}）: ${verdict.pass ? "PASS" : "FAIL"}`;
				const missing = verdict.missing.length ? ` — missing: ${verdict.missing.join(" ; ")}` : "";
				const manual = verdict.manual.length ? ` — manual review still required: ${verdict.manual.join(" ; ")}` : "";
				const prior = verdict.pendingPrior.length ? `\n前序逐产物门未判定（可能确无该类产物，但不得当作已过门）：${verdict.pendingPrior.join(", ")}` : "";
				const text = packText(`stage_gate-${p.mode}-${p.stage}-${verdict.pass ? "pass" : "fail"}`, `${head}${missing}${manual}${prior}\n审计行已落：${logPath}`);
				return { text, details: { ...verdict, gateLog: logPath } };
			});
		},
	});

	// ── gates_list ────────────────────────────────────────────────────────
	pi.registerTool({
		name: "gates_list",
		label: "gates list",
		description: "List the stage-gate schemas: each mode's gates, their canonical workspace files, whether a gate-scoped `file` argument is required, and the manual (reviewer-judged) items. Read this first when a workspace is created or before calling stage_gate.",
		promptSnippet: "列各模式门禁 schema（规范文件名/是否需 file/manual 项）",
		executionMode: "parallel",
		parameters: Type.Object({ mode: Type.Optional(modeSchema) }),
		async execute(_id, p) {
			const value = listGates(p.mode);
			const c = gateCount();
			const head = p.mode
				? `gates_list ${p.mode}：${Object.keys(value[p.mode] ?? {}).length} 道门（全库 ${c.modes} 模式 / ${c.gates} 道门）`
				: `gates_list：${c.modes} 个有门模式 / 共 ${c.gates} 道门 —— ${Object.entries(c.perMode).map(([m, n]) => `${m}=${n}`).join(" · ")}`;
			return result(packText(`gates_list-${p.mode ?? "all"}`, `${head}\n${JSON.stringify(value, null, 2)}`), value);
		},
	});

	// ── operation_goal ────────────────────────────────────────────────────
	pi.registerTool({
		name: "operation_goal",
		label: "operation goal",
		description: "Register the task's goal as a decidable contract into <workspace>/operation-state.json: one-line goal + success criteria (one per line, each independently verifiable). Do this at task start (before the first stage_gate). Criteria close one by one via operation_progress; reports/ output additionally requires every criterion met. The same file powers interruption recovery — a fresh session resumes from it. 按模式拆分准则参考返回体的拆分理论（mode 缺省读状态文件已记录的 mode）；解析出的 mode 会写回 operation-state.json 的 mode 字段，与 stage_gate 共用同一份真值。",
		promptSnippet: "登记目标契约（goal + 可判定准则 g1..gN）",
		promptGuidelines: ["任务开工先 operation_goal 登记可判定目标（再 operation_constraints / operation_scope），不得只写在回复里。"],
		executionMode: "sequential",
		parameters: Type.Object({
			workspace: Type.String({ description: "Task workspace root (absolute, or relative to cwd)" }),
			goal: Type.String({ description: "目标一句话（≤500 字符）" }),
			criteria: Type.String({ description: "成功准则，每行一条（可判定表述，如「getshell 证据：whoami 输出与 evidence 编号」「全量 12 条路由均给出终态」），≤20 条" }),
			mode: Type.Optional(Type.Union([...(Object.keys(DECOMPOSITION) as string[]), ""].map((m) => Type.Literal(m as never)), { description: "预设模式（拆分理论注入用）；缺省读 operation-state.json 已记录的 mode" })),
		}),
		async execute(_id, p, _signal, _onUpdate, ctx) {
			return withState(ctx, p.workspace, (ws) => {
				// mode 先解析后写：解析结果随目标契约一并落盘（见 setGoal 注释）
				const mode = resolveMode(p.mode, readOperationState(fs, ws));
				const st = setGoal(ws, p.goal, p.criteria, mode);
				const prevScope = normalizeScope(readOperationState(fs, ws)).length > 0;
				const scopeDraft = prevScope ? [] : deriveScopeDraft([p.goal, p.criteria], mode);
				const d = mode ? DECOMPOSITION[mode] : undefined;
				const text = `${mode ? `【${mode} 拆分理论】${d?.theory}——准则结构：${d?.criteriaGuide}（例：${d?.example}）。` : ""}目标契约已登记：${st.criteria.length} 条准则（${st.criteria.map((c) => c.id).join(", ")}）。逐条 met 用 operation_progress（met 必带 evidence 指位）；全部 met + 报告门通过后才可写 reports/。${scopeDraft.length ? `下一步（开工三登记）：operation_constraints 登记用户约束（deny/allow）；operation_scope 登记范围分母${d?.scopeSemantics ? `（${d.scopeSemantics}）` : ""}——草稿已从目标提取：${scopeDraft.join("、")}（确认或改，保守派生只取精确形态不放大）。` : "下一步：operation_constraints 登记用户约束、operation_scope 登记范围分母（登记即激活对账/推进/门禁）。"}`;
				return { text, details: { ok: true, total: st.criteria.length, ids: st.criteria.map((c) => c.id), scopeDraft, mode, theory: d?.theory } };
			});
		},
	});

	// ── operation_progress ────────────────────────────────────────────────
	pi.registerTool({
		name: "operation_progress",
		label: "operation progress",
		description: "Close or reopen goal-contract criteria in <workspace>/operation-state.json (registered via operation_goal), and maintain the pending-actions list / scope tested / intent closure. `met` ids MUST carry an evidence pointer in `evidence`（硬性 reject：没指位不算 met）. Returns the open/remaining summary; verdict=all-met means the contract is fully satisfied.",
		promptSnippet: "准则逐条 met/failed/reopened + 待办/tested/意图收口",
		executionMode: "sequential",
		parameters: Type.Object({
			workspace: Type.String({ description: "Task workspace root" }),
			met: Type.Optional(Type.String({ description: "已达成准则 id（逗号/空格分隔，如 g1 g3）——需带 evidence" })),
			failed: Type.Optional(Type.String({ description: "证伪准则 id（该准则按失败收口）" })),
			reopened: Type.Optional(Type.String({ description: "重开准则 id（回 open）" })),
			tested: Type.Optional(Type.String({ description: "标记已测的 scope id（逗号/空格分隔；须先 operation_scope 登记）" })),
			evidence: Type.Optional(Type.String({ description: "证据指位（met / tested 必填：evidence 编号/覆盖矩阵行/输出文件路径）" })),
			pending: Type.Optional(Type.String({ description: "待办动作清单（整表替换，每行一条；空串=清空）" })),
			note: Type.Optional(Type.String({ description: "进度注记（≤500 字符；intent blocked/dropped 收口必填原因）" })),
			intent_done: Type.Optional(Type.String({ description: "有产出收口的意图 id" })),
			intent_blocked: Type.Optional(Type.String({ description: "受阻终态的意图 id（需 note 说明依据）" })),
			intent_dropped: Type.Optional(Type.String({ description: "放弃的意图 id（需 note 说明理由）" })),
		}),
		async execute(_id, p, _signal, _onUpdate, ctx) {
			return withState(ctx, p.workspace, (ws) => {
				const summary = updateProgress(ws, p) as Record<string, unknown>;
				if (p.tested) summary.coverage = markTested(ws, p.tested, String(p.evidence ?? ""));
				const openIds = (summary.openIds as string[] | undefined) ?? [];
				const cov = summary.coverage as ReturnType<typeof scopeSummary> | undefined;
				const its = summary.intents as ReturnType<typeof intentSummary> | undefined;
				const text = `operation 进度：met ${summary.met}/${summary.total}${openIds.length ? `，未收口 ${openIds.join(", ")}` : ""}${(summary.pending as string[])?.length ? `，待办 ${(summary.pending as string[]).length} 项` : ""}${cov ? `，覆盖 ${cov.tested}/${cov.scope}${cov.untested ? `（未测 ${cov.untestedIds.slice(0, 8).join(", ")}${cov.untested > 8 ? " 等" : ""}）` : ""}` : ""}${its?.total ? `，意图 ${its.open}/${its.total} 未收口` : ""}——${summary.verdict === "all-met" ? "目标契约已全部达成" : "收口后才可产出 reports/"}`;
				return { text, details: { ok: true, ...summary } };
			});
		},
	});

	// ── operation_scope ───────────────────────────────────────────────────
	pi.registerTool({
		name: "operation_scope",
		label: "operation scope",
		description: "Register the task's coverage denominator into <workspace>/operation-state.json (after operation_goal): one scope item per line (a bare label auto-ids s1..sN; 'id: label' pins the id). 最小范围原则：只登记目标明确点到或派生必需的面，绝不擅自放大. Once registered, the mode's report gate runs arithmetic reconciliation: the report/coverage matrix must declare 「覆盖：M/N」matching the ledger (tested marked via operation_progress tested+evidence; honest partial coverage passes, inflated or missing declarations fail).",
		promptSnippet: "登记覆盖度分母（范围台账，报告门据此对账）",
		executionMode: "sequential",
		parameters: Type.Object({
			workspace: Type.String({ description: "Task workspace root" }),
			items: Type.String({ description: "范围项，每行一条（标签 或 id: 标签），≤200 项——如「10.0.0.5 Web 前台\n10.0.0.6 API 网关\ndb: 数据库面」" }),
			mode: Type.Optional(Type.String({ description: "预设模式（分母语义提示用）；缺省读状态文件已记录 mode" })),
		}),
		async execute(_id, p, _signal, _onUpdate, ctx) {
			return withState(ctx, p.workspace, (ws) => {
				const s = setScope(ws, p.items);
				const mode = resolveMode(p.mode, readOperationState(fs, ws));
				const sem = mode ? DECOMPOSITION[mode]?.scopeSemantics : undefined;
				return { text: `${sem ? `【${mode} 分母语义】${sem}。` : ""}范围台账已登记：${s.scope} 项（已测 ${s.tested}${s.untested ? `，未测 ${s.untestedIds.slice(0, 10).join(", ")}${s.untested > 10 ? " 等" : ""}` : ""}）。已测标记：operation_progress tested=<ids> evidence=<指位>；报告门将按台账对账「覆盖：${s.tested}/${s.scope}」。`, details: { ok: true, ...s, mode } };
			});
		},
	});

	// ── operation_constraints ──────────────────────────────────────────────
	pi.registerTool({
		name: "operation_constraints",
		label: "operation constraints",
		description: "Register the task's operational constraints (deny/allow) into <workspace>/operation-state.json（开工三登记之三）：用户口头约束的结构化落地——不碰生产库/只测某子域/禁止爆破等，压缩后仍在台账可见。行格式 `deny: 文本` 或 `allow: 文本`，可选匹配词 `deny: 文本 :: kw1,kw2`。约束自包含写死具体值；只登记用户明确说出的约束，严禁臆造；拿不准 kind 用 deny（保守）。整表替换重登记。",
		promptSnippet: "登记用户约束台账（deny/allow，可选匹配词）",
		executionMode: "sequential",
		parameters: Type.Object({
			workspace: Type.String({ description: "Task workspace root" }),
			items: Type.String({ description: "约束条目，每行一条：`deny: 不碰支付接口 :: pay,payment,refund`、`allow: 仅测 x.example.com`——≤30 条" }),
			mode: Type.Optional(Type.String({ description: "预设模式（约束面提示用）；缺省读状态文件已记录 mode" })),
		}),
		async execute(_id, p, _signal, _onUpdate, ctx) {
			return withState(ctx, p.workspace, (ws) => {
				const s = setConstraints(ws, p.items);
				const mode = resolveMode(p.mode, readOperationState(fs, ws));
				const hints = mode ? DECOMPOSITION[mode]?.constraintHints : undefined;
				return { text: `${hints ? `【${mode} 约束面提示】${hints}。` : ""}约束已登记：${s.total} 条（禁 ${s.deny}·含匹配词 ${s.denyGuarded} / 允 ${s.allow}）——${s.lines.slice(0, 5).join("；")}。全部约束在台账，压缩不丢；确定性拦截由 dsh-sec-enforce 移植件消费。`, details: { ok: true, ...s, mode } };
			});
		},
	});

	// ── operation_intent ───────────────────────────────────────────────────
	pi.registerTool({
		name: "operation_intent",
		label: "operation intent",
		description: "Register a direction/intent with a mandatory evidence anchor：开新方向（子代理派单/阶段切换/追一条线索）前登记，防凭空规划——方向只能锚在已确立的证据上。anchor：boot=开局/顶层全新方向豁免｜criterion=目标准则 id（g1..）｜scope=范围项 id（s1..）｜finding=本会话成果 id（如 pentest-3）｜chain=本会话链路节点 id。收口走 operation_progress（intent_done/intent_blocked/intent_dropped，blocked/dropped 须 note 原因）。凭空开方向（无锚）是审计红旗。",
		promptSnippet: "登记方向带证据锚（意图台账，防凭空规划）",
		executionMode: "sequential",
		parameters: Type.Object({
			workspace: Type.String({ description: "Task workspace root" }),
			summary: Type.String({ description: "一句话方向（做什么、追什么线索）≤200 字符" }),
			anchor_kind: Type.Union((ANCHOR_KINDS as readonly string[]).map((k) => Type.Literal(k as never)), { description: "锚点类型（boot=开局豁免，其余须带 anchor_ref）" }),
			anchor_ref: Type.Optional(Type.String({ description: "锚点 id（boot 省略；criterion/scope/finding/chain 必填）" })),
			note: Type.Optional(Type.String({ description: "备注（派单对象/预期产出等 ≤300 字符）" })),
		}),
		async execute(_id, p, _signal, _onUpdate, ctx) {
			return withState(ctx, p.workspace, (ws) => {
				// Pi 侧无 dsh-redteam-results / dsh-attack-atlas 跳库 store：finding/chain 锚走格式校验降级（原实现解析器不可达时同路）
				const r = registerIntent(ws, { summary: p.summary, anchorKind: p.anchor_kind, anchorRef: p.anchor_ref, note: p.note }, {});
				return { text: `意图已登记：${r.id}（锚=${p.anchor_kind}${p.anchor_ref ? ":" + p.anchor_ref : ""}）。收口：operation_progress intent_done/intent_blocked/intent_dropped（blocked/dropped 附原因）。当前 ${r.open}/${r.total} 未收口。`, details: { ok: true, ...r } };
			});
		},
	});

	// ── 中断恢复：从 operation-state.json 重建未完成目标 ────────────────
	pi.on("session_start", async (event, ctx) => {
		try {
			const key = sessionKeyOf(ctx);
			const idx = readIndex();
			let entry = idx.sessions[key];
			let stale = false;
			if (!entry && (event.reason === "startup" || event.reason === "new" || event.reason === "resume") && idx.last) {
				const ageH = (Date.now() - Date.parse(idx.last.at)) / 3600_000;
				if (ageH <= RESUME_TTL_HOURS) {
					entry = idx.last;
					stale = true;
				}
			}
			if (!entry?.workspace) return;
			const st = readOperationState(fs, entry.workspace);
			if (!st) return;
			const openCrit = (st.criteria ?? []).filter((c) => c.status !== "met" && c.status !== "failed").map((c) => c.id);
			const openIntents = normalizeIntents(st).filter((i) => i.status === "open").map((i) => i.id);
			const failGates = Object.entries(st.gates ?? {}).filter(([, g]) => !g.pass).map(([k]) => k);
			const pending = (st.pending ?? []).slice(0, 6);
			if (!openCrit.length && !openIntents.length && !failGates.length && !pending.length) return;
			const cov = scopeSummary(st);
			const lines = [
				`【阶段门禁恢复】${stale ? `近 ${RESUME_TTL_HOURS}h 内上次任务（仅当本次是它的续作时适用）` : "本会话中断前"}——工作区 ${entry.workspace}${st.mode ? `（模式 ${st.mode}）` : ""}`,
				st.goal ? `目标契约：${cleanLine(st.goal, 200)}` : "",
				`未收口准则：${openCrit.join(", ") || "无"}；已测/范围：${cov.tested}/${cov.scope}；未过门：${failGates.join(", ") || "无"}；未收口意图：${openIntents.join(", ") || "无"}`,
				pending.length ? `待办：${pending.join(" / ")}` : "",
				`继续：先读 ${entry.workspace}/${GATE_LOG} 与 ${STATE_FILE}，从 operation_progress 收口准则 / stage_gate 重判未过门接着做；不要重跑已完成阶段。若用户本次提的是新任务（与该工作区无关），忽略本提示，改用 operation_goal 开新契约。`,
			].filter(Boolean);
			const text = lines.join("\n");
			pi.appendEntry("stage-gate-resume", { workspace: entry.workspace, mode: st.mode, openCrit, openIntents, failGates, pending, at: new Date().toISOString() });
			if (ctx.mode === "tui") ctx.ui.setWidget("stage-gate", [lines[0]]);
			ctx.ui.notify(lines[0], "info");
			pi.sendMessage({ customType: "stage-gate-resume", content: text, display: false, details: { workspace: entry.workspace } }, { triggerTurn: false, deliverAs: "nextTurn" });
		} catch {
			/* 恢复提示绝不阻断会话启动 */
		}
	});

	pi.on("session_shutdown", async () => {
		/* 无常驻资源（无 DB/定时器/子进程）；幂等注：索引与日志都在磁盘，无需释放 */
	});

	// ── /gates：门数核对表（写 markdown，避开无 UI 模式）───────────────
	pi.registerCommand("gates", {
		description: "八模式 32 道阶段门清单（门数核对表 + 规范文件 + 是否需 file）",
		handler: async (args, ctx) => {
			const only = args.trim();
			const c = gateCount();
			const rows: string[] = [`| 模式 | 门 | 标题 | 规范文件 | 需 file | manual 项 |`, `|---|---|---|---|---|---|`];
			for (const [m, stages] of Object.entries(GATES)) {
				if (only && m !== only) continue;
				for (const [s, g] of Object.entries(stages)) {
					const files = [...new Set(g.checks.filter((x) => x.file && x.file !== "$file").map((x) => String(x.file)))].join(" / ") || (g.checks.some((x) => x.dir) ? `${g.checks.find((x) => x.dir)?.dir}/*/provenance.md` : "（仅 file 参数）");
					rows.push(`| ${m} | ${s} | ${g.title} | ${files} | ${g.requiresFile ? "是（" + (g.fileHint ?? "") + "）" : "否"} | ${g.manual.length} |`);
				}
			}
			const md = `# 阶段门禁清单（${c.modes} 模式 / ${c.gates} 道门）\n\n逐模式：${Object.entries(c.perMode).map(([m, n]) => `${m}=${n}`).join("、")}\n\n${rows.join("\n")}\n`;
			let file = path.join(LOG_DIR, `gates-${stamp()}.md`);
			try {
				ensureDir(LOG_DIR);
				fs.writeFileSync(file, md);
			} catch {
				file = "(写盘失败)";
			}
			ctx.ui.notify(`${c.modes} 模式 / ${c.gates} 道门——清单已写：${file}`, "info");
			if (ctx.mode === "tui") ctx.ui.setWidget("stage-gate-gates", md.split("\n").slice(0, 40));
		},
	});
}

//#endregion
