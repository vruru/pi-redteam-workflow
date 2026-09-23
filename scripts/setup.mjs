#!/usr/bin/env node
/*
 * pi-redteam-workflow 安装后设置脚本（幂等，可反复跑）。
 *
 *   node scripts/setup.mjs                 # 建仓库符号链接 + 合并 MCP 配置
 *   node scripts/setup.mjs --check         # 只报告，不写任何东西
 *   node scripts/setup.mjs --with-kali-mcp # 额外为 kali-mcp-server 建 venv 并装依赖（需联网）
 *   node scripts/setup.mjs --overwrite-mcp # 同名 server 也覆盖（默认保留用户已有条目）
 *
 * 为什么需要这一步：14 个扩展按 `~/.pi/agent/redteam-model` 读取模式门禁 schema、
 * refs 知识库与 semgrep 规则集（这是上游布局的既有约定）。本脚本把该路径符号链接到
 * 包内 data/redteam-model，包升级后链接自动跟随，无需改动任何扩展源码。
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const AGENT_DIR = process.env.PI_CODING_AGENT_DIR || path.join(os.homedir(), ".pi", "agent");
const REPO_LINK = path.join(AGENT_DIR, "redteam-model");
const REPO_DATA = path.join(PKG_ROOT, "data", "redteam-model");
const MCP_TEMPLATE = path.join(PKG_ROOT, "mcp", "recommended.json");
const MCP_TARGET = path.join(AGENT_DIR, "mcp.json");

const argv = process.argv.slice(2);
const CHECK = argv.includes("--check");
const WITH_KALI = argv.includes("--with-kali-mcp");
const OVERWRITE_MCP = argv.includes("--overwrite-mcp");

const log = (m) => console.log(m);
const step = (m) => log(`\n${m}`);

function ensureRepoLink() {
  step("1/3 仓库符号链接  ~/.pi/agent/redteam-model");
  if (!fs.existsSync(REPO_DATA)) { log(`   ✗ 包内缺少 ${REPO_DATA}（包内容不完整？）`); return false; }
  let st = null;
  try { st = fs.lstatSync(REPO_LINK); } catch { /* 不存在 */ }
  if (!st) {
    if (CHECK) { log("   · 待创建"); return true; }
    fs.symlinkSync(REPO_DATA, REPO_LINK, "junction");
    log(`   ✓ 已创建 → ${REPO_DATA}`);
    return true;
  }
  if (st.isSymbolicLink()) {
    const cur = fs.readlinkSync(REPO_LINK);
    if (path.resolve(path.dirname(REPO_LINK), cur) === REPO_DATA) { log("   ✓ 已正确指向本包，无需改动"); return true; }
    if (CHECK) { log(`   · 现指向 ${cur}，将改为指向本包`); return true; }
    fs.unlinkSync(REPO_LINK);
    fs.symlinkSync(REPO_DATA, REPO_LINK, "junction");
    log(`   ✓ 已改指向本包（原指向 ${cur}）`);
    return true;
  }
  log(`   ⚠ 该路径已是一个真实目录（你自己的 redteam-model 仓库？），未触碰。`);
  log(`     扩展会继续读它；若想让本包接管，请先自行改名后再跑一次。`);
  return true;
}

function mergeMcp() {
  step("2/3 MCP 配置合并  ~/.pi/agent/mcp.json");
  if (!fs.existsSync(MCP_TEMPLATE)) { log("   ✗ 缺少 mcp/recommended.json"); return false; }
  const tpl = JSON.parse(fs.readFileSync(MCP_TEMPLATE, "utf8"));
  const fix = (v) => JSON.parse(JSON.stringify(v).replaceAll("{{HOME}}", os.homedir()));
  let cur = { mcpServers: {} };
  if (fs.existsSync(MCP_TARGET)) {
    try { cur = JSON.parse(fs.readFileSync(MCP_TARGET, "utf8")); } catch (e) { log(`   ✗ 现有 mcp.json 解析失败：${e.message}；未改动`); return false; }
  }
  cur.mcpServers = cur.mcpServers || {};
  const added = [], kept = [], over = [];
  for (const [name, val] of Object.entries(tpl.mcpServers || {})) {
    if (Object.prototype.hasOwnProperty.call(cur.mcpServers, name)) {
      if (OVERWRITE_MCP) { cur.mcpServers[name] = fix(val); over.push(name); }
      else kept.push(name);
    } else { cur.mcpServers[name] = fix(val); added.push(name); }
  }
  if (CHECK) {
    log(`   · 将新增 ${added.length} 个：${added.join(", ") || "无"}`);
    log(`   · 已存在保留 ${kept.length} 个：${kept.join(", ") || "无"}`);
    return true;
  }
  if (added.length || over.length) {
    if (fs.existsSync(MCP_TARGET)) {
      const bak = `${MCP_TARGET}.bak-${Date.now()}`;
      fs.copyFileSync(MCP_TARGET, bak);
      log(`   · 已备份原配置 → ${bak}`);
    }
    fs.mkdirSync(path.dirname(MCP_TARGET), { recursive: true });
    fs.writeFileSync(MCP_TARGET, JSON.stringify(cur, null, 2) + "\n");
  }
  log(`   ✓ 新增 ${added.length} 个：${added.join(", ") || "无"}`);
  if (over.length) log(`   ✓ 覆盖 ${over.length} 个：${over.join(", ")}`);
  if (kept.length) log(`   · 保留你已有条目 ${kept.length} 个：${kept.join(", ")}（要覆盖请加 --overwrite-mcp）`);
  const enabled = Object.entries(cur.mcpServers).filter(([, v]) => !v?.disabled).map(([k]) => k);
  log(`   · 当前启用：${enabled.join(", ") || "（全停用）"}`);
  log(`     面板类 MCP（idapro/ghidra/burpsuite/reqable-mcp/anything-analyzer）依赖外部软件，用 /mcp enable <名字> 后再 /reload。`);
  return true;
}

function kaliVenv() {
  step("3/3 kali-mcp-server 依赖（可选）");
  if (!WITH_KALI) { log("   · 未要求安装（跳过）。需要时加 --with-kali-mcp"); return true; }
  const req = path.join(REPO_DATA, "deploy/assets/kali-mcp-server/requirements.txt");
  const venv = path.join(REPO_DATA, ".venv-kali");
  if (!fs.existsSync(req)) { log(`   ✗ 找不到 ${req}`); return false; }
  if (CHECK) { log(`   · 将创建 ${venv} 并安装 requirements（含 mcp<2 修正）`); return true; }
  const py = spawnSync("python3", ["-m", "venv", venv], { encoding: "utf8" });
  if (py.status !== 0) { log(`   ✗ python3 -m venv 失败：${(py.stderr || py.stdout).slice(0, 300)}`); return false; }
  const vpi = path.join(venv, "bin", "pip");
  // 上游 requirements.txt 写的是 mcp>=1.0.0，但代码用 mcp.server.fastmcp（mcp 2.x 已改名）→ 必须钉住 1.x
  const r1 = spawnSync(vpi, ["install", "-q", "-r", req, "mcp<2"], { encoding: "utf8" });
  if (r1.status !== 0) { log(`   ✗ pip 安装失败：${(r1.stderr || r1.stdout).slice(0, 400)}`); return false; }
  log("   ✓ venv 就绪（已钉 mcp<2），MCP 里 kali-mcp-server 可直接启用");
  return true;
}

function selfCheck() {
  step("自检");
  const ext = fs.readdirSync(path.join(PKG_ROOT, "extensions")).filter((f) => f.endsWith(".ts"));
  const counts = { reverse: 0, model: 0 };
  for (const f of ext) if (f.startsWith("dsh-")) counts.model++;
  const skillRoots = ["skills/reverse-skill", "skills/redteam-model"].map((p) => path.join(PKG_ROOT, p));
  let skillFiles = 0;
  const walk = (d) => {
    let e; try { e = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    if (e.some((x) => x.name === "SKILL.md")) { skillFiles++; return; }
    for (const x of e) {
      if (x.name.startsWith(".") || x.name === "node_modules") continue;
      const full = path.join(d, x.name);
      if (x.isDirectory() || x.isSymbolicLink()) walk(full);
    }
  };
  for (const p of skillRoots) walk(p);
  log(`   扩展：${ext.length} 件（其中 dsh-* 移植件 ${counts.model} 件）`);
  log(`   技能根：${skillFiles} 个（.disabled/ 内的赛道与重名技能不计入 Pi 名录）`);
  log(`   仓库数据：${fs.existsSync(REPO_DATA) ? "在包内" : "缺失"}`);
}

let ok = true;
ok = ensureRepoLink() && ok;
ok = mergeMcp() && ok;
ok = kaliVenv() && ok;
selfCheck();
step(CHECK ? "检查完成（未写入任何文件）" : "完成");
log(CHECK
  ? "  去掉 --check 即可实际执行。"
  : "  最后一步：在 Pi 里执行  /reload  —— 技能、扩展与 MCP 都会生效。\n  验证：/modes 列十个模式入口、/gates 列 32 道阶段门、/mcp-doctor 给全部 MCP 做体检。");
process.exit(ok ? 0 : 1);
