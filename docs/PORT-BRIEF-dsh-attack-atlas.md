# dsh-attack-atlas → Pi 移植简报（父代理侦察结论，照此实施）

## 关键发现：上游三个核心模块可被 Node 直接 import，**不要重写它们**

已实测（`node --input-type=module -e "await import(...)"`）：

| 上游文件 | 行数 | 依赖 | 结论 |
|---|---|---|---|
| `lib/taxonomy.js` | 1830 | **零依赖** | ✅ 直接 import，导出 `ATLAS_MODES` `CELL_STATES` `STAGE_STATES` `TAXONOMIES` `itemsInForm` `locate` `refPaths` `validateTaxonomy` |
| `lib/store.js` | 652 | 仅 `node:fs` `node:path` `node:sqlite` | ✅ 直接 import（导出见下） |
| `lib/method.js` | 215 | 仅 `./taxonomy.js` | ✅ 直接 import |
| `lib/index.js` | 1268 | `@deepseek-ai/dsh-tools` 等 | ❌ 这是 Cordis 接线层，**只有这一层需要按 Pi API 重写** |
| `lib/client.js` | 1678 | `react` | ❌ 纯前端，按约定第 6 条整体放弃 |

导入方式：`const tax = await import("file://" + path.join(os.homedir(), ".pi/agent/redteam-model/plugins/dsh-attack-atlas/lib/taxonomy.js"))`
（Pi 用 jiti 跑 TS，动态 import 绝对 file:// URL 可行；**不要**把 taxonomy 的 1830 行常量抄进你的文件。）

## 已确认的数据模型（不要自己发明）

- `ATLAS_MODES`（8 个）：pentest, code-audit, binary-analysis, attack-defense, av-evasion, incident-response, cloud-security, ctf-solver
- **矩阵四态** `CELL_STATES`：`tested-found` / `tested-clear` / `na` / `budget-stop`（另有中文 `stateLabels`、`stateShort` 在 TAXONOMIES 内）
- **阶段带** `STAGE_STATES`：`active` / `done`
- `TAXONOMIES[mode]` 顶层键：`label, stages, forms, stateLabels, stateShort, formCategories, categories`
  - 例 pentest：stages 7 条（s0 防护画像 → s6 验证与影响证明）、forms 9 条、categories 14 条；全库约 955 个 label 条目
- store 表（8 张，字段名以 store.js 为准，别改）：
  - `coverage(session_id, mode, target, key, state, reason, finding_refs, updated_at)` PK(session_id,mode,target,key)
  - `stages(session_id, mode, target, stage, state, updated_at)`
  - `targets(session_id, mode, seq, label, kind, note, active, created_at)`
  - `chain_nodes(session_id, mode, target, id, label, kind, seg, note, major, finding_ref, created_at)`
  - `chain_edges(session_id, mode, target, src, dst, label, edge_type, created_at)`
  - `methods(id, mode, name, target, notes, graph, created_at, updated_at)`
  - `capabilities(id, mode, kind, cat, item, label, descr, template, ref, pb, forms, created_at, updated_at)`
  - `misses(id, mode, kind, query, error, session_id, created_at)`
- store.js 导出（直接就是你要暴露的工具语义）：
  `addTarget listTargets getActiveTarget markCell getCoverage clearCoverage markStage addTarget chain 系列(addChainNode addChainNode listChain clearChain chainKindLabel chainRefIndex) methods 系列(getMethod listMethods copyMethod importMethods exportMethods) capabilities 系列(listCaps addCap? importCaps exportCaps) validateTaxonomy itemsInForm locate refPaths METHOD_LIMITS NODE_TYPES inferTargetKind normalizeGraph validateMethod layerMethod`

## 你要写的东西（只有接线层）

1. 打开 store：确认 store.js 的 open/init 函数签名是否接受 DB 路径（它 import 了 node:fs/node:path，极可能接受路径参数）。
   **Pi 侧必须落 `~/.pi/redteam/dsh-attack-atlas/atlas.db`，不要用 `~/.dsh/`。** 若签名不接受路径，用最小适配层（复制 store.js 到 `~/.pi/redteam/dsh-attack-atlas/` 后仅改路径常量，并在报告里说明你抄了它）。
2. 注册模型工具，语义对齐 store 导出（命名保持 dsh 可辨识，且不得与现有移植件重名——先 grep）：
   目标锚定（add/list/activate target，覆盖态按目标分账）、`markCell`（点亮矩阵格，**必须强制 finding_refs 或 reason 非空才允许 tested-found**，把"发现≠已验证"做成代码校验）、`markStage`、`getCoverage`（含按目标/聚合两种视图）、链路拓扑（add node/edge/list/clear）、自定义工作方法论（getMethod/listMethods/copyMethod，用 method.js 的 `normalizeGraph`/`validateMethod`/`METHOD_LIMITS` 做校验）、能力库（listCaps/importCaps/exportCaps 支持自定义主类/子类并入）。
3. 一条命令输出矩阵与阶段带：markdown 文件 + 精简文本表格两种，全文路径给出来；`ctx.mode === "tui"` 才尝试 setWidget/状态行，`--print` 模式必须纯文本可用。
4. 派单语义：工具返回「建议的下一步」文本，**绝不自动执行扫描或打目标**。

## 阅读纪律（上一个实现者就是爆在 262k 上下文上）

- **禁止 cat 全文**：taxonomy.js(1830) + store.js(652) + index.js(1268) + client.js(1678) 一次读全量 ≈ 直接超窗。
- 先用 `grep -n` 定位，再 `read` 带 offset/limit 取局部：store.js 只需读 open/建表与你要用的那些导出函数体；index.js 只需读它的工具注册段（找 `name:` / `schema` / handler 形态）与它对 coverage/method 的校验逻辑；**client.js 完全不用读**。
- 遇到不确定的字段语义，优先跑 `node --input-type=module -e` 实际调用验证，而不是猜。
