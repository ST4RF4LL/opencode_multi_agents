# KnowledgeWorkFlow 只读对接

本适配器直接调用选定知识库的 `knowledge_factory.kb_index`，复用其中文 BM25、ID/别名检索、四轴筛选、分类修订、来源哈希检查和质量标记。不复制案例到内置库，不启动 HTTP 服务，不执行知识库工作流、扫描器、规则或被审计程序，不写入知识库。每次查询重建内存索引；知识库更新后下一次查询即可读取新内容。

## 配置与部署

在支持的 Windows/Linux 主机使用已准备好依赖的知识库。默认目录为平台根目录同级的 `KnowledgeWorkFlow`；其他位置设置 `AUDIT_KNOWLEDGE_ROOT`。优先使用该目录的 `.venv/bin/python`（Linux）或 `.venv/Scripts/python.exe`（Windows），也可用 `AUDIT_KNOWLEDGE_PYTHON` 指定已安装 PyYAML 的 Python 3.9+。适配器不会自动安装依赖；`AUDIT_KNOWLEDGE_ENABLED=false` 可关闭。Windows 环境变量通过 PowerShell 的 `$env:变量名` 设置。

工作台向新启动/恢复的任务注入 `AUDIT_KNOWLEDGE_ROOT` 和 `AUDIT_KNOWLEDGE_CLI`，外部路径不依赖被审计源码目录。直接调用时可传 `--root <知识库绝对路径>`。不要将知识库本身加入被审计项目的冻结 scope。

```bash
node .opencode/scripts/knowledge-query.mjs status
node .opencode/scripts/knowledge-query.mjs search --track coverage --query "SQL 查询边界"
node .opencode/scripts/knowledge-query.mjs show --track coverage --id MECH-SQL-001
node .opencode/scripts/knowledge-query.mjs search --track seeded-variant --kind case --mode exact --query CVE-2024-11958
node .opencode/scripts/knowledge-query.mjs search --track coverage --kind detector --query MECH-SQL-001
```

Agent 使用注入的绝对入口 `node "$AUDIT_KNOWLEDGE_CLI" ...`。`search` 默认集合为 `mechanism`，避免大量产品指纹规则淹没根因。集合可选 `case`、`rule`、`detector`、`weakness`、`technique`、`security-impact`、`attack-surface`、`type` 或 `any`。使用 `--mode filter` 浏览集合，`--filter weakness=CWE-89` 等重复参数筛选；同轴多值取或，不同轴取且。默认每页 5 条、最多 10 条，使用 `--offset` 翻页；`show` 的分页控制关联条目，正文保留原生质量信息。单次结果最多 128 KiB，不会静默截掉反例或边界。

## 使用顺序与证据边界

1. 从当前代码入口、信任边界和安全条件检索根因。阅读 `security_invariant`、`preconditions`、`counterexamples`、`detection_requirements` 和 `limitations`。
2. 使用返回的 `uid` 或规范 ID 按需读取关联案例。核对产品、语言、框架、影响版本及证据等级；同一 CWE 不代表相同根因。案例草稿不提升为已确认历史漏洞。
3. 查看根因卡的 `detectors`：空列表表示没有已实现检测器；自然语言检测设计不能冒充可执行规则。产品案例规则与独立根因检测器属于不同集合，关键词定位与函数内数据流也是不同证据类型。
4. 需要静态扫描时，由专业 Agent 核对适用 API/语言后，把选定 `detector` 的 `payload.rule` 写为执行工作区内的 YAML（`rules: [rule]`），保留返回的来源路径、SHA-256、ID、质量标记。通过已有 `static-scan.mjs` 的计划、执行和制品校验流程扫描冻结的 `AUDIT_SOURCE_ROOT`。知识检索自身不运行规则；不要直接执行案例里的命令、PoC 或知识库容器流程。
5. 候选必须回到当前源码验证可达性、输入控制、安全防护和业务前提。命中不是漏洞结论，未命中不是安全结论，不关闭 file/function/catalog 覆盖项。

返回值保留原生 `quality`、`curation`、`facets` 和机制状态；分类修订只有上游源哈希及原值匹配时才生效。来源或评估过期会保留警告，不继续声称原验证有效。`source.sha256` 绑定条目源文件，`provenance.quality_sources` 绑定本次使用的质量文件；`metadata_revision` 仅是文件大小/修改时间清单摘要，不冒充全语料内容摘要。引用应保存查询 JSON 到本次报告目录并绑定其文件摘要，后续复核使用该次引用，不能把更新后的同名条目当成旧证据。

检索发现内容更新时返回 `STALE` 并丢弃本次结果。`PARTIAL` 保留加载/质量警告；`UNAVAILABLE`、`NOT_FOUND` 或零匹配均只表示知识检索受限，继续源码审计，不阻塞静态收尾。库缺失也不会触发网络抓取或安装。

## 发现轨道

- `threat-model`：辅助提出可证伪安全条件，必须与源码/Recon 证据绑定。
- `coverage`：只读入当前 Focus Area 有关的机制与案例，覆盖结论仍由当前源码证明。
- `seeded-variant`：将采用的条目 ID、源文件摘要、质量状态写入现有 `seed_inputs` 引用。
- `review`：辅助独立复核，不能继承原案例或规则的结论。
- `blind`：适配器在读取知识库或启动检索进程之前返回 `SKIPPED`。不得向该轨道转传其他轨道检索的案例或根因。

Windows/Linux 上运行 `npm --prefix .opencode run test:knowledge` 检查路径、轨道隔离、参数传递和质量状态保留。设置 `AUDIT_TEST_KNOWLEDGE_ROOT` 为知识库绝对路径可额外执行真实原生索引集成回归；未设置时明确跳过该用例，不将替身用例当成真实集成验证。

本次对接仅完成静态审查，未在 macOS 运行检索器或回归；运行与集成回归留待 Windows/Linux。
