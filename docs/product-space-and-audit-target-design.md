# 产品空间与测试对象管理详细设计

状态：设计稿；P0/P1 基础实现进行中，尚未完成 Windows/Linux 验收。日期：2026-09-11。修订：R3（评审问题 H1–H7、M1–M15、L1–L8 及首轮实现记录）。

本文整合产品空间、内置“未定义”产品、测试对象升级和查询性能要求。已有行为以当前源码为依据；新增模型、接口、性能指标和实施阶段均为拟议方案，不表示已经交付。

## 1. 目标与设计结论

产品空间负责业务归属，测试对象负责定义源码范围，审计任务负责一次执行。一个产品有多个对象，一个对象有多次任务；一个对象可以包含普通源码目录、仓库中的组件目录，或多个联合审计目录。

必须达到以下结果：

1. 不同产品拥有独立的对象、任务、漏洞、报告及动态验证视图。
2. 历史数据和不涉及具体产品的临时审计进入内置“未定义”产品。
3. Git 不再是登记、就绪、启动或恢复审计的强制条件。branch/tag 可以作为人工版本备注，不强制解析，不自动 checkout。
4. 用户选择的目录和范围规则决定审计边界，不由 Git 跟踪状态或仓库根目录替代。
5. 多目录审计在一个任务中处理，支持跨范围的证据关联和攻击链分析。
6. 按产品查询不扫描其他产品；切换空间不显示旧产品请求返回的数据。
7. 老对象、任务、漏洞资源标识、报告下载标识和已封存制品保持兼容。

本轮不引入源码上传、Git 克隆及更新、历史提交分析、远程部署、容器执行、团队成员及 RBAC。产品空间首先是业务数据分区，不等同于多租户权限隔离。环境、模型配置、执行器和总并发队列仍属于平台级资源。

## 2. 当前实现与改造原因

| 当前事实 | 对新模型的影响 |
|---|---|
| 网页登记名称与一个主机绝对路径，项目 ID 由路径哈希生成 | 对象需要稳定 ID，并支持多个范围；路径不能继续充当产品身份 |
| 登记信息存入 `repositories.json`，启动参数也可登记项目 | 需要统一读取旧来源并建立归属，保留来源限制 |
| 任务与 `repository_id`、单个 commit、`AUDIT_SOURCE_ROOT` 绑定 | 任务与审计契约需要显式支持多范围和无 Git 输入 |
| 漏洞、报告等由受控制品聚合，标识中存在仓库作用域 | 新归属不能改变旧标识和制品摘要 |
| 列表显示使用短期工作区缓存，冷加载仍聚合全局制品 | 产品化要引入可按归属查询的摘要目录，不能仅给全局快照加过滤 |
| 项目没有编辑、归档、详情和产品切换 | 新增对象生命周期与空间导航 |

主要代码入口：

- [audit-runner.mjs](../.opencode/web/dynamic-validation-observatory/audit-runner.mjs)：对象登记、任务生命周期、路径与源码绑定。
- [server.mjs](../.opencode/web/dynamic-validation-observatory/server.mjs)：资源聚合、接口、操作与事件订阅。
- [workspace-model.mjs](../.opencode/web/dynamic-validation-observatory/workspace-model.mjs)：制品扫描与审计资源派生。
- [app.js](../.opencode/web/dynamic-validation-observatory/public/app.js)：页面状态、列表加载、自动刷新。
- [build-scope-manifest.mjs](../.opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-scope-manifest.mjs)：文件范围枚举及 Git 文件查询。

旧术语与新术语的映射如下。界面迁移完成后不再把测试对象称为仓库；兼容字段名只用于旧数据和旧接口。

| 旧术语/字段 | 新术语 | 关系 |
|---|---|---|
| 审计项目、Repository | 审计对象 `AuditTarget` | 老项目迁移为一个单范围对象 |
| 项目目录、仓库路径 | 源码范围 `SourceScope.path` | 新对象可有一个或多个范围 |
| `repository_id` | `target_id` 的兼容来源 | 老对象保留原 ID；新接口只使用 `target_id` |
| 仓库级安全审计 | 审计任务 `AuditRun` | 可针对组件、普通目录或多个目录 |
| API scope | 产品路径作用域 | 与源码范围 `scope_id` 是不同概念 |

## 3. 概念与归属

```text
Product
  └─ AuditTarget
       ├─ SourceScope[]
       └─ AuditRun[]
            ├─ TargetSnapshot
            ├─ Findings / FindingWorkflow
            ├─ Reports / Artifacts
            └─ ValidationRequests / ValidationRuns / Evidence
```

| 概念 | 含义 | 归属约束 |
|---|---|---|
| 产品空间 Product | 一个产品或业务系统的数据空间 | 固定且独立的 `product_id` |
| 测试对象 AuditTarget | 一份可复用的测试范围定义 | 必须属于一个产品 |
| 源码范围 SourceScope | 一个目录及其包含、排除规则 | 属于一个对象，具有稳定 `scope_id` |
| 审计任务 AuditRun | 对对象执行的一次审计 | 绑定对象及创建时的配置快照 |
| 发现与报告 | 任务产出的审计结果 | 当前空间归属沿任务、对象解析 |
| 产品归属记录 | 对象当前所属产品及归属变更事件 | 不修改历史测试事实 |

一个物理目录可被不同对象引用，也可用于不同产品。重复路径不是全平台唯一约束。一个对象内部不能配置重复规范路径；父子目录重叠在第一版直接拒绝，并展示冲突范围，避免重复计数和难以解释的排除规则。

界面统一使用“产品”“审计对象”“源码范围”“审计任务”。旧接口和制品中的 `repository_id` 暂时保留为兼容标识，不再据此推断输入必须是 Git 仓库。

## 4. 内置“未定义”产品

| 项目 | 规则 |
|---|---|
| 内部 ID | `product-undefined`，数据库实体，不用 null 或空字符串代替 |
| 显示名称 | 未定义 |
| 系统属性 | `system=true`、`status=active` |
| 生命周期 | 不允许重命名、删除、归档 |
| 历史默认值 | 没有产品映射的老对象和老任务归入此空间 |
| 临时审计 | 全局“临时审计”入口默认进入此空间，不要求先创建正式产品 |
| 查询边界 | 只返回本空间资源，不充当全部产品视图 |
| 功能范围 | 与普通产品相同，允许对象、任务、发现、报告和验证管理 |

临时审计仍创建或复用一个可追溯的对象记录，可根据目录名自动填写对象名称。默认按“规范路径 + include/exclude 规则 + 范围角色”的规范化摘要，在“未定义”中复用同一活动、可编辑、由临时入口创建的对象；版本备注和任务补充说明不参与复用。用户可以取消“复用相同对象”，显式创建新对象。归档对象、只读历史对象、启动参数对象和正式创建的普通对象都不被临时入口静默复用。临时不意味着自动删除或不保存历史。新对象显式指定一个不存在的产品时返回错误，不悄悄回退到“未定义”。

“未定义”始终可从产品中心与切换器找到，但不强迫用户把临时对象整理到正式产品。

## 5. 页面与交互

### 5.1 产品中心

作为新的默认入口。每项显示产品名称、说明摘要、标签、对象数、运行任务数、最近审计时间及归档状态。支持名称搜索、标签筛选、活动/归档筛选，以及每页 20/30/50/100 条。

“未定义”入口固定可见，正式产品按最近访问或名称排序。摘要从索引读取，不逐个打开产品制品目录。平台级“全部产品概览”是独立页面，不混入“未定义”。

提供“新建产品”和“临时审计”。产品名称去除首尾空白后必填，建议限制 120 字符；正式产品名称在产品目录中唯一，保留名称“未定义”。

### 5.2 产品内导航

```text
顶部：产品切换器 / 当前产品名称 / 平台运行状态
侧栏：概览 / 审计对象 / 审计任务 / 漏洞发现 / 审计报告 / 动态验证 / 产品设置
平台入口：产品中心 / 运行环境 / 模型与队列设置
```

建议页面路由包含产品 ID，例如 `/products/{product_id}/audits`。若暂时保留单页原生 JS，可先使用等价 hash 路由；页面刷新、收藏和复制链接仍能恢复空间与页面，不能只依赖进程内状态或浏览器存储。

| 页面 | 默认行为 |
|---|---|
| 产品概览 | 展示本产品汇总与最近少量任务、报告 |
| 审计对象 | 搜索、按可用性与归档状态筛选、分页、创建与编辑 |
| 对象详情 | 基本信息和范围、该对象任务、发现、报告，页签按需加载 |
| 审计任务 | 运行中/已完成（非运行中）/全部；运行中不分页，其余默认 20，可选 30/50/100 |
| 漏洞发现 | 按对象、任务、严重度及处理状态筛选，不混淆同一发现的多次审计记录 |
| 审计报告 | 按对象和任务查找报告，保留完整性状态 |
| 动态验证 | 本产品的请求、运行、结果及脱敏证据；不因切换产品启动验证 |
| 产品设置 | 编辑、归档/恢复、空产品删除 |

沿用已约定的任务分类：`preparing/recovering/running/pausing/cancelling` 属于“运行中”；其余状态包括 `queued/paused/interrupted/cancelled/failed/completed/artifact_only` 归入“已完成”。这里的“已完成”是现有 UI 名称，含义明确标注为“非运行中”，不代表每条任务成功完成。队列占用、正在执行、可调度排队、归档暂停排队和暂停任务分别统计，不能把排队或暂停数量显示成正在执行数量。

### 5.3 切换产品

切换时先递增客户端 `space_generation`，取消旧产品请求、关闭旧产品 SSE、停止终端轮询，清空旧产品的列表、选中项、批量选择、对话框与临时表单。新产品响应必须同时匹配 `product_id` 与请求代次才能写入状态。

只保留少量全局查询偏好，例如各资源类型的每页数量；搜索词、筛选项、页码和选中项按产品隔离且只保留在当前会话，不保留跨产品的任务选择。后台刷新保留当前产品当前查询的已显示行；用户切换产品或查询条件时不能短暂显示上一个范围的数据。

### 5.4 创建对象与创建任务

创建对象流程：选择所属产品 → 填写名称与说明 → 添加源码范围 → 可选填写版本备注、标签与关系说明 → 保存。

范围检查可独立执行。创建任务时仍需检查范围可读取，不能仅信任先前检查结果。创建任务默认跟随当前空间，仅能选择本产品未归档对象。

产品和对象可以提供非敏感的测试重点；补充说明与测试环境凭据继续按任务单独保存。对象复制不复制凭据，不把动态验证授权变成产品默认开关。

## 6. 数据模型

### 6.1 产品

| 字段 | 说明 |
|---|---|
| `id` | 独立生成的稳定标识；内置产品使用固定值 |
| `name`, `description`, `tags` | 展示和检索字段 |
| `system` | 是否系统内置 |
| `status` | 持久化生命周期：`active/archived` |
| `version` | 乐观并发版本 |
| `created_at`, `updated_at`, `archived_at` | 生命周期时间 |

### 6.2 对象与源码范围

| 对象字段 | 说明 |
|---|---|
| `id`, `product_id`, `version` | 稳定对象身份、当前归属、并发版本 |
| `name`, `description`, `tags` | 对象信息 |
| `version_label` | 人工版本备注，无 Git 约束 |
| `test_focus`, `relationship_notes` | 测试重点与范围间关系说明 |
| `status` | `active/archived` |
| `source_scopes` | 一个或多个范围 |
| `origin` | `ui/startup/legacy`，保留旧来源管理限制 |
| `storage_namespace` | 与产品归属无关的稳定制品命名空间 |
| `operation_epoch`, `ownership_generation` | 对象操作并发版本与归属代次，分别维护 |
| `last_scope_check_id`, `checked_at`, `check_digest` | 可用性依据；`availability` 是读取时派生字段 |
| `created_at`, `updated_at`, `archived_at` | 时间信息 |

| 范围字段 | 说明 |
|---|---|
| `id` | 稳定 `scope_id`，对象内新增范围时生成 |
| `name` | 对象内唯一名称，例如 `gateway` |
| `path` | 服务端规范化绝对路径 |
| `include_patterns` | 空表示目录下全部候选文件 |
| `exclude_patterns` | 在包含集上排除，排除优先 |
| `role`, `description` | 可选，例如入口服务、共享库、接口定义 |

`status` 只表示生命周期。“可用性”是派生字段 `availability=ready/unavailable/unknown/checking`，来自最近一次持久化的 `scope_check`；每个对象保存 `last_scope_check_id/checked_at/check_digest`。超过 10 分钟显示 `unknown` 并由后台低优先级重查，列表请求本身不遍历目录。对象允许在 `availability=unavailable` 时保存，以便处理代码迁移或暂时离线；创建审计时必须执行新检查，所有参与范围可读且最终候选集合非空。编辑路径或规则后立即将可用性置为 `unknown`，但不改变对象 ID，只影响未来任务。

检查结果绑定对象配置版本和范围摘要；旧配置的后台检查即使后完成，也不能覆盖新版本的可用性。规则失效、未检查、检查中和不可读在列表中区分。`scope_check` 保存必要摘要，完整逐文件基线只在任务执行阶段生成。

### 6.3 任务与结果

任务保存 `target_id`、创建时 `product_id_at_creation`、`product_name_at_creation`、`target_snapshot`、`snapshot_digest`、`source_baseline_locator` 和 `source_binding_schema_version`。

`target_snapshot` 包含当时的对象名称、版本备注、范围 ID/名称/路径、规则、关系说明与对象版本，创建任务时一次写入。`snapshot_digest` 只证明配置未被修改。实际出队进入 `preparing` 时另封存 `execution_binding`，同时引用该快照摘要和 §7.4 的逐文件启动基线；两者组成完整任务快照。排队时 `source_baseline_locator=null`，不假称已经读取源码；封存后基线不可替换。对象编辑不影响已排队任务的配置。

任务当前所属空间经对象的当前归属解析。查询索引可冗余保存 `current_product_id`，但由同一事务维护；已封存报告中的原始产品名称和任务快照不回写。`product_id_at_creation/product_name_at_creation` 是历史事实：对象从“未定义”补录到正式产品后，它们与当前产品不同，也为将来受控的正式产品间转移保留审计证据。UI 同时显示“当前所属产品”与“创建时所属产品”。

新发现位置至少包含 `scope_id`、`relative_path`、`line_start`，可选 `line_end`。多位置证据分别标注范围。对外显示范围名称与相对路径；内部关联使用稳定 `scope_id`，不依赖可编辑名称。旧发现继续解析原路径，在其单范围对象下解释，不改写旧证据文件。

### 6.4 标识与存储命名空间

新正式产品、对象和范围分别使用 `product-<uuidv4>`、`target-<uuidv4>`、`scope-<uuidv4>`；UUID 由服务端密码学安全随机源生成。内置产品固定为 `product-undefined`。老对象继续以原 `repository_id` 作为 `target_id`，不重新编号。

`storage_namespace` 在对象创建时一次生成且不可编辑：老对象等于原 `repository_id`；新对象等于其 `target_id`。它与路径、产品和显示名称无关。编辑路径、重命名、归档或补录归属都不改变该值。复制对象产生新的 `target_id` 和命名空间。

定义 `H(s)=lowerhex(SHA-256(UTF8(s)))[0:24]`，`NUL` 为单个零字节。旧数据必须精确保留现有分类型算法，不能用统一的新哈希重新计算：

| 旧资源 | 当前公开标识算法/规则 |
|---|---|
| Finding `resource_id` | `H(repository_id + NUL + audit_id + NUL + finding.id)` |
| Report/Artifact `id` | 先 `local_id=H(原受控相对路径)`，再 `H(repository_id + NUL + local_id)`；这是两层哈希 |
| Validation request | 原 `request.id` 保留；`job_id=H(repository_id + NUL + request.id)` |
| Validation result | 原 `run.id` 保留；`resource_id=H(repository_id + NUL + run.id)`；已有运行 job ID 原样保留 |
| HTTP exchange | 保留原 `exchange_id`，当前没有统一的外层 repository 哈希 |

上表对应 `server.mjs` 的 `scopedResourceId` 调用点及 `workspace-model.mjs` 的本地制品 ID。迁移不对旧 ID 输入重新做 Unicode 或路径大小写归一化。无法无歧义重建的旧 ID 直接登记原值和 locator，标注来源，禁止猜测。

新对象、新任务和新制品使用明确的 `id_scheme=resource-v2`：`resource_id=H(JSON.stringify(["resource-v2", storage_namespace, resource_type, audit_id, local_resource_key]))`。数组各元素都是非空字符串。finding 的本地键为密封 finding ID；report/artifact 为规范受控相对路径；validation-request 为 request ID；validation-run 为 application service 在派发前生成并保存的 run ID；exchange 为捕获时一次生成的 exchange ID。finding 去重不能仅按源码行号或显示标题生成本地 ID。新旧 scheme 由任务/locator 持久字段指定，补录归属或重建索引不切换 scheme。

数据库对 `(resource_type, resource_id)` 和 `(id_scheme, storage_namespace, resource_type, audit_id, local_resource_key)` 建唯一约束；截断碰撞、旧 exchange 重号或同键不同定位一律列为迁移冲突，不覆盖、不追加随机后缀。报告与对应原始 artifact 可拥有各自类型的 ID，locator 指向同一文件。路径编辑、产品转移都不参与算法，故不改变已有资源 ID。

## 7. 源码范围和审计执行契约

### 7.1 文件枚举

直接从指定目录遍历候选文件，不再以 `git ls-files` 作为必需入口。规则使用本文固定的 `scope-glob-v1` 方言：路径相对范围根、统一 `/` 分隔；`*` 匹配单段内任意字符，`?` 匹配单段内一个字符，`**` 作为完整路径段时匹配零个或多个路径段，`[abc]`/`[a-z]` 支持字符类；不支持 `!` 否定、花括号、extglob、反斜杠分隔、绝对模式、空段或 `.`/`..` 段。匹配在所有平台统一区分大小写，模式与枚举路径规范化为 Unicode NFC。目录规则写为 `dir/**`。包含规则先应用、排除规则后应用，空包含列表等价于 `**`。实现采用固定版本的内部匹配器及契约测试，不继承 shell、gitignore 或第三方库的隐式行为。

界面显示默认排除项；`.git` 及其内部元数据默认不参与源码审计。其他目录不因被 `.gitignore` 忽略而自动排除。依赖、构建产物等排除项必须在范围预览中可见。

第一版不遍历范围内部的符号链接、目录链接或 Windows junction，范围预览记录相对路径和 `symlink-skipped`。用户明确登记的范围根先做 `realpath` 并展示、保存解析后的规范路径；内部链接与根路径登记分开处理。普通文件按 `(scope_id, relative_path)` 保留位置；可靠的 `(device,inode/file-id)` 相同只用于复用一次内容读取，不删除位置或改变覆盖率分母。文件 ID 不可用时各自读取，不能据相同内容误合并两个文件。NFC 归一化后重号的不同文件、无法稳定解析的文件类型均使范围检查失败，并保留原路径用于说明。

“过宽路径”采用确定性门禁：拒绝文件系统根、当前用户主目录本身、平台根目录及其祖先、平台受控的 state/reports/tmp/workspace 目录及其祖先；任一范围也不能包含另一个范围。范围预览发现候选文件超过 100,000 或候选总大小超过 10 GiB 时标记 `broad_scope`，需要在创建任务时提交 `allow_broad_scope=true` 和本次检查摘要，服务端仍重新核对；硬性遍历上限为 500,000 个目录项，超过则检查不完整且禁止启动。阈值可以通过平台配置降低，响应必须返回实际阈值。

范围预览是异步检查作业，返回文件数量、总大小、语言分布、排除理由、链接跳过信息、宽范围状态和错误，并持久化为对象的最新可用性依据。超过遍历预算标记结果不完整，不假装完整。列表页只读最近检查摘要，不触发范围预览。

路径门禁补充：平台受控制品/state 目录及其后代、平台 `.opencode` 引擎控制目录也禁止作为源码范围；依据规范绝对路径判断，不因为其他项目组件恰好同名就拒绝。主目录下普通 `src/service-a` 可以登记，不能把拒绝主目录本身扩大到所有后代。平台自身源码自审计应使用独立检出目录。

方言验收样例：`**/*.js` 匹配 `app.js` 和 `src/app.js`；`src/*` 不匹配 `src/lib/a.js`；`src/**` 匹配其全部候选后代；`A.js` 不匹配 `a.js`（所有平台一致）；包含 `**`、排除 `vendor/**` 时 `vendor/a.js` 不入基线。字符类不支持取反，未闭合括号和非整段的 `**` 返回 422；点开头文件不隐式忽略，只有显式排除生效。

### 7.2 多目录执行

任务工作区保存受控 `source-scopes.json`，通过 `AUDIT_SOURCE_MANIFEST` 传入执行链。只有单范围任务可同时提供兼容 `AUDIT_SOURCE_ROOT`；多范围禁止把第一个目录冒充全部输入，也不使用各目录的公共父目录代替授权范围。

范围枚举、Coverage Ledger、扫描器、解析器、发现 ID、证据关联、CVSS/裁决输入、攻击链、最终报告和验证 handoff 都要逐项核对单根假设。文件键采用 `scope_id + relative_path`，防止同名文件覆盖。覆盖率先按范围计算，再对去重文件/任务集合聚合，不能直接平均各目录百分比。

原本只接受单根目录的扫描工具逐范围执行，结果转换为统一位置模型后合并。多个独立扫描结果拼接不能标记为已完成跨范围分析。外部依赖不在范围内时同时写入 `reports/coverage/scope-limitations.<audit-id>.json` 和最终中文报告“范围限制”段；限制条目包含来源位置、未解析目标、影响阶段和原因，不自动扩大范围。

### 7.3 跨范围关联契约

范围数量大于 1 时，Orchestrator 在所有逐范围扫描与接口清单完成后、现有 preliminary attack-chain pass 之前调度 `P04_CROSS_SCOPE_ANALYSIS`。执行者为新增的专用审计角色 `security-cross-scope-analyzer`；其注册、输入输出 envelope、工具权限和校验器随 P3 一起交付。该子阶段归入现有“多维漏洞审计”阶段，不新增第九个顶层阶段；旧版任务不要求该交付件。

首轮实现只开放“一个范围、无包含/排除规则”的执行路径：多范围对象和规则仍可保存、查看、复制与归档，但创建任务会返回明确的阻断错误，绝不降级为只扫描第一个范围或忽略规则。选择独立组件目录作为该单一范围即可用于非 Git 审计；规则解释器和跨范围阶段完成全链路接入后再解除门禁。

顺序固定为：逐范围扫描 → 跨范围关联 → preliminary attack-chain → evidence correlation → 真实性 routing → final attack-chain。跨范围分析输出是候选结构证据，不等于已证实漏洞；最终链仍只能消费 routing 为 `TRUE_POSITIVE` 的发现。后续定向补审改变输入 manifest 摘要时，跨范围结果失效并按新输入重建。

输入 envelope 固定包含 `schema_version/audit_id/target_id/baseline_digest/input_manifest_digest`，以及任务配置快照、各 scope 的启动基线/覆盖/接口 manifest、规范化候选 finding、可解析调用/数据流/依赖边和范围关系说明。CPG 或工具索引为可选输入，必须声明 `available/unsupported/failed`，不能假设所有语言都有 CPG。输入 locator 只引用受控工作区或制品目录内带摘要的文件；原始源码按任务已授权范围读取。接口缺失或分析器失败需记录为缺口，禁止直接推定没有跨范围关联。

输出为 `reports/correlation/cross-scope-analysis.<audit-id>.json`，至少包含：

| 字段 | 内容 |
|---|---|
| `schema_version/audit_id/target_id/baseline_digest/input_manifest_digest` | 输出身份及完整输入绑定 |
| `scope_coverage[]` | 每个 scope 的输入完整度、使用的分析器和缺口 |
| `cross_scope_edges[]` | 源/目标位置、边类型、证据引用、置信度；边类型限调用、数据流、依赖、身份传播、信任边界 |
| `linked_findings[]` | 被关联的 finding ID、关联理由及证据 |
| `attack_path_candidates[]` | 有序跨范围节点、前置条件、已证实/推断状态 |
| `unresolved_boundaries[]` | 无法解析的跨范围接口及影响 |
| `status` | `COMPLETE`、`COMPLETE_WITH_RESIDUAL_GAPS` 或 `FAILED` |
| `manifest_digest` | 排除本字段后的规范 JSON SHA-256 |

确定性校验器验证 scope 均出现、位置合法、引用摘要匹配、边至少跨两个不同 `scope_id`、攻击路径节点可追溯，且 residual gap 已进入范围限制制品。`FAILED` 阻止证据关联和最终封存；`COMPLETE_WITH_RESIDUAL_GAPS` 可以继续，但最终报告必须列明缺口。对于确实没有跨范围边的任务，允许 `COMPLETE` 且边数组为空，前提是每个 scope 的接口和分析器覆盖已记录，不能用空文件冒充执行。

新增 `cross-scope-analysis.schema.json` 与 `validate-cross-scope-analysis.mjs`；输出规范 JSON 定义为递归按属性名字典序排序、数组保持契约顺序、UTF-8、无空白，摘要排除自身字段。schema 限定边类型、来源位置、证据 locator、已证实/推断属性和状态枚举；语义校验负责摘要、范围覆盖和引用闭合。`manifest_digest` 不依赖模型自行判断，通过确定性封存器生成。

证据关联阶段消费该输出，把跨范围关联纳入 canonical finding；攻击链阶段只接受其中可追溯边并可补充裁决结果。最终报告按 scope 展示覆盖，并单列跨范围路径、未解析边界和分析器限制。P3 验收使用至少一个可证实跨范围调用/数据流和一个无关联对照样例。

### 7.4 无 Git、源码基线与恢复

新任务取消 Git 存在性、dirty 工作树和当前 checkout 与 ref 相符的启动门禁，保留引擎配置有效、目录可读、范围合法等必要检查。版本备注由用户提供。

任务实际出队进入 `preparing` 后、任何审计 Agent 或扫描器启动前，必须为每个 scope 生成 `source-baseline-v2`。复用现有范围枚举器的逐文件 SHA-256 能力，移除其 Git 依赖，不引入历史版本仓库。基线包含规范相对路径、类型、大小、SHA-256、排除/链接记录。每个 scope 按 `(path,type)` 排序，对固定结构的文件记录及规则摘要计算 `scope_digest`；按 `scope_id` 排序的 scope/digest 数组计算 `baseline_digest`，规范 JSON 同 §7.3。具体 locator 固定为 `reports/coverage/source-baseline.<audit-id>.json`，进入 `execution_binding` 后不可变；不保存源码副本。

每个阶段提交的源码位置必须引用基线中的 `(scope_id, relative_path, sha256)`。收尾时重新枚举并与基线比较，输出 `reports/coverage/source-drift.<audit-id>.json`，分别列 added/removed/modified/type_changed，以及每个 finding 主位置和证据位置是否变化。没有变化才允许正常完成。发现漂移时任务进入 `interrupted`，原因 `source-drift`，已有制品保留但最终报告不得标记为可交付；恢复须源码回到原基线，否则创建新任务。哈希读取前后检查文件身份、大小和修改时间，结束时复核枚举集与属性；检测到变化重试一次，仍不稳定时拒绝启动。这能检测已观察到的变更，不能保证发现“改动后又恢复”等短暂变化；不能把基线声称为文件系统原子快照。

新任务的源码绑定使用 `source-binding-v2`：绑定 `snapshot_digest`、各 `scope_digest` 和 `baseline_digest`，不伪造 commit，也不把配置摘要填入 `source_commit`。旧的依赖 commit 的密封交付件、验证 request 和报告继续由旧版校验器读取；新契约必须同步升级全部生产者和消费者后启用。

断点恢复复用任务原快照，不读取对象后来修改的目录或规则。原路径不可用时返回明确错误，不自动切换路径。老任务按旧绑定恢复；如需使用新的无 Git 行为，应显式创建新任务，不能静默降低旧交付契约的校验。

## 8. 持久化与查询目录

使用一个嵌入式 SQLite 目录库保存产品、对象、归属与可查询的任务/结果摘要。首轮实现选用 Node 内置 `node:sqlite`（项目声明 Node `>=22.5.0`），因此不引入 `better-sqlite3` 的原生编译链；启用 WAL、外键和短事务。P0 仍必须在 Windows/Linux 上完成安装、并发事务、崩溃恢复、备份与迁移测试后，才能把该选型标记为验收通过；未通过时使用“单写者服务 + 已验证嵌入式驱动”的明确替代方案，不能退回请求时扫描 JSON。

采用目录库的理由是归属迁移、并发修改、分页计数和按产品查询需要事务与索引；继续让每次页面查询扫描 JSON/报告文件，无法满足现有延迟要求。

| 表/集合 | 角色 |
|---|---|
| `products`, `audit_targets`, `source_scopes` | 产品与对象的唯一权威配置 |
| `audit_catalog` | 任务当前归属与查询摘要，运行事实仍来自 Runner |
| `finding_catalog`, `report_catalog`, `validation_catalog` | 可重建结果索引，不替代原始证据 |
| `resource_locators` | 稳定资源 ID 到存储命名空间、受控相对路径的映射 |
| `ownership_events`, `idempotency_records` | 归属审计记录与幂等结果 |
| `catalog_jobs`, `migration_runs`, `product_events` | 索引任务、失败重试、迁移状态和持久事件序号 |

索引至少覆盖 `(product_id, status, updated_at, id)`、`(product_id, target_id, updated_at, id)`、任务 ID、对象 ID 及报告资源 ID。对象当前归属是权威记录。任务运行文件继续保存原始执行事实；不建立两套相互覆盖的状态机。

### 8.1 v2 到 Runner 的权威数据流

v2 对象不写回 `repositories.json`。`repositories.json + 启动参数` 仅由 `legacy-target-adapter` 在启动和迁移时导入/关联到目录库，之后 v2 产品与对象配置只从目录库读取。启动参数仍能在每次启动时校验其受管对象的路径，但不能覆盖对象已有的产品归属。

v2 创建任务必须走 `audit-application-service.createAudit(productId, targetId, input)`。该服务在同一个数据库事务中读取产品和对象、获取对象操作锁、校验状态和版本、创建任务意图及快照，然后生成不可变 `AuditExecutionSpec`。Spec 包含任务 ID、目标/产品 ID、`storage_namespace`、对象版本、范围配置、私密上下文 locator 和执行模型；进入 `preparing` 时再绑定源码基线。Runner 新增 `createAuditFromSpec(spec)`，只负责校验 spec schema/摘要、持久化运行状态、入队和进程控制，不再通过 `this.repositories` 再做对象白名单查询。

切换完成后现有 `createAudit(input)` 变为兼容薄适配器：按 SQLite 中的旧 ID 映射解析“未定义”单范围对象，再调用同一 application service；`this.repositories` 即使暂时保留也只能是可重建投影，不参与权威白名单判断。`repositories.json` 只在首次导入时读取一次，之后不与数据库双写；启动参数每次启动经受限适配器校验来源字段。P0 必须先交付 adapter、Spec 契约和 Runner 新入口，再开放 v2 对象创建；该链未完成时只允许迁移预览，不发布可写 v2 对象接口。P0/P1 可运行的任务仍遵守旧单范围 Git 契约，P3 才启用 `source-binding-v2`。

运行状态的权威仍是 Runner 的任务状态文件；目录库保存任务意图、不可变快照和查询摘要。Runner 状态事件带任务版本写入目录库，目录只能接受版本更大的状态；服务启动时以任务意图与 Runner 状态进行确定性恢复，缺一侧时按创建状态机补齐或标为受阻，不凭列表缓存猜测。

### 8.2 对象操作锁和事务边界

“对象操作锁”实现为 SQLite 中 `audit_targets.operation_epoch` 加事务内条件更新，不使用仅进程内互斥或独立文件锁。所有可能改变“是否允许转移”的入口——创建任务意图、入队/重新入队、断点恢复、启动动态验证、对象归档/删除和归属转移——必须调用同一 `audit-application-service.withTargetOperation(targetId, expectedEpoch, fn)`，在一个 `BEGIN IMMEDIATE` 写事务内重查对象、产品和活动资源并递增 epoch。

Runner、队列调度器和 ValidationRunner 不允许从 HTTP 路由直接启动。server、定时调度、恢复器、watchdog 重启都调用 application service。事务内先建立持久 `operation_intent` 保留项，状态为 `reserved/queued/dispatch_pending/running` 的意图均阻止转移和对象删除；服务提交后才发命令。派发失败可重试或记录为终态失败；未确认进程不存在前不能释放保留项。动态验证先经 application service 解析 request 所属任务和对象、执行授权门禁、提交保留项，再调用 ValidationRunner。因此从事务提交到进程派发之间的间隙也阻止迁移。

归档与出队同样在对象事务中判断；先归档则拒绝出队，先取得启动保留项则视为已开始运行、允许完成。多个对象操作的产品归档使用同一数据库写事务修改产品状态，后续每次派发均重查它。`BEGIN IMMEDIATE` 是数据库写序列化，不是长期对象行锁；`operation_epoch` 用于并发版本检查，持久意图负责覆盖事务外执行窗口。第一版单服务进程拥有所有 Runner；独立索引 worker 只能经目录服务提交，不获得启动权限。

SQLite 事务只覆盖短小的状态判断和意图写入，不在持锁事务内扫描源码、读取大型制品或启动进程。迁移预览不持锁；正式提交重新检查全部条件。

### 8.3 异步索引与归属代次

`audit_targets.ownership_generation` 初始为 1，每次转移递增。索引 job 保存 `target_id/audit_id/resource locator/enqueued_generation/input_digest`，不携带权威 `product_id`。提交结果的数据库事务重新读取对象、任务及删除标记，以 `(resource_type, resource_id)` upsert，`target_id` 是外键而非整张资源表的主键。代次未变则正常写入；仅归属变化且输入 digest 仍相同时，从当前对象取产品和新代次写入，禁止使用旧产品值；输入已过期则 `superseded` 并按当前版本排队。对象/任务已删除时标为 `discarded`，不能重建删除资源。删除流程保留任务 tombstone 直到所有关联 job 终止。

所有派生目录行保存 `ownership_generation`，查询通过对象当前归属 join；冗余 `product_id` 仅用于索引加速，并由触发器或同一事务更新。归属转移事务同时更新对象、关联派生行、事件和代次。事务前入队、事务后写回的旧 job 不能把资源重新归入“未定义”。

创建和执行分开：对象事务写入幂等任务意图与配置快照 → 原子写入 Runner 的 queued 状态并登记摘要 → 创建完成；取得调度名额后在新事务建立启动保留项 → Runner 进入 preparing → 生成源码基线和 execution_binding → 派发审计进程。基线失败则转为受阻/中断，不启动审计进程。崩溃恢复按任务 ID 和 Spec 摘要补齐文件与目录；旧基线存在时校验并复用，不覆盖。状态不明的派发先核对该任务记录的精确进程身份，不能因重试相同 ID 就再次 spawn。

数据库放在工作台本机受控状态目录，部署在支持的 Windows/Linux 主机上。首次迁移前备份现有登记与任务元数据。目录库的派生部分可以重建；产品、对象和归属事件必须备份，不能通过重新扫描报告推断丢失的业务归属。

制品继续按稳定对象命名空间及任务存储，旧的 `reports/repositories/<repository-id>` 路径不移动。新对象也使用与产品无关的存储键。源码只读，不向源码目录写库、缓存、配置或报告。

## 9. API 设计

新接口统一使用 `/api/v2`，产品作用域写在路径中。第一版列表默认 20 条，允许 20/30/50/100；稳定排序使用更新时间和 ID。运行中任务返回该产品全部运行条目，仍只返回摘要。

| 方法与路径 | 用途 |
|---|---|
| `GET /api/v2/products` | 产品搜索、状态筛选与分页 |
| `POST /api/v2/products` | 新建正式产品 |
| `GET/PATCH/DELETE /api/v2/products/{p}` | 详情、编辑、删除空产品 |
| `POST /api/v2/products/{p}/actions` | 归档或恢复 |
| `GET /api/v2/products/{p}/summary` | 产品汇总及索引更新时间 |
| `GET/POST /api/v2/products/{p}/targets` | 对象查询与创建 |
| `GET/PATCH/DELETE /api/v2/products/{p}/targets/{t}` | 对象详情、编辑、删除空对象 |
| `POST /api/v2/products/{p}/targets/{t}/actions` | 归档或恢复对象 |
| `POST /api/v2/products/{p}/targets/{t}/scope-checks` | 启动范围检查，返回作业 ID |
| `GET /api/v2/products/{p}/scope-checks/{job}` | 查询范围检查结果 |
| `POST /api/v2/products/{p}/targets/{t}/copies` | 复制配置到指定产品，不复制凭据或历史 |
| `GET/POST /api/v2/products/{p}/audits` | 查询或创建本产品任务 |
| `GET /api/v2/products/{p}/audits/{a}` | 任务详情 |
| `POST /api/v2/products/{p}/audits/{a}/actions` | 暂停、恢复、取消、断点恢复等现有操作 |
| `DELETE /api/v2/products/{p}/audits/{a}` | 沿用受控任务删除流程 |
| `GET /api/v2/products/{p}/events` | 本产品任务和目录更新摘要事件 |
| `GET /api/v2/products/{p}/findings` | 发现分页与筛选 |
| `GET /api/v2/products/{p}/reports` | 报告分页与筛选 |
| `POST /api/v2/products/product-undefined/targets/{t}/transfer-preview` | 归属补录预览 |
| `POST /api/v2/products/product-undefined/targets/{t}/transfer` | 原子提交归属补录 |

所有资源端点的 v2 路径固定如下，不能通过全局资源 ID 绕过产品边界：

| 资源 | v2 方法与路径 |
|---|---|
| 任务事件 | `GET /api/v2/products/{p}/audits/{a}/events` |
| 任务日志 | `GET /api/v2/products/{p}/audits/{a}/logs` |
| 任务终端 | `GET /api/v2/products/{p}/audits/{a}/terminal` |
| 终端尺寸 | `POST /api/v2/products/{p}/audits/{a}/terminal/resize` |
| 任务制品 | `GET /api/v2/products/{p}/audits/{a}/artifacts` |
| Finding workflow | `POST /api/v2/products/{p}/findings/{f}/workflow` |
| 报告正文 | `GET /api/v2/products/{p}/reports/{r}` |
| 报告下载 | `GET /api/v2/products/{p}/reports/{r}/download` |
| 验证请求 | `GET /api/v2/products/{p}/validation-requests` |
| 启动验证 | `POST /api/v2/products/{p}/validations` |
| 验证详情/列表 | `GET /api/v2/products/{p}/validations[/{v}]` |
| 验证操作 | `POST /api/v2/products/{p}/validations/{v}/actions` |
| 验证事件 | `GET /api/v2/products/{p}/validations/{v}/events` |
| HTTP exchange 列表/详情 | `GET /api/v2/products/{p}/http-exchanges[/{e}]` |
| Bruno/HAR 导出 | `POST /api/v2/products/{p}/http-exchanges/export/bruno`、`.../export/har` |

批量请求先验证全部资源属于路径中的同一产品；混入其他产品时整体拒绝，不部分导出。平台级 `/api/health`、`/api/v1/runtime/health`、`/api/v1/environment`、`/api/v1/settings/model` 和 `/api/v1/settings/queue*` 第一版保持平台路径，后续可统一版本号，但不添加虚假的产品参数。

### 9.1 v1 兼容矩阵

v1 的兼容空间固定为 `product-undefined`。以下“仅未定义”表示列表只返回该空间；详情、下载和写操作仅在资源当前仍属于该空间时执行，否则返回 409 `resource-moved-to-product`，响应给出新 v2 导航路径但不泄露资源正文。404 仍用于不存在的资源。

| 现有 v1 端点 | 兼容行为 | 对应 v2 |
|---|---|---|
| `GET /api/v1/workspace`、`GET /api/v1/dashboard/summary` | 仅未定义；保留旧响应形状 | 产品 summary 与各资源列表 |
| `GET/POST /api/v1/repositories` | 仅未定义；POST 经 legacy adapter 创建/复用单范围对象 | `.../{p}/targets` |
| `DELETE /api/v1/repositories/{id}` | 仅未定义、旧删除门禁；有历史仍拒绝 | `.../{p}/targets/{t}` |
| `GET/POST /api/v1/audits` | 仅未定义；POST 经 application service | `.../{p}/audits` |
| `GET/DELETE /api/v1/audits/{a}` | 仅未定义 | `.../{p}/audits/{a}` |
| `POST /api/v1/audits/{a}/actions` | 仅未定义并参与对象操作锁 | 同名 v2 actions |
| `GET /api/v1/audits/{a}/events` | 仅未定义；转移后发送终止事件并关闭 | 同名 v2 events |
| `GET /api/v1/audits/{a}/logs` | 仅未定义 | 同名 v2 logs |
| `GET /api/v1/audits/{a}/terminal` | 仅未定义 | 同名 v2 terminal |
| `POST /api/v1/audits/{a}/terminal/resize` | 仅未定义 | 同名 v2 resize |
| `GET /api/v1/audits/{a}/artifacts` | 仅未定义 | 同名 v2 artifacts |
| `GET /api/v1/findings` | 仅未定义 | `.../{p}/findings` |
| `POST /api/v1/findings/{f}/workflow` | 仅未定义 | 同名 v2 workflow |
| `GET /api/v1/reports` | 仅未定义 | `.../{p}/reports` |
| `GET /api/v1/reports/{r}`、`.../{r}/download` | 仅未定义；ID 保持不变 | 同名 v2 report 路径 |
| `GET /api/v1/validation-requests` | 仅未定义 | `.../{p}/validation-requests` |
| `POST /api/v1/validations` | 仅未定义并参与对象操作锁 | `.../{p}/validations` |
| `POST /api/v1/validations/{v}/actions` | 仅未定义 | 同名 v2 actions |
| `GET /api/v1/validations/{v}/events` | 仅未定义；转移时关闭 | 同名 v2 events |
| `GET /api/v1/http-exchanges[/{e}]` | 仅未定义 | 同名 v2 路径 |
| `POST /api/v1/http-exchanges/export/bruno`、`.../export/har` | 仅未定义，混合归属整体拒绝 | 同名 v2 export |
| `GET /api/runs[/{v}]` | 仅未定义，标记 deprecated | `.../{p}/validations[/{v}]` |

平台接口明确保留：`GET /api/health`、`GET /api/v1/runtime/health`、`GET /api/v1/environment`、`GET/PUT /api/v1/settings/model`、`GET/PUT /api/v1/settings/queue`、`POST /api/v1/settings/queue/activate`、`.../deactivate`、`.../dispatch`。全局 dispatch 仍经 application service 检查每个对象及产品的调度资格。v1 不新增产品选择参数；兼容期至少跨一个正式版本，下线时间属于发布决策，在此之前所有映射都必须有路由回归测试。新增产品操作 `resume_queue` 只解除产品暂停原因，仍归档的对象不会恢复调度；对象动作同理。

### 9.2 列表响应

统一返回 `items`、`count`、`page`、`page_size`、`total_pages`、`generated_at`、`catalog_updated_at`、`refreshing`。摘要列表不携带日志、报告正文、全部证据和阶段校验树。运行中列表的 `page_size=null`、`page=1`、`total_pages=1`。

### 9.3 写入、并发与错误

创建与迁移使用 `Idempotency-Key`，保存请求摘要；相同键不同请求体返回 409。修改与删除使用 `If-Match`，版本冲突返回 412。继续执行现有 JSON、同源写请求及受控路径检查。

| 情况 | 状态码与处理 |
|---|---|
| 产品不存在、资源不属于路径中产品 | 404，避免返回其他产品资源详情 |
| 非法范围、页码或字段 | 422，指出具体字段 |
| 对象有活动任务，不能迁移 | 409，并返回阻塞任务 ID |
| 归档产品/对象试图创建任务 | 409 |
| 写入使用旧版本 | 412，提示刷新后重试 |
| 幂等键重复但请求不同 | 409 |
| 目录尚未建立或该产品重建失败 | 返回可区分的准备中/失败状态，不把未就绪当作空数据 |

## 10. 归属补录与迁移

第一版只允许从“未定义”向一个未归档正式产品进行整体归属补录。这一限制用于把历史兼容补录与一般业务重组分开：正式产品间转移需要额外的报告展示语义、审计审批和链接保留策略，第一版不承诺。产品 A 到 B 暂时只能复制配置并为未来任务使用，历史任务留在 A。后续版本可复用本节的原子转移机制，但必须先增加跨正式产品权限/审批、别名链接和撤销策略。

补录单位是对象及其全部关联任务、发现、workflow、报告、验证记录和证据索引，不允许只迁移一份报告导致父子归属分裂。

### 10.1 预览与提交

1. 用户选择目标产品，服务端返回迁移预览：对象与两侧版本、关联资源数量、阻塞项、预览摘要。
2. 阻塞条件包括排队任务、运行/恢复/暂停中的任务、正在取消的任务、活动完整动态验证、待完成的删除或迁移操作。展示“已完成”页签不代表可以迁移，例如 queued/paused 仍阻塞。
3. 用户提交带预览摘要、版本与幂等键的迁移请求。锁定对象，重新检查归属、两侧产品状态和活动任务。
4. 通过 §8.2 的 application service 和对象操作锁，在一个数据库事务中更新对象当前归属、全部派生归属、`ownership_generation`、持久事件及幂等结果。
5. 提交后失效两侧摘要与列表缓存；旧产品事件流停止推送已迁移资源，新产品流发布变更通知。§8.3 的 job 写回必须重新校验归属代次。

接口建议：`POST /api/v2/products/product-undefined/targets/{t}/transfer-preview` 与 `POST .../transfer`。预览不直接授予执行权；提交必须重新检查，不能仅凭之前没有活动任务就继续。

### 10.2 文件与历史事实

不搬源码、不移动历史制品、不改变任务 ID 和资源 ID、不重写已封存 JSON/Markdown，不重算旧报告摘要。存储定位与当前产品归属分别解析。

从旧产品路径访问已迁移任务返回 404。旧无产品链接经兼容解析器定位当前空间。已经下载到本机的报告不会被远程修改，其文本仍描述创建时事实。

迁移事务失败则整体回滚。提交后即便页面刷新失败也不能重复迁移；重试相同幂等键返回已完成结果。

## 11. 生命周期

| 资源与操作 | 规则 |
|---|---|
| 正式产品归档 | 禁止新任务、断点重启和新的验证运行；已运行任务允许完成，排队任务停止调度但保留 |
| 正式产品恢复 | 不自动重新调度保留任务；操作员执行“恢复排队”后，任务才重新获得调度资格 |
| 产品删除 | 仅无对象、任务及遗留资源的空产品可删除 |
| 未定义产品 | 永久活动，禁止重命名、归档、删除 |
| 对象编辑 | 未来任务使用新配置，已有任务快照不变 |
| 对象归档 | 已在执行的任务自然完成，也可沿用 `cancelling → cancelled` 流程取消；排队任务转为不可调度保留，禁止启动、恢复和新验证 |
| 对象删除 | 无关联任务/遗留资源时才允许；不删除源码 |
| 对象复制 | 新 ID，可选目标产品；只复制范围与非敏感配置 |

归档产品/对象内的 queued 任务仍计入全局“排队总数”，但不计入“可调度排队数”，单列“归档暂停排队数”。暂停任务不因归档或恢复自动继续；恢复执行必须等产品和对象恢复。归档不应隐式取消任务，也不隐式授权任何测试行为。

只读历史对象带有关联制品时无法删除是有意行为：它默认归档并可从普通列表隐藏，用于承载历史资源。只有通过现有受控流程删除其全部任务及遗留资源后才允许删除对象；“保留报告但删除承载对象”不支持。未来如增加合规清理，将作为独立、可审计的清理操作设计。

启动参数管理对象保留来源标记及编辑/删除限制。可以在业务层补录产品归属，但不得通过 UI 修改由启动参数控制的源码路径；下次启动依据稳定旧 ID 复用业务归属，不覆盖为“未定义”。

## 12. 事件、缓存与加载性能

### 12.1 索引更新

列表直接查询目录库，不在 HTTP 请求中执行全产品制品扫描、Git 命令、完整性校验或环境探测。

Runner 状态变化优先更新任务摘要。制品完成事件将相关任务加入可合并的索引队列，job 按 §8.3 校验 `ownership_generation`；为兼容外部写文件，增加低频、分批且有并发限制的目录核对。首次迁移和索引修复是后台作业，页面显示进度。写入中的文件使用重试与现有校验规则处理，不把半写文件判为有效结果。

报告下载和证据读取继续按请求校验受控路径及必要的摘要。查询索引用于快速定位，不能替代完整性证明。

### 12.2 产品事件流

每个当前空间建立一条产品级摘要 SSE，推送资源 ID、状态、版本和目录代次，不推送日志全文或敏感任务上下文。详情日志仍按需订阅单任务。事件在修改资源的同一 SQLite 事务内写入 `product_events`，每个产品使用持久单调递增的 64 位 `event_sequence`；进程重启后继续递增。事件保留最近 10,000 条且至少 7 天，清理前记录每个产品的 `minimum_available_sequence`。

事件必须在发送时检查当前归属。支持 `Last-Event-ID` 或 `after` 恢复；请求序号小于 `minimum_available_sequence` 时发送 `catalog.resync-required` 并关闭，客户端只重查当前页。转移事务分别在原产品写 `resource.moved-out`、在目标产品写 `resource.moved-in`。运行任务进入终态时，客户端更新分类和数量；当前页删除后越界则回到有效末页。

### 12.3 缓存与一致性

缓存键包含产品 ID、查询条件、分页和产品数据代次。缓存只保存摘要页，使用条数与字节双重上限的全局 LRU：初始上限为全进程 200 页/32 MiB，同时每个产品最多 40 页/8 MiB；任一上限触发即淘汰该范围最久未使用页，避免单个高频产品挤占全部缓存。最终值由主机基准调整。不能缓存每个产品的全部制品树。

对运行状态使用当前 Runner/目录状态；展示性制品统计允许短暂滞后并返回更新时间。授权范围、迁移归属、写操作版本、删除前置条件不使用过期缓存。数据库事务提交后先更新代次；事务前开始的查询不能回填新代次缓存。

### 12.4 性能验收目标

以下为设计目标，尚未实测：在记录了 CPU、磁盘、内存及 Node 版本的 Windows/Linux 本地主机上，使用至少 20 个产品、500 个对象、10,000 个历史任务、100,000 条发现摘要的合成数据测试。

| 指标 | 目标 |
|---|---|
| 索引就绪时产品、对象、历史任务列表 API | 默认 20 条，热态 P95 ≤ 300 ms；冷数据库读取 P95 ≤ 1 s |
| 100 个运行任务的摘要列表 | 不分页，P95 ≤ 500 ms |
| 自动刷新 | 请求期间旧行保持可见；状态事件到页面更新 P95 ≤ 1 s |
| 产品切换 | 只请求新产品资源，旧响应写入次数为 0 |
| 制品批量更新 | 前台列表不等待全量扫描；展示明确索引更新时间 |
| 内存 | 缓存不超过配置上限；反复翻页和切换不线性积累列表、证据或 SSE |

运行中超过 100 条时继续全量展示，不添加隐藏截断；DOM 使用分批渲染避免长时间阻塞，额外记录大规模下的延迟。超过目标必须附 CPU/I/O、接口耗时及查询计划证据，不以缓存命中个例冒充整体性能。

## 13. 历史迁移与旧接口兼容

### 13.1 迁移步骤

1. 在线预建：先启用持久变更日志，记下迁移起始序号；旧服务继续使用原读写源，同时在影子库分批扫描登记、任务、制品并预计算摘要。启用日志之后才扫描，避免扫描与增量之间丢事件。
2. 增量追平：按事件序号应用新增、更新及删除 tombstone，记录消费者水位；外部写文件通过分批核对补齐。后台完成大部分哈希校验，展示迁移准备度。
3. 短暂停写：确认没有正在执行/暂停/取消的审计或动态验证，也没有待派发保留项后暂停新写入和调度。仅 queued 且无启动保留项的任务可以连同原排队顺序迁移，不要求清空队列。活动任务由操作员结束或推迟切换，不自动终止。以停写后日志水位为边界备份登记、最新运行状态和影子库。
4. 最终对账：重放增量，创建/确认内置产品；以原 `repository_id` 建立对应单范围对象，保留原 ID、来源、路径和存储命名空间。老任务关联对象并归入“未定义”，原任务/证据字段原样保留。
5. 历史例外：只有制品没有登记对象时，建立默认归档的只读历史对象；源码路径无法可靠确定时标记 `availability=unknown`，不允许启动/恢复，不猜测路径。孤立制品进入待核对记录，不按文件名相似性挂到其他产品。
6. 确定性验收：全量比较资源数量、ID 集合及归属映射；每份可下载报告和密封 JSON 都需 SHA-256 一致。复用在线预建时相同文件身份/大小/mtime/ctime 的已计算结果，对变化项重新计算；严格审计要求下可选择全量重算并明确延长维护窗口。辅助制品按每类 `H(full migration_run_id + NUL + resource_id)`、再按资源 ID 排序，取前 `min(N, max(100, ceil(N*0.05)))` 条，不依赖未指定的伪随机算法。保存全部对账 ID、哈希和样本规则。
7. 原子切换：写入 schema/version 开关，使读写进入 adapter/application service；执行烟雾测试后恢复写入。失败则在没有 v2 新写入的前提下按 §13.3 回滚。

迁移可以重跑，每条旧资源有稳定来源键及迁移版本，不重复创建对象或任务。新索引、业务归属元数据写入事务化新存储，不直接改写旧报告。

### 13.2 旧 API 与旧链接

旧 `/api/v1` 不直接解释为“当前页面产品”。兼容列表默认只查询“未定义”；旧项目/任务创建请求未携带产品信息时也归入“未定义”。不能默认为跨产品全部数据。

旧无产品详情链接通过仅用于导航的解析器查找当前归属，跳转到新页面。操作和下载随后使用有产品作用域的 v2 接口；旧直接写操作仅允许“未定义”资源，已补录资源返回明确迁移提示，不绕过产品路由。

旧报告下载 ID 保持稳定。URL 中的产品作用域路径前缀可以改变，资源 ID 与摘要不改变。迁移提供兼容行为说明和旧客户端升级路径。

### 13.3 回滚

定义两个回滚边界：

1. `compatibility rollback`：从未发生不可兼容写入时，停写并导出切换时刻的最新数据到独立恢复目录。把“未定义”内符合旧 Git/单范围/ID 格式且使用旧执行契约的全部对象导出为 `repositories.json`；保留全部最新任务状态、事件和制品，包括切换后新增与取消的任务，不用切换前备份覆盖它们。空正式产品及 UI 偏好导出 sidecar 随新库归档。以旧版在恢复目录执行只读兼容检查、ID/数量/哈希对账，再切换启动目录。导出不完整则中止回退，继续运行新版。
2. `forward-only barrier`：在第一个正式产品对象/任务、非旧版可表达的对象配置、多范围或无 Git 任务、新 ID scheme、归属补录之前，于同一写事务记录屏障。越过后只支持新版备份恢复或修复前滚，不自动降级。多范围不能压扁成伪目录，正式产品归属不能在旧 UI 中静默混为一体。

零新写入时可直接恢复切换前备份；有兼容新写入时必须采用上面的最新状态导出。P0 门槛同时演练这两个场景，尤其验证新增任务和取消状态不丢失。P1 开放正式产品对象前完成新版全库备份恢复演练，P3 再加入多范围样例。屏障状态及不能降级的原因展示在平台维护信息中。

## 14. 动态验证和运行边界

本方案不授予动态验证权限。产品或对象存在、范围检查通过、请求制品存在、迁移完成都不能触发浏览器或目标访问。

动态验证仍要求用户明确启用并提供授权环境，范围限 `localhost`、`127.0.0.1`、`[::1]`。开关关闭、环境无效或缺少所需登录信息时记录 `SKIPPED`，继续静态流程。凭据继续按当前受控私密存储处理，不放入产品列表、对象快照和通用缓存。

实现和测试直接运行在 Windows/Linux 主机，不引入 Docker、Podman、Compose 或容器化浏览器。浏览器验证使用 Chrome DevTools MCP，不切换到 agent-browser；不得全局终止 Chrome/Chromium。完整动态运行的制品、日志和 HTTP exchange 同样执行产品归属检查。

本次仅编写设计文档，动态验证状态为 `SKIPPED`，没有启动平台、浏览器或访问测试目标。

## 15. 实施拆分与交付门槛

| 阶段 | 交付内容 | 完成门槛 |
|---|---|---|
| P0：模型与迁移基础 | SQLite 驱动决策、目录库、固定未定义产品、legacy adapter、ExecutionSpec、Runner v2 入口、在线预建与回滚 | 老资源完整可查；v1/v2 均经统一服务创建任务；迁移幂等、失败可恢复；完成回滚演练 |
| P1：产品空间 | 产品中心、切换、完整 v1/v2 路由映射、全资源归属校验、持久 SSE、产品级目录查询 | 全部页面、下载、事件、操作均按产品限定；不能只完成 UI |
| P2：对象生命周期 | 对象详情、编辑、归档、复制、未定义归属补录 | 并发迁移不漏子资源、不改变制品摘要 |
| P3：范围与执行契约 | scope-glob-v1、源码基线、普通目录、组件、多范围、跨范围分析、新版交付/验证契约 | 实际扫描及覆盖核算使用完整范围；源码漂移可定位；跨范围产物通过契约；不存在首目录回退 |
| P4：性能与回归 | 索引增量更新、缓存预算、SSE 恢复、故障及跨产品回归 | 达成性能目标并记录实际测试环境和测量结果 |

P1 即开始按产品索引查询，性能架构不能推迟到 P4。P3 的多范围选项只有在扫描、定位、裁决和报告消费者全部支持时才在页面启用。各阶段可以独立验收，但在 P3/P4 完成前不能宣称整份方案交付。

建议模块边界：`product-store` 负责产品，`target-store` 负责对象和范围，`resource-catalog` 负责派生索引与定位，`audit-application-service` 统一对象操作锁、意图和 Runner/ValidationRunner 派发，`ownership-service` 负责归属事务，`product-events` 负责持久空间事件，`source-scope-contract` 负责多范围输入。现有 Runner 只继续负责进程状态和执行，不再拥有 v2 对象登记。前端将空间状态与平台状态分离。文件名为建议，不要求一次性重写现有服务。

## 16. 验收矩阵

| 类别 | 关键用例 | 预期 |
|---|---|---|
| 默认兼容 | 空安装、仅旧项目、仅历史制品 | 都有唯一未定义产品，原资源可定位 |
| 普通目录 | 无 `.git` 的有效源码目录 | 可以登记与执行静态审计 |
| Runner 登记 | v2 新对象不写 `repositories.json` | application service 生成 Spec，Runner 可以创建并执行任务 |
| 组件范围 | 指定仓库子目录，父目录有其他源码 | 不扩大范围、不受父仓库 dirty 状态阻止 |
| 多目录 | 两个目录存在同名路径与跨服务调用 | 位置不冲突，联合分析可追溯到各范围 |
| 范围规则 | 包含/排除冲突、链接越界、父子目录重复 | 规则确定，越界拒绝或明确跳过，不静默重复 |
| 路径门禁 | 根目录、主目录本身、平台控制面、普通主目录下组件 | 前三类拒绝，普通组件允许；规则基于规范路径 |
| 检查竞态 | 编辑范围后旧 scope-check 才完成 | 旧版本不能覆盖新版本可用性 |
| 源码基线 | 启动后修改、增加、删除发现相关文件 | 收尾逐项指出漂移，任务不能正常完成；恢复仍核对原基线 |
| 跨范围契约 | 有跨服务流、无跨范围边、输入缺失三类样例 | 分别输出可追溯边、有效空结果、FAILED/残余缺口 |
| 产品隔离 | 用 A 路径读取/操作 B 的任务、报告、证据 | 404，批量导出也拒绝混入其他产品 |
| 切换竞态 | A 慢请求在进入 B 后返回 | B 页面不被覆盖，旧事件与终端轮询关闭 |
| 生命周期 | 归档时有运行、排队和暂停任务 | 运行任务可完成；不新增调度，不自动恢复暂停 |
| 补录归属 | 未定义对象带历史任务与完整验证记录 | 原子转入正式产品，旧路径不可继续操作 |
| 补录并发 | 预览后新任务入队、验证启动、版本变化、目标归档 | 共享对象事务使一方失败，所有资源归属一致 |
| 索引写回竞态 | 旧代次 job 在补录提交后完成 | job 按当前归属写入或 superseded，不能写回未定义 |
| 历史完整性 | 补录前后下载封存报告 | 资源 ID 和文件 SHA-256 相同 |
| 任务快照 | 对象编辑后恢复旧任务 | 使用原范围，不读取新配置 |
| 崩溃恢复 | 创建中断、索引中断、迁移事务失败 | 不重复启动、不丢权威配置、可恢复派生索引 |
| 兼容回滚 | P0/P1 切换后、v2 不可表达写入前回退 | 恢复旧服务并保持对象、任务、报告数量与摘要 |
| 缓存一致性 | 删除、取消、恢复、补录时旧查询仍在运行 | 旧结果不覆盖新代次，操作版本保持正确 |
| SSE 重启 | 保存序号后重启，再携带 Last-Event-ID 连接 | 序号继续递增；窗口外明确要求重同步 |
| 临时复用 | 同路径同规则重复创建、规则改变、对象已归档 | 默认复用前者，后两者不隐式复用 |
| 规模性能 | 冷启动、重复翻页、跨产品切换、批量制品更新 | 前台不执行全局扫描，达到规定测量目标 |
| 动态边界 | 未授权或无有效环境 | `SKIPPED`，不启动浏览器、不联系目标 |

自动化测试覆盖数据约束、服务端归属、迁移事务、API 与事件；人工页面验证覆盖切换、导航、分页和长列表。测试使用隔离的合成对象、模拟 Runner 及临时受控制品，不使用真实用户记录。按项目规定在 Windows/Linux 主机完成，不在当前 macOS 环境冒充已通过功能验收。

## 17. 主要风险及处理

| 风险 | 处理方式 |
|---|---|
| 只改项目表，执行链仍假定单仓库 | P3 全链契约审计与多范围端到端用例作为启用门槛 |
| 改归属破坏报告封存和旧资源 ID | 当前归属独立于不可变制品和存储键 |
| 查询目录与磁盘事实不同步 | Runner 事件、可重试索引作业、低频核对；展示更新时间 |
| 再次出现全局扫描阻塞列表 | 列表只查询按产品索引的摘要；完整验证放到后台或具体证据读取 |
| 产品分区被误认为团队权限隔离 | 明确第一版无成员/RBAC，保持现有本地受控平台定位 |
| 历史缺失信息被猜测成完整对象 | 使用只读历史对象与待核对记录，保留缺失原因 |
| 用户编辑目录后误认为旧任务测试了新代码 | 历史显示配置快照；恢复永远使用原快照 |
| SQLite 驱动在 Windows/Linux 安装或恢复不一致 | P0 对候选驱动做双平台原型并锁定版本，未通过不得开始目录迁移 |
| 旧索引 job 用过期产品归属回写 | job 不携带权威 product_id，事务提交时校验 ownership_generation |
| 迁移/验证/入队绕过共享锁 | 所有入口强制经过 application service 的 SQLite 对象事务 |
| 无 Git 期间源码变化导致证据失真 | 启动逐文件基线、位置绑定和收尾差异核对 |

本设计默认：先做业务空间和历史兼容，再完成对象范围及执行链升级；不把 Git 版本管理重新引入为前置条件。“未定义”永久可用，临时审计无需额外产品建模步骤。

## 18. R2 评审处理索引

以下指设计决策已落入本文，尚不代表实现或测试通过。M 编号对应本轮评审中“中优先级”的 1–15。

| 编号 | 修订结论 | 位置 |
|---|---|---|
| H1 | SQLite 唯一对象源；v1 薄适配；Spec 到 Runner；P0 完成执行桥接 | §8.1、§15 |
| H2 | job 写回事务读当前归属代次、校验输入；删除 tombstone 防复活 | §8.3、§16 |
| H3 | 逐文件启动基线、execution_binding、收尾差异及发现受影响定位 | §6.3、§7.4 |
| H4 | 专用角色、子阶段顺序、输入/输出 schema、校验器与消费方 | §7.3 |
| H5 | application service 独占派发入口；SQLite 短事务与持久保留项覆盖事务外窗口 | §8.2 |
| H6 | 旧 ID 分类型保留精确算法，新 ID 带 scheme；namespace 与路径/产品无关 | §6.4 |
| H7 | 资源子路由、平台端点和逐项 v1 兼容映射 | §9 |
| M1 | 生命周期与派生可用性分离；检查结果绑定版本与有效期 | §6.2–6.3 |
| M2 | 临时入口按路径和范围配置复用自身活动对象，可显式新建 | §4 |
| M3 | scope-glob-v1 语法、大小写及确定性样例 | §7.1–7.2 |
| M4 | 内部链接跳过，根路径 realpath；硬链接只复用读取不丢位置 | §7.1 |
| M5 | 明确根/主目录/平台控制面路径规则与规模阈值 | §7.1–7.2、§16 |
| M6 | 排队总数、可调度数、归档暂停数分列；恢复排队需明确动作 | §9.1、§11 |
| M7 | 只读历史对象默认归档；保留资源期间有意禁止删除 | §11 |
| M8 | 正式产品转移暂缓的理由及审批/链接/撤销演进条件 | §10 |
| M9 | 未定义补录已使创建时产品与当前产品不同，创建字段应保留 | §6.3 |
| M10 | 对象归档允许正在执行任务完成；取消仍走 cancelling 流程 | §11 |
| M11 | 在线影子库、持久增量、水位追平，再短暂停写切换 | §13.1 |
| M12 | 零新写入回退、最新兼容数据导出、不可兼容屏障及恢复演练 | §13.3、§15 |
| M13 | product_events 持久序号、重启续接和历史窗口 | §12.2 |
| M14 | 全进程与每产品双重缓存上限 | §12.3 |
| M15 | 已完成标注为非运行中分组，不代表成功终态 | §5.2 |
| L1 | 旧项目/Repository 到对象和源码范围的术语映射 | §2 |
| L2 | 改为“产品作用域路径前缀” | §13.2 |
| L3 | 移除未确定的负责人字段 | §6.1 |
| L4 | 对象补充 archived_at | §6.2 |
| L5 | 每资源类型页大小全局保存，其他查询状态按产品会话隔离 | §5.3 |
| L6 | 关键制品全量对账，辅助制品固定哈希排序抽样且保存样本 | §13.1 |
| L7 | 驱动候选与决策标准列为 P0 阻断项和部署风险 | §8、§15、§17 |
| L8 | 范围外依赖落到 scope-limitations 制品及报告范围限制段 | §7.2 |

当前代码已锁定 `node:sqlite` 和最低 Node 版本，但尚未通过 Windows/Linux 实测验收。性能阈值、遍历预算和缓存预算为初始设计值，修改时须同步平台配置与验收基准。
