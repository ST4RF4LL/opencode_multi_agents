---
name: detect-bac-risks
description: Compare intended database access policies with evidenced entry-to-database paths inside a BAC-enabled source audit packet, preserving unknown facts and adapting static candidates to the platform Finding v2 review chain.
---

# 越权策略与路径差分

用于工作包中的 `bac-analysis.v1`，不用于 blind 轨道，不执行目标请求。先读 `.opencode/lib/bac/workflow.md` 和 [输入契约](references/input-contract.md)。保持四元组 `{D,O,R,AC}`；租户、共享、字段、流程状态、复杂父子权限和非数据库资源继续原审计，不折算为 HAC。

使用独立策略会话提供的 ACP。专业源码会话只生产实际路径并比较，不因看到了缺失控制就修改预期策略。库/框架依赖只表示可能有能力，必须证明绑定和执行。缺少控制与有效控制都需要定位证据；没有事实是 UNKNOWN。

每条路径拆出明确数据库操作、调用者情景与必要分支，核对入口、同步/异步调用、主体传播、selector 数据流和所有 sink 前的有效控制。内部入口与外部入口采用相同规则；只有证据证明不可达才能抑制。

Java 的恢复细节加载 `java-access-path-analysis`。其他服务端框架至少核对：

- Django/DRF：URL/viewset/action 绑定，permission/object permission 的实际调用时机，`get_queryset` 与 ORM 条件；列表接口不能从 detail 的对象检查推导安全。
- Flask/FastAPI：路由、装饰器、dependency/中间件的作用域与参数传播，SQLAlchemy/原生 SQL 条件；依赖注入存在不代表每条路径都强制执行。
- 服务端 JavaScript/TypeScript：Express/Nest/Next 路由绑定、中间件/guard 顺序及排除项、ORM 查询与 session 来源；客户端隐藏按钮不是服务端控制。
- RPC/消息/任务：恢复实际触发链、服务身份与委托用户，确认异步切换后的上下文；无法恢复则保留 GAP。

使用平台 CLI 生成和封存结果。对每个原始候选写明接入、证据不足、反证否定或同次重复去向；只有接入项生成 Finding v2，并经当前工作包、correlation、adjudication、三方复核。所有人类可读说明使用中文，证据必须来自实际检查，不填虚构默认值。

需要核对已保存差分时使用 `scripts/validate_bac_findings.py`，参数见平台 workflow 的恢复部分。原始方法与改编来源摘要见 [provenance.json](references/provenance.json)。
