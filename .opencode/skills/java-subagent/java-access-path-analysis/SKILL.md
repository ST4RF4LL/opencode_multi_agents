---
name: java-access-path-analysis
description: Recover evidenced Java entry-to-database paths and effective role/owner controls for BAC-enabled audit packets, including Spring security composition, ORM predicates, RPC, messages, and scheduled triggers.
---

# Java 数据库访问路径

配合 `detect-bac-risks`，使用已冻结的入口、函数和敏感操作清单。此 skill 生产实际实现事实，不生成预期 ACP，不改变原 java-idor 的租户/父子/字段权限审计范围。

1. 确认 Spring MVC/WebFlux/JAX-RS/Servlet 的真实路由绑定；RPC、消息与调度恢复服务导出、监听注册和触发链。接口声明或注解命中只是锚点。
2. 逐路径恢复 controller/handler → service → mapper/repository → SQL/持久化操作。MyBatis XML 确认 namespace、statement ID、动态条件；JPA 确认派生查询、@Query、实体表映射、flush/dirty tracking。save/upsert 不按名字直接归为 CREATE。
3. 同一入口的每个数据库操作、不同授权分支、批处理和替代调用入口分别建 path_id。路径记录完整调用链和结构化证据，未知的反射/动态代理/生成代码保留 GAP。
4. 区分请求用户、服务账号、委托用户和任务身份；确认 SecurityContext、session/JWT claim 的信任来源与异步传播。攻击者传入的 userId/ownerId 不是当前受信任主体。
5. 合成 SecurityFilterChain 的顺序与 matcher、permitAll、过滤器/拦截器、方法安全是否启用、代理自调用、全局异常/拒绝分支、service 自定义检查及查询级 owner 条件。部署层未提供的事实保持 UNKNOWN。
6. VAC 必须证明适当角色约束先于 sink 并 fail closed；HAC 必须证明当前受信任用户和资源直接 owner 的约束在读写前成立。批量逐项核对，查询过滤可作为排除机制。身份传播和单纯 tenant 条件不能替代 HAC。

每个 true/false 事实附定位证据；观察范围不足时用 null。包括内部路径在内，都不因“内网”“没有直接外部调用”而降低差分可信度。明确不可达必须提供条件/配置/调用证据；源码未搜索到调用者不是不可达证明。

按 shared input-contract 填写 paths、api_catalog 与 caller_context，保持预期策略只读。实际策略绑定须有 D/O 和期望角色的语义依据；低权限调用管理操作时绑定 ADMIN 策略，同时保留低权限 caller_context。完成后由 control-driven 执行差分与 Finding 复查，三个 lens 继续正常交付。
