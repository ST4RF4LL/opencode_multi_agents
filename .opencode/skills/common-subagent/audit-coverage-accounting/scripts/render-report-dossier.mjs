const text = value => String(value ?? "未记录").replaceAll("\r", "").replaceAll("|", "\\|");
const cell = value => text(value).replaceAll("\n", " ");
const valueText = value => typeof value === "string" ? value : JSON.stringify(value);
const list = (values, empty = "未记录。") => values?.length ? values.map(value => `- ${text(valueText(value))}`) : [`- ${empty}`];
const facts = indexes => indexes?.length ? indexes.map(index => `E${index}`).join("、") : "未绑定事实索引";
const location = value => value ? `${value.file}:${value.line_start}${value.line_end && value.line_end !== value.line_start ? `-${value.line_end}` : ""}` : "未记录位置";
const label = state => ({ TRUE_POSITIVE: "真实漏洞", FALSE_POSITIVE: "误报", INCONCLUSIVE: "证据不足", CONFIRMED: "已取得动态支持证据", UNCONFIRMED: "未取得动态支持证据", SKIPPED: "已跳过", NOT_TESTED: "未执行", NOT_RUN: "未执行", AVAILABLE: "已有运行记录", SUPPORTS: "支持", REFUTES: "反驳", REFUTED: "已反驳", PRESENT: "存在", ABSENT: "未发现", UNKNOWN: "未知", COMPLETED: "已执行", SUPPORTED: "支持", COUNTEREVIDENCE: "反证", NOT_APPLICABLE: "不适用", SUPPORTED_STATIC: "静态支持", SUPPORTED_RUNTIME: "运行支持", CONDITIONAL: "条件未满足", CONTRADICTED: "已反驳", PROVEN: "已证明", UNRESOLVED: "未解决", DEPLOYMENT_UNKNOWN: "部署条件未知" })[state] ?? cell(state);
const source = binding => binding ? `\`${cell(binding.artifact)}\` ${cell(binding.json_pointer)}（SHA-256：\`${cell(binding.digest)}\`）` : "未绑定上游制品";

function codeBlock(value, language = "text") {
  const runs = String(value).match(/`+/g) ?? [];
  const fence = "`".repeat(Math.max(3, ...runs.map(run => run.length + 1)));
  return [`${fence}${language}`, String(value), fence, ""];
}

export function runtimeDetail(runtime) {
  if (!runtime) return ["未提供运行验证记录，不能推定已复现。", ""];
  const rows = [`执行状态：${label(runtime.status)}。${text(runtime.reason ?? "")}`, ""];
  if (runtime.evidence_bindings?.length) rows.push("运行证据索引（相对于运行记录所在目录）：", "",
    "| 证据 ID | 制品 | SHA-256 |", "|---|---|---|",
    ...runtime.evidence_bindings.map(binding => `| ${cell(binding.id ?? "历史记录")} | ${cell(binding.path)} | ${cell(binding.sha256)} |`), "");
  if (runtime.protocol === "legacy-quick") {
    const result = runtime.result;
    if (result) rows.push(`耗时：${result.duration_ms} ms；清理：${cell(result.cleanup_status ?? "未记录")}。`, "",
      "运行证据引用：", "", ...list(result.evidence_refs, "没有动态证据引用。"), "", "运行限制与缺口：", "", ...list(result.gaps, "无额外记录的动态缺口。"), "");
    return rows;
  }
  if (!runtime.packets?.length) return [...rows, "本项没有已绑定的动态测试包；上文复现步骤仅是设计，不是执行记录。", ""];
  for (const packet of runtime.packets) {
    rows.push(`**${cell(packet.phase)} / ${cell(packet.id)}**：执行=${label(packet.execution_status)}；结果=${label(packet.outcome)}；清理=${cell(packet.cleanup_status)}。`, "",
      `假设：${cell(packet.hypothesis_id ?? "无")}；候选：${cell(packet.finding_id ?? "未映射源码候选")}；输入摘要：${cell(packet.input_digest ?? "无")}；结果：${cell(packet.result_path ?? "无结果文件")} / ${cell(packet.result_digest ?? "无")}。`, "",
      text(packet.result?.summary ?? packet.summary ?? packet.reason ?? "未记录观察摘要。"), "",
      "实际观察：", "", ...list(packet.result?.observations, "没有逐项观察记录。"), "",
      "运行证据引用：", "", ...list(packet.result?.evidence_ids ?? packet.evidence_ids, "没有绑定运行证据。"), "",
      "运行限制与缺口：", "", ...list(packet.result?.gaps, "未记录额外运行证据缺口。"), "");
    if (packet.result?.proof) rows.push("应用层证明记录：", "", ...codeBlock(JSON.stringify(packet.result.proof, null, 2), "json"));
    for (const change of packet.result?.changes ?? []) rows.push(`- 测试修改及清理记录：${text(valueText(change))}`);
    rows.push("");
  }
  return rows;
}

export function renderFindingDossier(row, { excluded = false } = {}) {
  const dossier = row.dossier, finding = dossier.finding, decision = dossier.adjudication;
  const detail = finding.report_details, surface = finding.attack_surface;
  const heading = excluded ? "#####" : "###", section = `${heading}#`;
  const rows = [
    `${heading} ${excluded ? "候选处置" : `[${cell(row.cvss?.severity)} ${row.cvss?.base_score}]`} ${cell(row.title)}`, "",
    `- **Finding ID**：\`${cell(row.finding_id)}\`；**最终结论**：${label(row.state)}。`,
    `- **漏洞类型 / 责任域**：${cell(row.vulnerability_type_id)} / ${cell(row.domain)}；**Focus Area**：${cell(finding.routing.focus_area_id)}。`,
    `- **主要漏洞位置**：\`${cell(location(finding.locations.primary))}\`。`,
    `- **受影响入口**：${cell(surface.exposure.surface)}；**认证要求**：${cell(surface.auth_scope.state)}。`,
    `- **身份与边界**：${cell(surface.identities.attacker)} → ${cell(surface.identities.effective_principal)}；${cell(surface.boundary_crossing.from)} → ${cell(surface.boundary_crossing.to)}。`, "",
    `${section} 漏洞成因与行为差异`, "",
    text(detail?.root_cause.summary ?? decision.decision_rationale), "",
    ...(detail ? [`- 应有行为：${text(detail.root_cause.expected_behavior)}`, `- 实际行为：${text(detail.root_cause.actual_behavior)}`, ""] : []),
    `${section} 代码位置与证据链`, "",
  ];
  finding.evidence.facts.forEach((fact, index) => {
    rows.push(`**E${index} · ${cell(fact.kind)} · \`${cell(location(fact.locator))}\`**`, "", text(fact.claim), "",
      `取证方法：${cell(fact.method)}；置信度：${cell(fact.confidence)}；源码摘要：\`${cell(fact.locator.source_digest)}\`。`, "");
  });
  for (const snippet of detail?.code_context?.snippets ?? []) {
    rows.push(`代码上下文 · E${snippet.evidence_fact_index} · \`${cell(location(finding.evidence.facts[snippet.evidence_fact_index]?.locator))}\`（上游记录${snippet.redacted ? "，已脱敏" : ""}）：`, "",
      ...codeBlock(snippet.text, snippet.language));
  }
  if (!detail?.code_context || detail.code_context.state === "UNAVAILABLE") rows.push(`代码上下文缺口：${text(detail?.code_context?.reason ?? "上游未提供代码片段；目前只有路径、行号与证据陈述。")}`, "");
  rows.push("**专业审计提供的路径**", "");
  const path = detail?.path ?? [];
  path.forEach((step, index) => rows.push(`${index + 1}. ${text(step.description)}（${facts(step.evidence_fact_indexes)}）`));
  if (!path.length) rows.push("上游未提供按事实索引逐步绑定的路径。");
  rows.push("", `**独立裁决的语义路径**：${label(decision.semantic_proof?.path?.state)}`, "",
    ...(decision.semantic_proof?.path?.steps ?? []).map((step, index) => `${index + 1}. ${text(step)}`), "",
    `输入事实：${facts(decision.semantic_proof?.source_fact_indexes)}；危险操作/配置事实：${facts(decision.semantic_proof?.sink_or_config_fact_indexes)}。`, "");
  const framework = decision.semantic_proof?.framework;
  rows.push(`框架/版本依据：${cell(framework?.component)} / ${cell(framework?.version_or_commit)}；API/配置：${cell(framework?.api_or_configuration)}。`, "",
    ...list(framework?.evidence, "未记录框架语义证据。"), "",
    text(decision.semantic_proof?.security_effect?.rationale ?? "未记录安全效果的语义证明。"), "",
    `${section} 利用前提、影响与限制`, "", ...list(surface.preconditions?.map(item => `${item.description}（${item.feasibility}；${facts(item.evidence_fact_indexes)}）`), "未记录额外前置条件。"), "",
    `安全影响：${text(surface.impact.outcome)}`, "", `影响范围：${cell(surface.target_reach.state)}；${text(surface.target_reach.rationale)}`, "",
    "适用假设：", "", ...list(finding.uncertainty?.assumptions, "未记录额外假设。"), "", "审计盲区：", "", ...list(surface.blindspots, "未记录盲点。"), "",
    `攻击面独立复核：${cell(decision.attack_surface_review?.disposition)}；${text(decision.attack_surface_review?.rationale)}`, "",
    ...list(decision.attack_surface_review?.evidence, "未记录攻击面复核证据。"), "", "攻击面结论限制：", "", ...list(decision.attack_surface_review?.limitations, "未记录额外攻击面限制。"), "",
    `${section} 已检查的防护与反证`, "",
    "| 防护层次 | 状态 | 判断依据 | 证据 |", "|---|---|---|---|",
    ...(decision.guards ?? []).map(guard => `| ${cell(guard.scope)} | ${cell(guard.state)} | ${cell(guard.rationale)} | ${cell(guard.evidence?.join("；"))} |`), "",
    "专业审计记录的保护与控制：", "", ...list([...(finding.guards ?? []), ...(surface.controls ?? [])], "未记录额外保护或控制。"), "",
    ...list(surface.counterevidence?.map(item => `${item.claim}；处理：${item.disposition}（${facts(item.evidence_fact_indexes)}）`), "未记录反证，不能据此推定不存在反证。"), "",
    "矛盾事实及裁决引用：", "", ...list(finding.contradictions, "未记录矛盾事实。"), ...list(decision.contradiction_refs, "裁决未引用矛盾项。"), "",
    `独立反方主张：${text(decision.counterclaim?.claim)}；处置：${label(decision.counterclaim?.outcome)}。`, "",
    ...list(decision.counterclaim?.evidence, "未记录反方处置证据。"), "", "阻断问题：", "", ...list(decision.blocking_questions, "无记录中的阻断问题。"), "",
    `${section} 复现设计（未执行）`, "",
  );
  if (detail) rows.push(`环境要求：${text(detail.reproduction.environment_requirements)}`, "", ...list(detail.reproduction.preconditions, "无额外复现前提。"), "",
    ...detail.reproduction.steps.map((step, index) => `${index + 1}. ${text(step)}`), "",
    `安全行为预期：${text(detail.reproduction.expected_secure_result)}`, "",
    `漏洞行为预期：${text(detail.reproduction.expected_vulnerable_result)}`, "");
  else rows.push("上游未提供可复核的复现步骤，不生成推测性请求或测试结果。", "");
  rows.push(`${section} 动态测试实际记录`, "", ...runtimeDetail(dossier.runtime), `${section} 独立复核与最终裁定`, "");
  for (const review of dossier.reviews) {
    rows.push(`**${({ AFFIRMATIVE: "正方主张", NEGATIVE: "反方反例", MODERATOR: "裁定方" })[review.role]}**：${label(review.review.verdict)}`, "",
      `会话：${cell(review.session_id)}；复核模式：${cell(review.review.review_mode ?? "历史协议未记录")}；事实包摘要：${cell(review.review.fact_packet_digest ?? "历史协议未记录")}。`, "",
      ...list(review.review.claims), "", text(review.review.reasoning), "",
      "主张依据：", "", ...list(review.review.evidence_refs, "未列出主张证据引用。"), "", "实际复核证据：", "",
      ...list(review.review.checked_evidence_refs, "历史协议未列出实际复核证据。"), "", "复核缺口：", "", ...list(review.review.gaps, "未记录额外复核缺口。"), "");
    if (review.review.runtime_review) rows.push(`运行证据判断：${label(review.review.runtime_review.evidence_validity)}；${text(review.review.runtime_review.reasoning)}`, "",
      ...list(review.review.runtime_review.packet_ids, "没有参与判断的动态测试包。"), "");
  }
  rows.push(`最终理由：${text(row.validation?.rationale ?? decision.decision_rationale)}`, "",
    `${section} 修复建议与回归标准`, "", text(finding.remediation.summary), "");
  if (detail) {
    detail.remediation.changes.forEach((change, index) => rows.push(`${index + 1}. **${cell(change.location)}**：${text(change.action)} 原因：${text(change.rationale)}`));
    rows.push("", "临时缓解：", "", ...list(detail.remediation.temporary_mitigations, "未提供临时缓解方案。"), "",
      "兼容性与实施注意：", "", ...list(detail.remediation.compatibility_notes, "未记录兼容性说明。"), "",
      "| 用例类型 | 场景 | 通过标准 |", "|---|---|---|",
      ...detail.regression_tests.map(test => `| ${test.kind === "SECURITY" ? "安全回归" : "正常功能回归"} | ${cell(test.scenario)} | ${cell(test.expected_result)} |`), "");
  } else rows.push("修复步骤、修改位置和安全/正常功能回归用例未由上游提供。", "");
  if (row.cvss) rows.push(`${section} 风险评分依据`, "", `CVSS 3.1：\`${cell(row.cvss.vector)}\`；${row.cvss.base_score} / ${cell(row.cvss.severity)}。`, "",
    text(row.cvss.rationale), "", "评分假设：", "", ...list(row.cvss.assumptions, "未记录评分假设。"), "", "评分证据：", "", ...list(row.cvss.evidence_refs, "未列出评分证据。"), "");
  rows.push(`${section} 交付缺口与证据溯源`, "", ...list(dossier.missing_sections, "本项所需内容字段已提供；字段齐全不代表证据必然正确。"), "",
    `- 原始候选：${source(dossier.source)}`, `- 独立裁决：${source(row.source)}`, `- 运行记录：${source(dossier.runtime.source)}`,
    `- 最终路由：${source(row.validation?.source)}`, ...(row.cvss ? [`- 评分制品：${source(row.cvss.source)}`] : []),
    `- 原始候选对象 SHA-256：\`${cell(row.finding_object_digest)}\``,
    ...list(dossier.origins.source_reports, "未记录额外的专业报告来源。"),
    ...(dossier.origins.artifact ? [`- 原始候选制品：${text(valueText(dossier.origins.artifact))}`] : []),
    ...dossier.reviews.map(review => `- ${review.role}：${source(review.source)}`), "");
  return rows;
}

export function renderChainDetails(chain) {
  return [`#### ${cell(chain.chain_id)} · ${label(chain.assessment_state)}`, "",
    ...(chain.steps ?? []).map((step, index) => `${index + 1}. **${cell(step.step_id)} / ${label(step.evidence_state)}**：${text(step.claim)}；漏洞证据：${cell(step.evidence_refs?.join("、"))}；阻断缺口：${cell(step.blocking_gap_ids?.join("、") || "无")}。`), "",
    ...(chain.transitions ?? []).map(item => `- 连接 ${cell(item.transition_id)}：${cell(item.requires?.join("、"))} → ${cell(item.produces?.join("、"))}；${label(item.status)}；证据：${cell(item.evidence_refs?.join("、"))}。`), "",
    ...list(chain.gaps, "未记录链路缺口。"), "", `来源：${source(chain.source)}`, ""];
}
