#!/usr/bin/env node
import { parseKnowledgeArgs, queryKnowledge } from "../lib/knowledge-workflow.mjs";

try {
  const request = parseKnowledgeArgs(process.argv.slice(2));
  if (request.help) process.stdout.write(`只读知识检索（不启动服务、不执行规则或目标）：
  node .opencode/scripts/knowledge-query.mjs status [--root PATH]
  node .opencode/scripts/knowledge-query.mjs search --track coverage --query "SQL 查询边界" [--kind mechanism] [--limit 5] [--offset 0]
  node .opencode/scripts/knowledge-query.mjs search --track seeded-variant --kind case --query CWE-89 --filter product=PRODUCT
  node .opencode/scripts/knowledge-query.mjs show --track coverage --id MECH-SQL-001
环境变量：AUDIT_KNOWLEDGE_ROOT、AUDIT_KNOWLEDGE_PYTHON；AUDIT_KNOWLEDGE_ENABLED=false 关闭。
默认先查根因机制。案例与检测器按 ID 读取，保留来源摘要与质量状态。\n`);
  else process.stdout.write(`${JSON.stringify(await queryKnowledge(request))}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({ status: "ERROR", reason: error.message })}\n`); process.exitCode = 2;
}
