#!/usr/bin/env node

import {
  auditTodoSummary,
  claimAuditTodo,
  completeAuditTodoPacket,
  createEmptyAuditTodo,
  failAuditTodoPacket,
  initializeAuditTodo,
  listAuditTodoItems,
  recoverExpiredAuditTodo,
} from "./audit-todo-core.mjs";

function parse(argv) {
  const [command, ...rest] = argv;
  const values = {};
  for (let index = 0; index < rest.length; index += 1) {
    const entry = rest[index];
    if (!entry.startsWith("--")) throw new Error(`未知参数：${entry}`);
    const [key, inline] = entry.slice(2).split("=", 2);
    if (!key) throw new Error("参数名不能为空。");
    if (inline !== undefined) values[key] = inline;
    else if (rest[index + 1] && !rest[index + 1].startsWith("--")) values[key] = rest[++index];
    else values[key] = true;
  }
  return { command, values };
}

function required(values, key) {
  const value = values[key];
  if (typeof value !== "string" || !value) throw new Error(`缺少 --${key}`);
  return value;
}

function number(values, key, fallback) {
  return values[key] === undefined ? fallback : Number(values[key]);
}

function boolean(values, key, fallback = false) {
  if (values[key] === undefined) return fallback;
  return values[key] === true || values[key] === "true" || values[key] === "1";
}

async function main() {
  const { command, values } = parse(process.argv.slice(2));
  const todoPath = required(values, "todo");
  let result;
  switch (command) {
    case "create":
      result = await createEmptyAuditTodo({ todoPath, auditId: required(values, "audit-id") });
      break;
    case "init":
      result = await initializeAuditTodo({ todoPath, auditId: required(values, "audit-id"), planPath: required(values, "plan") });
      break;
    case "stats":
      result = await auditTodoSummary(todoPath);
      break;
    case "claim":
      result = await claimAuditTodo({
        todoPath,
        packetLimit: number(values, "packets", 4),
        itemsPerPacket: number(values, "items", 12),
        leaseMinutes: number(values, "lease-minutes", 30),
      });
      break;
    case "complete":
      result = await completeAuditTodoPacket({
        todoPath,
        packetId: required(values, "packet"),
        handoffPath: required(values, "handoff"),
        reportsRoot: required(values, "reports-root"),
      });
      break;
    case "fail":
      result = await failAuditTodoPacket({
        todoPath,
        packetId: required(values, "packet"),
        reason: required(values, "reason"),
        retry: boolean(values, "retry", true),
        maxAttempts: number(values, "max-attempts", 3),
      });
      break;
    case "recover":
      result = await recoverExpiredAuditTodo({ todoPath });
      break;
    case "list":
      result = await listAuditTodoItems({
        todoPath,
        status: typeof values.status === "string" ? values.status : null,
        offset: number(values, "offset", 0),
        limit: number(values, "limit", 100),
      });
      break;
    default:
      throw new Error("用法：audit-todo.mjs <create|init|stats|claim|complete|fail|recover|list> --todo <path> ...");
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
