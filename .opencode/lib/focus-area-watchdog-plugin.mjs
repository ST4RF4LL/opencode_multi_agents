import { inspectFocusAreaCoverage, formatFocusAreaReminder } from "../scripts/focus-area-watchdog.mjs";

// OpenCode's tool-result hook delivers reminders to the same live session;
// it does not start another process, issue a user prompt or interrupt analysis.
export default async function focusAreaWatchdogPlugin({ watchdogEnvironment = process.env } = {}) {
  const todoPath = watchdogEnvironment.AUDIT_TODO_PATH;
  const reportsRoot = watchdogEnvironment.AUDIT_REPORTS_ROOT;
  if (!todoPath || !reportsRoot) return {};
  const agents = new Map(), delivered = new Map();
  const relevant = agent => agent === "security-audit-orchestrator" || /^(?:java|web|python|c-cpp)-source-auditor$/.test(agent ?? "") || ["ai-security-auditor", "platform-security-auditor"].includes(agent);
  async function reminder(sessionID, agent, force = false) {
    if (!relevant(agent)) return "";
    const prior = delivered.get(sessionID);
    if (!force && prior && Date.now() - prior.at < 15_000) return "";
    try {
      const check = await inspectFocusAreaCoverage({ todoPath, reportsRoot, agentName: agent === "security-audit-orchestrator" ? null : agent });
      const message = formatFocusAreaReminder(check);
      if (!message) { delivered.delete(sessionID); return ""; }
      if (prior?.fingerprint === check.fingerprint && Date.now() - prior.at < 60_000) return "";
      delivered.set(sessionID, { at: Date.now(), fingerprint: check.fingerprint });
      return message;
    } catch {
      const fingerprint = "UNAVAILABLE";
      if (prior?.fingerprint === fingerprint && Date.now() - prior.at < 60_000) return "";
      delivered.set(sessionID, { at: Date.now(), fingerprint });
      return "[Focus Area watchdog] 覆盖检查 UNAVAILABLE：无法读取或校验任务清单。请运行 audit-todo stats / check 排查；不能把检查失败当作全部覆盖。";
    }
  }
  return {
    "chat.message": async input => { if (input.agent) agents.set(input.sessionID, input.agent); },
    "tool.execute.after": async (input, output) => {
      const agent = input.tool === "task" ? input.args?.subagent_type : agents.get(input.sessionID);
      const message = await reminder(input.sessionID, agent, input.tool === "task" || /audit-todo.*(?:complete|check)/.test(input.args?.command ?? ""));
      if (message) output.output = `${output.output ?? ""}\n\n${message}`;
    },
    "experimental.chat.system.transform": async (input, output) => {
      const message = await reminder(input.sessionID, agents.get(input.sessionID));
      if (message) output.system.push(message);
    },
  };
}
