const BASE_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  PR: {
    U: { N: 0.85, L: 0.62, H: 0.27 },
    C: { N: 0.85, L: 0.68, H: 0.5 },
  },
};

function roundUp(value) {
  return Math.ceil((value - Number.EPSILON) * 10) / 10;
}

export function parseCvssV31Vector(vector) {
  if (typeof vector !== "string") throw new Error("CVSS vector must be a string");
  const parts = vector.split("/");
  if (parts.shift() !== "CVSS:3.1") throw new Error("CVSS vector must use CVSS:3.1");
  const metrics = Object.create(null);
  for (const part of parts) {
    const [metric, value, ...extra] = part.split(":");
    if (extra.length > 0 || !BASE_METRICS.includes(metric) || !value || metrics[metric]) {
      throw new Error(`Invalid or duplicate CVSS base metric: ${part}`);
    }
    metrics[metric] = value;
  }
  if (Object.keys(metrics).length !== BASE_METRICS.length || BASE_METRICS.some(metric => !metrics[metric])) {
    throw new Error("CVSS vector must contain every base metric exactly once");
  }
  if (!WEIGHTS.AV[metrics.AV] || !WEIGHTS.AC[metrics.AC] || !WEIGHTS.UI[metrics.UI]
    || !["U", "C"].includes(metrics.S) || !WEIGHTS.PR[metrics.S][metrics.PR]
    || !Object.hasOwn(WEIGHTS.CIA, metrics.C) || !Object.hasOwn(WEIGHTS.CIA, metrics.I) || !Object.hasOwn(WEIGHTS.CIA, metrics.A)) {
    throw new Error("CVSS vector contains an unsupported base metric value");
  }
  return metrics;
}

export function severityForCvssBaseScore(score) {
  if (!Number.isFinite(score) || score < 0 || score > 10) throw new Error("CVSS base score is out of range");
  if (score === 0) return "None";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}

export function scoreCvssV31(vector) {
  const metrics = typeof vector === "string" ? parseCvssV31Vector(vector) : vector;
  const impactSubScore = 1 - ((1 - WEIGHTS.CIA[metrics.C]) * (1 - WEIGHTS.CIA[metrics.I]) * (1 - WEIGHTS.CIA[metrics.A]));
  const impact = metrics.S === "U"
    ? 6.42 * impactSubScore
    : 7.52 * (impactSubScore - 0.029) - 3.25 * ((impactSubScore - 0.02) ** 15);
  const exploitability = 8.22 * WEIGHTS.AV[metrics.AV] * WEIGHTS.AC[metrics.AC]
    * WEIGHTS.PR[metrics.S][metrics.PR] * WEIGHTS.UI[metrics.UI];
  const baseScore = impact <= 0
    ? 0
    : roundUp(Math.min((metrics.S === "U" ? 1 : 1.08) * (impact + exploitability), 10));
  return {
    vector: `CVSS:3.1/${BASE_METRICS.map(metric => `${metric}:${metrics[metric]}`).join("/")}`,
    base_score: baseScore,
    severity: severityForCvssBaseScore(baseScore),
  };
}
