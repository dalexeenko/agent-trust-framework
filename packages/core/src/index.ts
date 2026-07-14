import { z } from "zod";

export const capabilities = [
  "google.vertex.generate",
  "google.modelarmor.sanitize",
  "google.agentspace.search",
  "google.a2a.send",
  "google.cloud.read",
  "google.cloud.write",
] as const;

export const CapabilitySchema = z.enum(capabilities);
export type Capability = z.infer<typeof CapabilitySchema>;

export const TaskDeclarationSchema = z.object({
  purpose: z.string().trim().min(12).max(500),
  capabilities: z.array(CapabilitySchema).min(1).max(12),
  resources: z.array(z.string().trim().min(1).max(500)).min(1).max(30),
  expiresInSeconds: z.number().int().min(60).max(3600).default(900),
  constraints: z
    .object({
      maxCalls: z.number().int().min(1).max(1_000).default(20),
      maxRecords: z.number().int().min(1).max(10_000).optional(),
      allowExternalCommunication: z.boolean().default(false),
      allowSensitiveData: z.boolean().default(false),
      requireModelArmor: z.boolean().default(true),
    })
    .default({
      maxCalls: 20,
      allowExternalCommunication: false,
      allowSensitiveData: false,
      requireModelArmor: true,
    }),
  context: z.record(z.string(), z.string().max(500)).optional(),
});

export type TaskDeclaration = z.infer<typeof TaskDeclarationSchema>;

export const ActionRequestSchema = z.object({
  capability: CapabilitySchema,
  resource: z.string().trim().min(1).max(500),
  operation: z.string().trim().min(1).max(100),
  input: z.unknown().optional(),
  dryRun: z.boolean().default(false),
});

export type ActionRequest = z.infer<typeof ActionRequestSchema>;

export type RiskFactor = {
  name: string;
  points: number;
  explanation: string;
};

export type RiskAssessment = {
  score: number;
  level: "low" | "medium" | "high" | "critical";
  factors: RiskFactor[];
};

const capabilityRisk: Record<Capability, number> = {
  "google.modelarmor.sanitize": 0,
  "google.vertex.generate": 8,
  "google.agentspace.search": 12,
  "google.a2a.send": 25,
  "google.cloud.read": 18,
  "google.cloud.write": 40,
};

export function assessRisk(task: TaskDeclaration): RiskAssessment {
  const factors: RiskFactor[] = [];
  const capabilityPoints = Math.max(...task.capabilities.map((item) => capabilityRisk[item]));
  factors.push({
    name: "highest capability impact",
    points: capabilityPoints,
    explanation: `Highest requested capability contributes ${capabilityPoints} points.`,
  });

  if (task.resources.some((resource) => resource.includes("*"))) {
    factors.push({
      name: "wildcard scope",
      points: 20,
      explanation: "A wildcard can expand the affected resource set.",
    });
  }
  if (task.constraints.allowExternalCommunication) {
    factors.push({
      name: "external communication",
      points: 15,
      explanation: "The task may transmit information outside the trust boundary.",
    });
  }
  if (task.constraints.allowSensitiveData) {
    factors.push({
      name: "sensitive data",
      points: 20,
      explanation: "The task may process sensitive data.",
    });
  }
  if (!task.constraints.requireModelArmor) {
    factors.push({
      name: "guardrail bypass",
      points: 15,
      explanation: "Runtime prompt and response screening is not required.",
    });
  }
  if (task.constraints.maxCalls > 100) {
    factors.push({
      name: "large action budget",
      points: 10,
      explanation: "The task can perform more than 100 actions.",
    });
  }

  const score = Math.min(100, factors.reduce((sum, factor) => sum + factor.points, 0));
  const level =
    score >= 80 ? "critical" : score >= 55 ? "high" : score >= 25 ? "medium" : "low";
  return { score, level, factors };
}

function matchesResource(pattern: string, resource: string): boolean {
  if (!pattern.includes("*")) return pattern === resource;
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
  return new RegExp(`^${escaped}$`).test(resource);
}

export type AuthorizationInput = {
  task: TaskDeclaration;
  taskStatus: "pending" | "approved" | "denied" | "expired";
  taskExpiresAt: string;
  callsUsed: number;
  action: ActionRequest;
  now?: Date;
};

export type AuthorizationDecision = {
  allowed: boolean;
  reason: string;
};

export function authorize(input: AuthorizationInput): AuthorizationDecision {
  if (input.taskStatus !== "approved") {
    return { allowed: false, reason: `task is ${input.taskStatus}` };
  }
  if (new Date(input.taskExpiresAt) <= (input.now ?? new Date())) {
    return { allowed: false, reason: "task approval has expired" };
  }
  if (!input.task.capabilities.includes(input.action.capability)) {
    return { allowed: false, reason: "capability was not approved for this purpose" };
  }
  if (!input.task.resources.some((pattern) => matchesResource(pattern, input.action.resource))) {
    return { allowed: false, reason: "resource is outside the approved blast radius" };
  }
  if (input.callsUsed >= input.task.constraints.maxCalls) {
    return { allowed: false, reason: "task action budget is exhausted" };
  }
  if (
    input.action.capability === "google.a2a.send" &&
    !input.task.constraints.allowExternalCommunication
  ) {
    return { allowed: false, reason: "external communication was not approved" };
  }
  return { allowed: true, reason: "action matches the approved purpose envelope" };
}
