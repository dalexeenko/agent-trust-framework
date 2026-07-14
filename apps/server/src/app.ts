import { timingSafeEqual } from "node:crypto";
import {
  ActionRequestSchema,
  assessRisk,
  authorize,
  TaskDeclarationSchema,
} from "@atf/core";
import cors from "@fastify/cors";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { z } from "zod";
import { TrustDatabase } from "./database.js";
import { GoogleExecutor, GoogleGuardrails } from "./google.js";

const AgentRegistrationSchema = z.object({
  name: z.string().trim().min(2).max(100),
  spiffeId: z.string().startsWith("spiffe://").optional(),
});

const DecisionSchema = z.object({
  approved: z.boolean(),
  approver: z.string().trim().min(2).max(200),
});

function bearer(request: FastifyRequest): string | undefined {
  const [scheme, token] = request.headers.authorization?.split(" ") ?? [];
  return scheme?.toLowerCase() === "bearer" ? token : undefined;
}

function safeEqual(left: string | undefined, right: string): boolean {
  if (!left) return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function buildApp(options?: { database?: TrustDatabase }) {
  const app = Fastify({ logger: process.env.NODE_ENV !== "test" });
  const database = options?.database ?? new TrustDatabase();
  const guardrails = new GoogleGuardrails();
  const executor = new GoogleExecutor();
  const approvalToken = process.env.APPROVAL_TOKEN ?? "dev-approve";
  const bootstrapToken = process.env.BOOTSTRAP_TOKEN ?? "dev-bootstrap";

  app.register(cors, { origin: true });

  app.addHook("onClose", async () => {
    database.close();
  });

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof z.ZodError) {
      return reply.code(400).send({ error: "invalid_request", issues: error.issues });
    }
    app.log.error(error);
    return reply.code(500).send({
      error: "internal_error",
      message: error instanceof Error ? error.message : "Unexpected error",
    });
  });

  app.get("/health", async () => ({
    status: "ok",
    safeguards: {
      approvalTokenConfigured: Boolean(process.env.APPROVAL_TOKEN),
      bootstrapTokenConfigured: Boolean(process.env.BOOTSTRAP_TOKEN),
      modelArmorConfigured: Boolean(process.env.MODEL_ARMOR_ENDPOINT),
      googleApplicationCredentials: Boolean(process.env.GOOGLE_APPLICATION_CREDENTIALS),
    },
  }));

  app.get("/.well-known/agent-card.json", async () => ({
    name: "Agent Trust Framework Gateway",
    description: "Purpose-based authorization and audited Google Cloud tool execution",
    url: process.env.PUBLIC_URL ?? "http://localhost:8787",
    version: "0.1.0",
    capabilities: { streaming: false, pushNotifications: false },
    defaultInputModes: ["application/json"],
    defaultOutputModes: ["application/json"],
    skills: [
      {
        id: "declare-purpose",
        name: "Declare a task purpose",
        description:
          "Request a scoped, expiring execution handle after a human approves the purpose.",
        tags: ["authorization", "governance", "google-cloud", "saif"],
      },
    ],
    securitySchemes: {
      agentApiKey: { type: "http", scheme: "bearer" },
    },
  }));

  app.get("/v1/governance/google-controls", async () => ({
    mandate: "Approve a purpose, not a permission",
    controls: [
      {
        concern: "Agent identity",
        implementation: "Local agent API key or asserted SPIFFE ID",
        googleTarget: "Agent Identity on Gemini Enterprise Agent Platform Runtime",
        productionUpgrade: "Verify mTLS/DPoP-bound Agent Identity at the gateway",
      },
      {
        concern: "Authorization",
        implementation: "Purpose, capability, resource, TTL, and action-budget envelope",
        googleTarget: "IAM allow/deny, Principal Access Boundary, VPC Service Controls",
        productionUpgrade: "Compile approvals into IAM Conditions and PAB policies",
      },
      {
        concern: "Guardrails",
        implementation: "Pre-execution screening with a local fail-safe adapter",
        googleTarget: "Model Armor",
        productionUpgrade: "Set MODEL_ARMOR_ENDPOINT to enforce the organization template",
      },
      {
        concern: "Interoperability",
        implementation: "A2A-compatible Agent Card",
        googleTarget: "Agent2Agent and Agent Gateway",
        productionUpgrade: "Add signed Agent Cards and authenticated A2A task exchange",
      },
      {
        concern: "Runtime",
        implementation: "Server-side ADC injection for allowlisted Vertex model resources",
        googleTarget: "Vertex AI Agent Engine / Gemini Enterprise",
        productionUpgrade: "Deploy beside Agent Runtime and use per-agent identity",
      },
      {
        concern: "Auditability",
        implementation: "Hash-chained append-only decision log",
        googleTarget: "Cloud Audit Logs, Security Command Center, Cloud Logging",
        productionUpgrade: "Export immutable events with agent and user principals",
      },
    ],
  }));

  app.post("/v1/agents", async (request, reply) => {
    if (!safeEqual(request.headers["x-bootstrap-token"] as string | undefined, bootstrapToken)) {
      return reply.code(401).send({ error: "invalid_bootstrap_token" });
    }
    const body = AgentRegistrationSchema.parse(request.body);
    return reply.code(201).send(database.createAgent(body.name, body.spiffeId));
  });

  const authenticateAgent = async (request: FastifyRequest, reply: FastifyReply) => {
    const token = bearer(request);
    const agent = token ? database.authenticateAgent(token) : undefined;
    if (!agent) {
      await reply.code(401).send({ error: "invalid_agent_identity" });
      return undefined;
    }
    return agent;
  };

  app.post("/v1/tasks", async (request, reply) => {
    const agent = await authenticateAgent(request, reply);
    if (!agent) return;
    const declaration = TaskDeclarationSchema.parse(request.body);
    const risk = assessRisk(declaration);
    return reply.code(202).send(database.createTask(agent.id, declaration, risk));
  });

  app.get<{ Params: { id: string } }>("/v1/tasks/:id", async (request, reply) => {
    const agent = await authenticateAgent(request, reply);
    if (!agent) return;
    const task = database.getTask(request.params.id);
    if (!task || task.agentId !== agent.id) return reply.code(404).send({ error: "task_not_found" });
    return task;
  });

  app.post<{ Params: { id: string } }>("/v1/tasks/:id/handle", async (request, reply) => {
    const agent = await authenticateAgent(request, reply);
    if (!agent) return;
    const task = database.getTask(request.params.id);
    if (!task || task.agentId !== agent.id) return reply.code(404).send({ error: "task_not_found" });
    const result = database.issueHandle(task.id);
    if (!result) {
      return reply.code(409).send({
        error: "handle_unavailable",
        message: "The task is not approved, expired, or its handle was already issued.",
      });
    }
    return reply.code(201).send(result);
  });

  app.get("/v1/review/tasks", async (request, reply) => {
    if (!safeEqual(request.headers["x-approval-token"] as string | undefined, approvalToken)) {
      return reply.code(401).send({ error: "invalid_approval_token" });
    }
    return database.listTasks();
  });

  app.post<{ Params: { id: string } }>("/v1/review/tasks/:id/decision", async (request, reply) => {
    if (!safeEqual(request.headers["x-approval-token"] as string | undefined, approvalToken)) {
      return reply.code(401).send({ error: "invalid_approval_token" });
    }
    const decision = DecisionSchema.parse(request.body);
    const task = database.decideTask(request.params.id, decision.approved, decision.approver);
    if (!task) return reply.code(409).send({ error: "task_not_pending" });
    return task;
  });

  app.get("/v1/review/audit", async (request, reply) => {
    if (!safeEqual(request.headers["x-approval-token"] as string | undefined, approvalToken)) {
      return reply.code(401).send({ error: "invalid_approval_token" });
    }
    const taskId =
      typeof (request.query as Record<string, unknown>).taskId === "string"
        ? ((request.query as Record<string, string>).taskId ?? undefined)
        : undefined;
    return database.listAudit(taskId);
  });

  app.post("/v1/gateway/execute", async (request, reply) => {
    const handle = bearer(request);
    const resolved = handle ? database.resolveHandle(handle) : undefined;
    if (!resolved) return reply.code(401).send({ error: "invalid_or_expired_handle" });
    const action = ActionRequestSchema.parse(request.body);
    const decision = authorize({
      task: resolved.task.declaration,
      taskStatus: resolved.task.status,
      taskExpiresAt: resolved.task.expiresAt,
      callsUsed: resolved.row.calls_used,
      action,
    });
    if (!decision.allowed) {
      database.appendAudit({
        agentId: resolved.task.agentId,
        taskId: resolved.task.id,
        handleId: resolved.row.id,
        eventType: "action.authorization",
        decision: "deny",
        reason: decision.reason,
        input: action,
        details: { capability: action.capability, resource: action.resource },
      });
      return reply.code(403).send({ error: "outside_approved_purpose", reason: decision.reason });
    }

    const screen = await guardrails.screen(action.input, resolved.task.declaration);
    if (!screen.allowed) {
      database.appendAudit({
        agentId: resolved.task.agentId,
        taskId: resolved.task.id,
        handleId: resolved.row.id,
        eventType: "action.guardrail",
        decision: "deny",
        reason: screen.reasons.join(", "),
        input: action.input,
        details: { provider: screen.provider },
      });
      return reply.code(403).send({ error: "guardrail_block", reasons: screen.reasons });
    }

    try {
      const result = await executor.execute(action);
      database.consumeHandle(resolved.row.id);
      database.appendAudit({
        agentId: resolved.task.agentId,
        taskId: resolved.task.id,
        handleId: resolved.row.id,
        eventType: "action.executed",
        decision: "allow",
        reason: decision.reason,
        input: action,
        details: {
          capability: action.capability,
          resource: action.resource,
          dryRun: action.dryRun,
          guardrailProvider: screen.provider,
        },
      });
      return { decision, guardrail: screen, result };
    } catch (error) {
      database.appendAudit({
        agentId: resolved.task.agentId,
        taskId: resolved.task.id,
        handleId: resolved.row.id,
        eventType: "action.failed",
        decision: "error",
        reason: error instanceof Error ? error.message : "execution failed",
        input: action,
        details: { capability: action.capability, resource: action.resource },
      });
      return reply.code(502).send({
        error: "upstream_execution_failed",
        message: error instanceof Error ? error.message : "Execution failed",
      });
    }
  });

  return app;
}
