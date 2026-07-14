import { createHash, randomBytes, randomUUID } from "node:crypto";
import Database from "better-sqlite3";
import type { RiskAssessment, TaskDeclaration } from "@atf/core";

export type TaskStatus = "pending" | "approved" | "denied" | "expired";

export type TaskRecord = {
  id: string;
  agentId: string;
  declaration: TaskDeclaration;
  risk: RiskAssessment;
  status: TaskStatus;
  createdAt: string;
  expiresAt: string;
  approvedAt: string | null;
  approvedBy: string | null;
  handleIssuedAt: string | null;
};

type TaskRow = {
  id: string;
  agent_id: string;
  declaration_json: string;
  risk_json: string;
  status: TaskStatus;
  created_at: string;
  expires_at: string;
  approved_at: string | null;
  approved_by: string | null;
  handle_issued_at: string | null;
};

type HandleRow = {
  id: string;
  task_id: string;
  secret_hash: string;
  expires_at: string;
  calls_used: number;
  revoked_at: string | null;
};

type AgentRow = {
  id: string;
  name: string;
  spiffe_id: string | null;
  api_key_hash: string;
  created_at: string;
};

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const canonicalJson = (value: unknown) => JSON.stringify(value);

export class TrustDatabase {
  readonly db: Database.Database;

  constructor(path = process.env.DATABASE_PATH ?? "agent-trust.db") {
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.migrate();
  }

  private migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        spiffe_id TEXT,
        api_key_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL REFERENCES agents(id),
        declaration_json TEXT NOT NULL,
        risk_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired')),
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        approved_at TEXT,
        approved_by TEXT,
        handle_issued_at TEXT
      );
      CREATE TABLE IF NOT EXISTS handles (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(id),
        secret_hash TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        calls_used INTEGER NOT NULL DEFAULT 0,
        revoked_at TEXT
      );
      CREATE TABLE IF NOT EXISTS audit_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        occurred_at TEXT NOT NULL,
        agent_id TEXT,
        task_id TEXT,
        handle_id TEXT,
        event_type TEXT NOT NULL,
        decision TEXT NOT NULL,
        reason TEXT NOT NULL,
        input_hash TEXT NOT NULL,
        details_json TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE
      );
      CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(agent_id);
      CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_events(task_id);
    `);
  }

  close() {
    this.db.close();
  }

  createAgent(name: string, spiffeId?: string) {
    const id = randomUUID();
    const apiKey = `atf_agent_${randomBytes(24).toString("base64url")}`;
    const createdAt = new Date().toISOString();
    this.db
      .prepare(
        "INSERT INTO agents (id, name, spiffe_id, api_key_hash, created_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run(id, name, spiffeId ?? null, hash(apiKey), createdAt);
    this.appendAudit({
      agentId: id,
      eventType: "agent.registered",
      decision: "allow",
      reason: "agent identity registered",
      input: { name, spiffeId },
      details: { identityType: spiffeId ? "spiffe" : "local-api-key" },
    });
    return { id, name, spiffeId: spiffeId ?? null, apiKey, createdAt };
  }

  authenticateAgent(apiKey: string): AgentRow | undefined {
    return this.db
      .prepare("SELECT * FROM agents WHERE api_key_hash = ?")
      .get(hash(apiKey)) as AgentRow | undefined;
  }

  createTask(agentId: string, declaration: TaskDeclaration, risk: RiskAssessment): TaskRecord {
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + declaration.expiresInSeconds * 1_000).toISOString();
    this.db
      .prepare(
        `INSERT INTO tasks
          (id, agent_id, declaration_json, risk_json, status, created_at, expires_at)
         VALUES (?, ?, ?, ?, 'pending', ?, ?)`,
      )
      .run(id, agentId, canonicalJson(declaration), canonicalJson(risk), createdAt, expiresAt);
    this.appendAudit({
      agentId,
      taskId: id,
      eventType: "task.declared",
      decision: "pending",
      reason: "purpose requires human approval",
      input: declaration,
      details: { risk },
    });
    return this.getTask(id)!;
  }

  getTask(id: string): TaskRecord | undefined {
    const row = this.db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as TaskRow | undefined;
    if (!row) return undefined;
    if (row.status === "approved" && new Date(row.expires_at) <= new Date()) {
      this.db.prepare("UPDATE tasks SET status = 'expired' WHERE id = ?").run(id);
      row.status = "expired";
    }
    return {
      id: row.id,
      agentId: row.agent_id,
      declaration: JSON.parse(row.declaration_json) as TaskDeclaration,
      risk: JSON.parse(row.risk_json) as RiskAssessment,
      status: row.status,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      approvedAt: row.approved_at,
      approvedBy: row.approved_by,
      handleIssuedAt: row.handle_issued_at,
    };
  }

  listTasks(): TaskRecord[] {
    const ids = this.db
      .prepare("SELECT id FROM tasks ORDER BY created_at DESC")
      .all() as Array<{ id: string }>;
    return ids.map(({ id }) => this.getTask(id)!);
  }

  decideTask(id: string, approved: boolean, approver: string): TaskRecord | undefined {
    const task = this.getTask(id);
    if (!task || task.status !== "pending") return undefined;
    const status = approved ? "approved" : "denied";
    const approvedAt = new Date().toISOString();
    this.db
      .prepare("UPDATE tasks SET status = ?, approved_at = ?, approved_by = ? WHERE id = ?")
      .run(status, approvedAt, approver, id);
    this.appendAudit({
      agentId: task.agentId,
      taskId: id,
      eventType: approved ? "task.approved" : "task.denied",
      decision: approved ? "allow" : "deny",
      reason: approved ? "human approved the declared purpose" : "human denied the declared purpose",
      input: { approver },
      details: { riskAtDecision: task.risk },
    });
    return this.getTask(id);
  }

  issueHandle(taskId: string): { handle: string; expiresAt: string } | undefined {
    const task = this.getTask(taskId);
    if (!task || task.status !== "approved" || task.handleIssuedAt) return undefined;
    const id = randomUUID();
    const secret = randomBytes(32).toString("base64url");
    const handle = `atf_handle_${id}.${secret}`;
    this.db.transaction(() => {
      this.db
        .prepare(
          "INSERT INTO handles (id, task_id, secret_hash, expires_at) VALUES (?, ?, ?, ?)",
        )
        .run(id, taskId, hash(handle), task.expiresAt);
      this.db
        .prepare("UPDATE tasks SET handle_issued_at = ? WHERE id = ?")
        .run(new Date().toISOString(), taskId);
      this.appendAudit({
        agentId: task.agentId,
        taskId,
        handleId: id,
        eventType: "handle.issued",
        decision: "allow",
        reason: "single-use credential handle issued to approved agent",
        input: { taskId },
        details: { expiresAt: task.expiresAt },
      });
    })();
    return { handle, expiresAt: task.expiresAt };
  }

  resolveHandle(handle: string): { row: HandleRow; task: TaskRecord } | undefined {
    const row = this.db
      .prepare("SELECT * FROM handles WHERE secret_hash = ?")
      .get(hash(handle)) as HandleRow | undefined;
    if (!row || row.revoked_at || new Date(row.expires_at) <= new Date()) return undefined;
    const task = this.getTask(row.task_id);
    if (!task) return undefined;
    return { row, task };
  }

  consumeHandle(handleId: string) {
    this.db.prepare("UPDATE handles SET calls_used = calls_used + 1 WHERE id = ?").run(handleId);
  }

  appendAudit(event: {
    agentId?: string;
    taskId?: string;
    handleId?: string;
    eventType: string;
    decision: string;
    reason: string;
    input: unknown;
    details?: unknown;
  }) {
    const previous = this.db
      .prepare("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
      .get() as { event_hash: string } | undefined;
    const record = {
      eventId: randomUUID(),
      occurredAt: new Date().toISOString(),
      agentId: event.agentId ?? null,
      taskId: event.taskId ?? null,
      handleId: event.handleId ?? null,
      eventType: event.eventType,
      decision: event.decision,
      reason: event.reason,
      inputHash: hash(canonicalJson(event.input)),
      details: event.details ?? {},
      previousHash: previous?.event_hash ?? "GENESIS",
    };
    const eventHash = hash(canonicalJson(record));
    this.db
      .prepare(
        `INSERT INTO audit_events
          (event_id, occurred_at, agent_id, task_id, handle_id, event_type, decision, reason,
           input_hash, details_json, previous_hash, event_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        record.eventId,
        record.occurredAt,
        record.agentId,
        record.taskId,
        record.handleId,
        record.eventType,
        record.decision,
        record.reason,
        record.inputHash,
        canonicalJson(record.details),
        record.previousHash,
        eventHash,
      );
    return { ...record, eventHash };
  }

  listAudit(taskId?: string) {
    const rows = (
      taskId
        ? this.db
            .prepare("SELECT * FROM audit_events WHERE task_id = ? ORDER BY sequence DESC")
            .all(taskId)
        : this.db.prepare("SELECT * FROM audit_events ORDER BY sequence DESC LIMIT 500").all()
    ) as Array<Record<string, unknown> & { details_json: string }>;
    return rows.map(({ details_json, ...row }) => ({
      ...row,
      details: JSON.parse(details_json),
    }));
  }
}
