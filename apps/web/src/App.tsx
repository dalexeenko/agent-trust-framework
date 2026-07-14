import { useCallback, useEffect, useState } from "react";

type Risk = {
  score: number;
  level: "low" | "medium" | "high" | "critical";
  factors: Array<{ name: string; points: number; explanation: string }>;
};

type Task = {
  id: string;
  agentId: string;
  declaration: {
    purpose: string;
    capabilities: string[];
    resources: string[];
    expiresInSeconds: number;
    constraints: {
      maxCalls: number;
      allowExternalCommunication: boolean;
      allowSensitiveData: boolean;
      requireModelArmor: boolean;
    };
  };
  risk: Risk;
  status: "pending" | "approved" | "denied" | "expired";
  createdAt: string;
  expiresAt: string;
  approvedBy: string | null;
};

type AuditEvent = {
  sequence: number;
  event_id: string;
  occurred_at: string;
  event_type: string;
  decision: string;
  reason: string;
  event_hash: string;
  previous_hash: string;
};

const apiBase = import.meta.env.VITE_API_BASE ?? "";

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem("approval-token") ?? "dev-approve");
  const [approver, setApprover] = useState("local-owner");
  const [tasks, setTasks] = useState<Task[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  const headers = useCallback(
    () => ({ "content-type": "application/json", "x-approval-token": token }),
    [token],
  );

  const refresh = useCallback(async () => {
    try {
      const [taskResponse, auditResponse] = await Promise.all([
        fetch(`${apiBase}/v1/review/tasks`, { headers: headers() }),
        fetch(`${apiBase}/v1/review/audit`, { headers: headers() }),
      ]);
      if (!taskResponse.ok || !auditResponse.ok) throw new Error("Approval token was rejected");
      setTasks((await taskResponse.json()) as Task[]);
      setAudit((await auditResponse.json()) as AuditEvent[]);
      setError("");
      localStorage.setItem("approval-token", token);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load gateway state");
    }
  }, [headers, token]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function decide(task: Task, approved: boolean) {
    setBusy(task.id);
    try {
      const response = await fetch(`${apiBase}/v1/review/tasks/${task.id}/decision`, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({ approved, approver }),
      });
      if (!response.ok) throw new Error("The task could not be decided");
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Decision failed");
    } finally {
      setBusy("");
    }
  }

  const pending = tasks.filter((task) => task.status === "pending");

  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">Agentic Security Control Plane</p>
          <h1>Approve a purpose.<br />Not a permission.</h1>
          <p className="lede">
            Agents receive expiring handles. Credentials remain behind the gateway. Every decision
            is replayable.
          </p>
        </div>
        <div className="status">
          <span className="pulse" />
          Gateway online
        </div>
      </header>

      <section className="controls">
        <label>
          Approval token
          <input value={token} onChange={(event) => setToken(event.target.value)} type="password" />
        </label>
        <label>
          Approver identity
          <input value={approver} onChange={(event) => setApprover(event.target.value)} />
        </label>
        <button className="secondary" onClick={() => void refresh()}>Refresh</button>
        {error && <p className="error">{error}</p>}
      </section>

      <section>
        <div className="section-heading">
          <div>
            <p className="eyebrow">Purpose inbox</p>
            <h2>{pending.length} awaiting review</h2>
          </div>
          <span className="counter">{tasks.length} total</span>
        </div>

        <div className="task-grid">
          {tasks.length === 0 && <div className="empty">No tasks have been declared yet.</div>}
          {tasks.map((task) => (
            <article className={`task ${task.status}`} key={task.id}>
              <div className="task-topline">
                <span className={`badge ${task.status}`}>{task.status}</span>
                <span className={`risk ${task.risk.level}`}>
                  {task.risk.score}/100 · {task.risk.level}
                </span>
              </div>
              <h3>{task.declaration.purpose}</h3>
              <dl>
                <div>
                  <dt>Capabilities</dt>
                  <dd>{task.declaration.capabilities.join(", ")}</dd>
                </div>
                <div>
                  <dt>Blast radius</dt>
                  <dd>{task.declaration.resources.join(", ")}</dd>
                </div>
                <div>
                  <dt>Budget</dt>
                  <dd>
                    {task.declaration.constraints.maxCalls} calls · expires{" "}
                    {new Date(task.expiresAt).toLocaleTimeString()}
                  </dd>
                </div>
              </dl>
              <div className="risk-bar">
                <span style={{ width: `${task.risk.score}%` }} />
              </div>
              <ul className="factors">
                {task.risk.factors.map((factor) => (
                  <li key={factor.name}>
                    <strong>+{factor.points}</strong> {factor.name}
                  </li>
                ))}
              </ul>
              {task.status === "pending" && (
                <div className="actions">
                  <button
                    className="deny"
                    disabled={busy === task.id}
                    onClick={() => void decide(task, false)}
                  >
                    Deny
                  </button>
                  <button
                    disabled={busy === task.id}
                    onClick={() => void decide(task, true)}
                  >
                    Approve purpose
                  </button>
                </div>
              )}
              {task.approvedBy && <p className="approved-by">Decided by {task.approvedBy}</p>}
            </article>
          ))}
        </div>
      </section>

      <section>
        <div className="section-heading">
          <div>
            <p className="eyebrow">Tamper-evident ledger</p>
            <h2>Replayable audit trail</h2>
          </div>
        </div>
        <div className="audit">
          {audit.map((event) => (
            <div className="audit-row" key={event.event_id}>
              <span className={`decision ${event.decision}`}>{event.decision}</span>
              <div>
                <strong>{event.event_type}</strong>
                <p>{event.reason}</p>
              </div>
              <time>{new Date(event.occurred_at).toLocaleString()}</time>
              <code title={event.event_hash}>{event.event_hash.slice(0, 10)}</code>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
