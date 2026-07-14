import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { TrustDatabase } from "../src/database.js";

const apps: Array<ReturnType<typeof buildApp>> = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function setup() {
  const app = buildApp({ database: new TrustDatabase(":memory:") });
  apps.push(app);
  const agentResponse = await app.inject({
    method: "POST",
    url: "/v1/agents",
    headers: { "x-bootstrap-token": "dev-bootstrap" },
    payload: { name: "support-agent" },
  });
  const agent = agentResponse.json<{ id: string; apiKey: string }>();
  const taskResponse = await app.inject({
    method: "POST",
    url: "/v1/tasks",
    headers: { authorization: `Bearer ${agent.apiKey}` },
    payload: {
      purpose: "Summarize support records for the weekly operations review",
      capabilities: ["google.agentspace.search"],
      resources: ["projects/demo/locations/global/collections/support"],
      expiresInSeconds: 600,
      constraints: {
        maxCalls: 2,
        allowExternalCommunication: false,
        allowSensitiveData: false,
        requireModelArmor: true,
      },
    },
  });
  return {
    app,
    agent,
    task: taskResponse.json<{ id: string; risk: { score: number } }>(),
  };
}

describe("authorization gateway", () => {
  it("issues a handle only after purpose approval and executes a scoped dry run", async () => {
    const { app, agent, task } = await setup();
    expect(task.risk.score).toBeGreaterThan(0);

    const beforeApproval = await app.inject({
      method: "POST",
      url: `/v1/tasks/${task.id}/handle`,
      headers: { authorization: `Bearer ${agent.apiKey}` },
    });
    expect(beforeApproval.statusCode).toBe(409);

    const approval = await app.inject({
      method: "POST",
      url: `/v1/review/tasks/${task.id}/decision`,
      headers: { "x-approval-token": "dev-approve" },
      payload: { approved: true, approver: "owner@example.com" },
    });
    expect(approval.statusCode).toBe(200);

    const handleResponse = await app.inject({
      method: "POST",
      url: `/v1/tasks/${task.id}/handle`,
      headers: { authorization: `Bearer ${agent.apiKey}` },
    });
    const { handle } = handleResponse.json<{ handle: string }>();
    expect(handle).toMatch(/^atf_handle_/);

    const execution = await app.inject({
      method: "POST",
      url: "/v1/gateway/execute",
      headers: { authorization: `Bearer ${handle}` },
      payload: {
        capability: "google.agentspace.search",
        resource: "projects/demo/locations/global/collections/support",
        operation: "search",
        input: { query: "open cases" },
        dryRun: true,
      },
    });
    expect(execution.statusCode).toBe(200);
    expect(execution.json().result.credentialExposed).toBe(false);
  });

  it("denies a resource outside the approved purpose", async () => {
    const { app, agent, task } = await setup();
    await app.inject({
      method: "POST",
      url: `/v1/review/tasks/${task.id}/decision`,
      headers: { "x-approval-token": "dev-approve" },
      payload: { approved: true, approver: "owner@example.com" },
    });
    const handleResponse = await app.inject({
      method: "POST",
      url: `/v1/tasks/${task.id}/handle`,
      headers: { authorization: `Bearer ${agent.apiKey}` },
    });
    const { handle } = handleResponse.json<{ handle: string }>();

    const execution = await app.inject({
      method: "POST",
      url: "/v1/gateway/execute",
      headers: { authorization: `Bearer ${handle}` },
      payload: {
        capability: "google.agentspace.search",
        resource: "projects/demo/locations/global/collections/payroll",
        operation: "search",
        input: { query: "salaries" },
        dryRun: true,
      },
    });
    expect(execution.statusCode).toBe(403);
    expect(execution.json().error).toBe("outside_approved_purpose");
  });
});
