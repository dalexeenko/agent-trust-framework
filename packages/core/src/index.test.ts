import { describe, expect, it } from "vitest";
import { assessRisk, authorize, TaskDeclarationSchema } from "./index.js";

const task = TaskDeclarationSchema.parse({
  purpose: "Summarize the approved customer support documents",
  capabilities: ["google.agentspace.search"],
  resources: ["projects/demo/locations/global/collections/support-*"],
  expiresInSeconds: 600,
  constraints: {
    maxCalls: 5,
    allowExternalCommunication: false,
    allowSensitiveData: false,
    requireModelArmor: true,
  },
});

describe("purpose authorization", () => {
  it("allows an action inside the approved envelope", () => {
    expect(
      authorize({
        task,
        taskStatus: "approved",
        taskExpiresAt: "2030-01-01T00:00:00.000Z",
        callsUsed: 1,
        now: new Date("2029-01-01"),
        action: {
          capability: "google.agentspace.search",
          resource: "projects/demo/locations/global/collections/support-emea",
          operation: "search",
          dryRun: true,
        },
      }),
    ).toEqual({
      allowed: true,
      reason: "action matches the approved purpose envelope",
    });
  });

  it("denies a resource outside the approved blast radius", () => {
    expect(
      authorize({
        task,
        taskStatus: "approved",
        taskExpiresAt: "2030-01-01T00:00:00.000Z",
        callsUsed: 1,
        now: new Date("2029-01-01"),
        action: {
          capability: "google.agentspace.search",
          resource: "projects/demo/locations/global/collections/finance",
          operation: "search",
          dryRun: true,
        },
      }).allowed,
    ).toBe(false);
  });

  it("raises risk for writes, wildcards, and data egress", () => {
    const assessment = assessRisk(
      TaskDeclarationSchema.parse({
        ...task,
        capabilities: ["google.cloud.write"],
        resources: ["projects/*"],
        constraints: {
          ...task.constraints,
          allowExternalCommunication: true,
          allowSensitiveData: true,
          requireModelArmor: false,
        },
      }),
    );
    expect(assessment.level).toBe("critical");
    expect(assessment.score).toBe(100);
  });
});
