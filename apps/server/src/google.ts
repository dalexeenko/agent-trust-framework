import { GoogleAuth } from "google-auth-library";
import type { ActionRequest, TaskDeclaration } from "@atf/core";

export type GuardrailResult = {
  allowed: boolean;
  provider: "google-model-armor" | "local-fallback";
  reasons: string[];
};

const injectionPatterns = [
  /ignore (all|any|the|your) previous instructions/i,
  /reveal (the )?(system prompt|credentials|secrets)/i,
  /bypass (the )?(policy|guardrail|approval)/i,
  /send .* (token|password|secret|credential)/i,
];

const sensitivePatterns = [
  /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\bAIza[0-9A-Za-z_-]{35}\b/,
  /\b(?:password|access[_ -]?token|client[_ -]?secret)\s*[:=]\s*\S+/i,
];

function inputText(input: unknown): string {
  return typeof input === "string" ? input : JSON.stringify(input ?? {});
}

export class GoogleGuardrails {
  private readonly auth = new GoogleAuth({
    scopes: ["https://www.googleapis.com/auth/cloud-platform"],
  });

  async screen(input: unknown, task: TaskDeclaration): Promise<GuardrailResult> {
    const text = inputText(input);
    const localReasons = [
      ...injectionPatterns.filter((pattern) => pattern.test(text)).map(() => "prompt injection"),
      ...sensitivePatterns.filter((pattern) => pattern.test(text)).map(() => "sensitive credential"),
    ];
    if (localReasons.length > 0) {
      const credentialLeak = localReasons.includes("sensitive credential");
      return {
        allowed: !credentialLeak && task.constraints.allowSensitiveData,
        provider: "local-fallback",
        reasons: [...new Set(localReasons)],
      };
    }

    const endpoint = process.env.MODEL_ARMOR_ENDPOINT;
    if (!endpoint || !task.constraints.requireModelArmor) {
      return { allowed: true, provider: "local-fallback", reasons: [] };
    }

    const client = await this.auth.getClient();
    const response = await client.request<Record<string, unknown>>({
      url: endpoint,
      method: "POST",
      data: { userPromptData: { text } },
    });
    const serialized = JSON.stringify(response.data);
    const blocked =
      /MATCH_FOUND|MALICIOUS|BLOCKED/i.test(serialized) &&
      !/NO_MATCH_FOUND/i.test(serialized);
    return {
      allowed: !blocked,
      provider: "google-model-armor",
      reasons: blocked ? ["Model Armor policy match"] : [],
    };
  }
}

type VertexResource = {
  project: string;
  location: string;
  model: string;
};

function parseVertexResource(resource: string): VertexResource | undefined {
  const match = resource.match(
    /^projects\/([^/]+)\/locations\/([^/]+)\/publishers\/google\/models\/([^/]+)$/,
  );
  if (!match?.[1] || !match[2] || !match[3]) return undefined;
  return { project: match[1], location: match[2], model: match[3] };
}

export class GoogleExecutor {
  private readonly auth = new GoogleAuth({
    scopes: ["https://www.googleapis.com/auth/cloud-platform"],
  });

  async execute(action: ActionRequest) {
    if (action.dryRun) {
      return {
        executed: false,
        dryRun: true,
        credentialExposed: false,
        target: action.resource,
      };
    }

    if (action.capability === "google.modelarmor.sanitize") {
      throw new Error("Model Armor runs as a pre-execution guardrail, not as an agent tool");
    }
    if (action.capability !== "google.vertex.generate") {
      throw new Error(`No live executor is configured for ${action.capability}; use dryRun`);
    }

    const target = parseVertexResource(action.resource);
    if (!target) {
      throw new Error("Vertex resource must name a Google publisher model");
    }
    const client = await this.auth.getClient();
    const url =
      `https://${target.location}-aiplatform.googleapis.com/v1/` +
      `${action.resource}:generateContent`;
    if (!action.input || typeof action.input !== "object" || Array.isArray(action.input)) {
      throw new Error("Vertex input must be a generateContent request object");
    }
    const response = await client.request({
      url,
      method: "POST",
      data: action.input as Record<string, unknown>,
    });
    return {
      executed: true,
      credentialExposed: false,
      target: action.resource,
      data: response.data,
    };
  }
}
