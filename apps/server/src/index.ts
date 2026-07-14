import { buildApp } from "./app.js";

const app = buildApp();
const port = Number(process.env.PORT ?? 8787);
const host = process.env.HOST ?? "127.0.0.1";

try {
  await app.listen({ port, host });
  if (!process.env.APPROVAL_TOKEN || !process.env.BOOTSTRAP_TOKEN) {
    app.log.warn(
      "Using development control tokens. Set APPROVAL_TOKEN and BOOTSTRAP_TOKEN before deployment.",
    );
  }
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
