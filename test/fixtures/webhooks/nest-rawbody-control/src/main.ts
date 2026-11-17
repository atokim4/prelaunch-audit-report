// Control: the app's own parsers keep the bytes with a verify option, so req.rawBody is set.
import type { IncomingMessage } from "node:http";
import { NestFactory } from "@nestjs/core";
import bodyParser from "body-parser";
import { AppModule } from "./app.module.js";

function keepRawBody(req: IncomingMessage, _res: unknown, buf: Buffer): void {
  (req as IncomingMessage & { rawBody?: Buffer }).rawBody = buf;
}

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule, { bodyParser: true, rawBody: true });
  app.use("/api/payments/webhook", bodyParser.raw({ type: "application/json", verify: keepRawBody }));
  app.use(bodyParser.json({ limit: "2mb", verify: keepRawBody }));
  await app.listen(3000);
}

void bootstrap();
