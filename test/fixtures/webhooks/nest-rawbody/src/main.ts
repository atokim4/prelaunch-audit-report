// Test fixture, written broken on purpose: the shape of a real NestJS API. rawBody: true asks Nest to keep
// the bytes, but the app registers its own body parsers, which replace Nest's, so req.rawBody stays unset.
import { NestFactory } from "@nestjs/core";
import bodyParser from "body-parser";
import { AppModule } from "./app.module.js";

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule, { bodyParser: true, rawBody: true });

  // Stripe webhook needs the raw body for signature verification
  app.use("/api/payments/webhook", bodyParser.raw({ type: "application/json", limit: "1mb" }));

  app.use(bodyParser.json({ limit: "2mb" }));

  await app.listen(3000);
}

void bootstrap();
