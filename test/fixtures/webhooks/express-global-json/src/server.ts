import express from "express";
import type Stripe from "stripe";
import { markPaid } from "./billing.ts";

export const app = express();
app.use(express.json());

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.post("/api/stripe/webhook", async (req, res) => {
  const event = req.body as Stripe.Event;

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    await markPaid(String(session.client_reference_id));
  }

  res.json({ received: true });
});

app.post("/api/notes", (req, res) => {
  res.status(201).json({ title: req.body.title });
});
