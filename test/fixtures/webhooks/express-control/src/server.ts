import express from "express";
import Stripe from "stripe";
import { markPaid } from "./billing.ts";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export const app = express();

// The webhook is registered before the JSON parser, so it still gets the raw bytes.
app.post("/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"] as string,
      process.env.STRIPE_WEBHOOK_SECRET!,
    );
  } catch {
    res.status(400).send("Invalid signature");
    return;
  }

  if (event.type === "checkout.session.completed") {
    await markPaid(String(event.data.object.client_reference_id));
  }
  res.json({ received: true });
});

app.use(express.json());
