import express from "express";
import Stripe from "stripe";
import { markPaid } from "./billing.ts";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export const app = express();
app.use(express.json());

app.post("/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"] as string,
      process.env.STRIPE_WEBHOOK_SECRET!,
    );
  } catch (err) {
    res.status(400).send(`Webhook Error: ${(err as Error).message}`);
    return;
  }

  if (event.type === "checkout.session.completed") {
    await markPaid(String(event.data.object.client_reference_id));
  }
  res.json({ received: true });
});
