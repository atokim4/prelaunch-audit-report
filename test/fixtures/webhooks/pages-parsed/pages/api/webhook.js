import Stripe from "stripe";
import { markPaid } from "../../lib/billing.js";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const handler = (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      JSON.stringify(req.body),
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET,
    );
  } catch {
    return res.status(400).json({ error: "Invalid signature" });
  }
  if (event.type === "checkout.session.completed") {
    markPaid(String(event.data.object.client_reference_id));
  }
  return res.status(200).json({ received: true });
};

export default handler;
