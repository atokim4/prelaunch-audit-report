import type { NextApiRequest, NextApiResponse } from "next";
import type Stripe from "stripe";
import { markPaid } from "../../../lib/billing";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.status(405).end();
    return;
  }
  const event = req.body as Stripe.Event;

  if (event.type === "checkout.session.completed") {
    await markPaid(String(event.data.object.client_reference_id));
  }
  res.status(200).json({ received: true });
}
