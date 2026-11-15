import Stripe from "stripe";

// Used by the Billing page to show the customer's past payments.
const stripe = new Stripe(import.meta.env.VITE_STRIPE_SECRET_KEY);

export async function listPayments(customerId: string) {
  const charges = await stripe.charges.list({ customer: customerId, limit: 20 });
  return charges.data.map((c) => ({ id: c.id, amount: c.amount, created: c.created }));
}
