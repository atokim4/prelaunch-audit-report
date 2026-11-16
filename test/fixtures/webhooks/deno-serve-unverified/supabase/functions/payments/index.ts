import Stripe from "npm:stripe@19.3.1";

Deno.serve(async (req) => {
  const event = (await req.json()) as Stripe.Event;

  if (event.type === "checkout.session.completed") {
    return Response.json({ received: true, paid: true });
  }
  return Response.json({ received: true });
});
