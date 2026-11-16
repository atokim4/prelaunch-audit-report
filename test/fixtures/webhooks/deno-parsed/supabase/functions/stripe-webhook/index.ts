import Stripe from "npm:stripe@19.3.1";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY") ?? "", { httpClient: Stripe.createFetchHttpClient() });
const cryptoProvider = Stripe.createSubtleCryptoProvider();

Deno.serve(async (req) => {
  const signature = req.headers.get("stripe-signature") ?? "";
  const body = await req.json();

  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(
      JSON.stringify(body),
      signature,
      Deno.env.get("STRIPE_WEBHOOK_SECRET") ?? "",
      undefined,
      cryptoProvider,
    );
  } catch {
    return new Response("Invalid signature", { status: 400 });
  }

  console.log("stripe event", body.id);
  return Response.json({ received: true, type: event.type });
});
