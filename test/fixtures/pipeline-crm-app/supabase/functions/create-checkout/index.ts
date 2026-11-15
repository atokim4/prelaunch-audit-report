import Stripe from "npm:stripe@19.3.0";
import { createClient } from "npm:@supabase/supabase-js@2.81.0";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY") ?? "");

Deno.serve(async (req) => {
  const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_ANON_KEY") ?? "", {
    global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } },
  });
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });

  const { price } = (await req.json()) as { price: string };
  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    line_items: [{ price, quantity: 1 }],
    client_reference_id: user.id,
    success_url: `${req.headers.get("origin")}/billing?paid=1`,
    cancel_url: `${req.headers.get("origin")}/billing`,
  });
  return Response.json({ url: session.url });
});
