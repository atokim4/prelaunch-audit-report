import { NextResponse } from "next/server";
import type Stripe from "stripe";
import { supabaseAdmin } from "@/lib/supabase/admin";

export async function POST(request: Request) {
  const event = (await request.json()) as Stripe.Event;

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    await supabaseAdmin
      .from("profiles")
      .update({ plan: "pro", stripe_customer_id: String(session.customer) })
      .eq("id", session.client_reference_id);
  }

  return NextResponse.json({ received: true });
}
