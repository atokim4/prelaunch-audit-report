import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { listPayments } from "@/lib/billing";

type Payment = { id: string; amount: number; created: number };

export default function Billing() {
  const [payments, setPayments] = useState<Payment[]>([]);

  useEffect(() => {
    supabase
      .from("profiles")
      .select("stripe_customer_id")
      .single()
      .then(async ({ data }) => {
        if (data?.stripe_customer_id) setPayments(await listPayments(data.stripe_customer_id));
      });
  }, []);

  async function upgrade() {
    const { data } = await supabase.functions.invoke("create-checkout", {
      body: { price: import.meta.env.VITE_STRIPE_PRICE_PRO },
    });
    if (data?.url) window.location.href = data.url;
  }

  return (
    <section>
      <button onClick={upgrade}>Upgrade to Pro</button>
      <ul>
        {payments.map((p) => (
          <li key={p.id}>{(p.amount / 100).toFixed(2)}</li>
        ))}
      </ul>
    </section>
  );
}
