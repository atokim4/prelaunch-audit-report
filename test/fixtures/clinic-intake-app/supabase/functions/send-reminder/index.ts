import { createClient } from "npm:@supabase/supabase-js@2";

Deno.serve(async (req) => {
  const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const { appointmentId, email } = await req.json();
  const { data: appointment } = await supabase
    .from("appointments")
    .select("scheduled_at, reason, patients(full_name, date_of_birth)")
    .eq("id", appointmentId)
    .single();
  console.log("sending reminder", appointment);

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${Deno.env.get("RESEND_API_KEY")}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "clinic@example.invalid",
      to: email,
      subject: "Your appointment",
      text: `Reminder: ${appointment?.reason} on ${appointment?.scheduled_at}`,
    }),
  });
  if (!res.ok) {
    console.error("reminder failed for", appointment?.patients, await res.text());
    return new Response("failed", { status: 502 });
  }
  return new Response("sent");
});
