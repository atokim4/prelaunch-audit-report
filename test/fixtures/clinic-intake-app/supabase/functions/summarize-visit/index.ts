import { createClient } from "npm:@supabase/supabase-js@2";

Deno.serve(async (req) => {
  const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: req.headers.get("Authorization")! } },
  });
  const { visitId } = await req.json();
  const { data: visit, error } = await supabase
    .from("appointments")
    .select("reason, clinical_notes, patients(full_name, diagnosis)")
    .eq("id", visitId)
    .single();
  if (error || !visit) return new Response(JSON.stringify({ error: error?.message }), { status: 404 });

  const prompt = `Summarize this visit for the chart.\nReason: ${visit.reason}\nNotes: ${visit.clinical_notes}`;
  const res = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: { Authorization: `Bearer ${Deno.env.get("OPENAI_API_KEY")}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model: "gpt-6-luna", input: prompt }),
  });
  const summary = await res.json();
  return new Response(JSON.stringify({ summary: summary.output_text }), {
    headers: { "Content-Type": "application/json" },
  });
});
