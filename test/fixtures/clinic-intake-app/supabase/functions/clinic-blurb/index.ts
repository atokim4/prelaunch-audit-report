import { createClient } from "npm:@supabase/supabase-js@2";

/** Writes a short marketing blurb for a clinic location from its public description. */
Deno.serve(async (req) => {
  const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!);
  const { locationId } = await req.json();
  const { data: location } = await supabase
    .from("clinic_locations")
    .select("name, address, description")
    .eq("id", locationId)
    .single();
  console.log("blurb requested", locationId);

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": Deno.env.get("ANTHROPIC_API_KEY")!,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model: "claude-haiku-5-5",
      max_tokens: 200,
      messages: [{ role: "user", content: `Two friendly sentences about ${location?.name}: ${location?.description}` }],
    }),
  });
  return new Response(await res.text(), { headers: { "Content-Type": "application/json" } });
});
