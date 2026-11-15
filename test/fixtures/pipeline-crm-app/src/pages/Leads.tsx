import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";

type Lead = { id: string; name: string; email: string | null };

export default function Leads() {
  const [leads, setLeads] = useState<Lead[]>([]);

  useEffect(() => {
    supabase
      .from("leads")
      .select("id, name, email")
      .order("created_at", { ascending: false })
      .then(({ data }) => setLeads(data ?? []));
  }, []);

  async function remove(id: string) {
    await supabase.rpc("delete_lead", { lead_id: id });
    setLeads((rows) => rows.filter((r) => r.id !== id));
  }

  return (
    <ul>
      {leads.map((lead) => (
        <li key={lead.id}>
          {lead.name} {lead.email}
          <button onClick={() => remove(lead.id)}>Delete</button>
        </li>
      ))}
    </ul>
  );
}
