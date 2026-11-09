"use client";

import { useEffect, useState } from "react";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

type Profile = { id: string; display_name: string | null; plan: string };

export function UsersTable() {
  const [profiles, setProfiles] = useState<Profile[]>([]);

  useEffect(() => {
    supabase
      .from("profiles")
      .select("id, display_name, plan")
      .then(({ data }) => setProfiles(data ?? []));
  }, []);

  return (
    <table>
      <tbody>
        {profiles.map((p) => (
          <tr key={p.id}>
            <td>{p.display_name ?? p.id}</td>
            <td>{p.plan}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
