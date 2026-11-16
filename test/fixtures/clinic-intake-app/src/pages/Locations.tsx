import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";

export default function Locations() {
  const [locations, setLocations] = useState<{ id: string; name: string; address: string }[]>([]);

  useEffect(() => {
    supabase
      .from("clinic_locations")
      .select("id, name, address")
      .then(({ data }) => setLocations(data ?? []));
  }, []);

  return (
    <ul>
      {locations.map((l) => (
        <li key={l.id}>
          {l.name}, {l.address}
        </li>
      ))}
    </ul>
  );
}
