import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import type { Database } from "@/integrations/supabase/types";

type Patient = Database["public"]["Tables"]["patients"]["Row"];

export default function Patients() {
  const [patients, setPatients] = useState<Patient[]>([]);

  useEffect(() => {
    supabase
      .from("patients")
      .select("*")
      .order("full_name")
      .then(({ data }) => setPatients(data ?? []));
  }, []);

  return (
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Date of birth</th>
          <th>MRN</th>
        </tr>
      </thead>
      <tbody>
        {patients.map((p) => (
          <tr key={p.id}>
            <td>
              <Link to={`/patients/${p.id}`}>{p.full_name}</Link>
            </td>
            <td>{p.date_of_birth}</td>
            <td>{p.mrn}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
