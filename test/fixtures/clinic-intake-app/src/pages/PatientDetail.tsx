import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { uploadLabResult } from "@/lib/labs";

export default function PatientDetail() {
  const { id = "" } = useParams();
  const [patient, setPatient] = useState<{ full_name: string; diagnosis: string | null; insurance_member_id: string | null }>();
  const [visits, setVisits] = useState<{ id: string; reason: string; clinical_notes: string | null }[]>([]);

  useEffect(() => {
    supabase
      .from("patients")
      .select("full_name, diagnosis, insurance_member_id")
      .eq("id", id)
      .single()
      .then(({ data }) => setPatient(data ?? undefined));
    supabase
      .from("appointments")
      .select("id, reason, clinical_notes")
      .eq("patient_id", id)
      .then(({ data }) => setVisits(data ?? []));
  }, [id]);

  async function summarize(visitId: string) {
    await supabase.functions.invoke("summarize-visit", { body: { visitId } });
  }

  if (!patient) return null;
  return (
    <article>
      <h1>{patient.full_name}</h1>
      <p>Diagnosis: {patient.diagnosis}</p>
      <p>Insurance member id: {patient.insurance_member_id}</p>
      <input type="file" onChange={(e) => e.target.files?.[0] && uploadLabResult(id, e.target.files[0])} />
      <ul>
        {visits.map((v) => (
          <li key={v.id}>
            {v.reason}: {v.clinical_notes}
            <button onClick={() => summarize(v.id)}>Summarize</button>
          </li>
        ))}
      </ul>
    </article>
  );
}
