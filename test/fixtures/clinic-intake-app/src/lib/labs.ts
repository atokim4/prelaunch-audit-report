import { supabase } from "@/integrations/supabase/client";

/** Lab PDFs go to the lab-results bucket under the patient's id; the page links the public URL. */
export async function uploadLabResult(patientId: string, file: File): Promise<string> {
  const path = `${patientId}/${Date.now()}-${file.name}`;
  const { error } = await supabase.storage.from("lab-results").upload(path, file);
  if (error) throw error;
  return supabase.storage.from("lab-results").getPublicUrl(path).data.publicUrl;
}
