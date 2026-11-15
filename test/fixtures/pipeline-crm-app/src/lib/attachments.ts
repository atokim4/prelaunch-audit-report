import { supabase } from "@/integrations/supabase/client";

/** Files go under the owner's folder: attachments/<user id>/<file name>. */
export async function uploadAttachment(userId: string, file: File) {
  const path = `${userId}/${file.name}`;
  const { error } = await supabase.storage.from("attachments").upload(path, file, { upsert: false });
  if (error) throw error;
  return path;
}
