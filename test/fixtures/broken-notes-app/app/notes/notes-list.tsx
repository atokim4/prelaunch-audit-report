"use client";

import { useEffect, useState } from "react";
import { createSupabaseBrowserClient } from "@/lib/supabase/browser";

type Note = { id: string; title: string };

export function NotesList() {
  const [notes, setNotes] = useState<Note[]>([]);

  useEffect(() => {
    const supabase = createSupabaseBrowserClient();
    supabase
      .from("notes")
      .select("id, title")
      .order("created_at", { ascending: false })
      .then(({ data }) => setNotes(data ?? []));
  }, []);

  return (
    <ul>
      {notes.map((note) => (
        <li key={note.id}>{note.title}</li>
      ))}
    </ul>
  );
}
