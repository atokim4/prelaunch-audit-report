"use client";

import { useEffect, useState } from "react";
import { createSupabaseBrowserClient } from "@/lib/supabase/browser";

interface Project {
  id: string;
  name: string;
}

export function ProjectsList({ organizationId }: { organizationId: string }) {
  const [projects, setProjects] = useState<Project[]>([]);

  useEffect(() => {
    const supabase = createSupabaseBrowserClient();
    supabase
      .from("projects")
      .select("id, name")
      .eq("organization_id", organizationId)
      .then(({ data }) => setProjects(data ?? []));
  }, [organizationId]);

  return (
    <ul>
      {projects.map((p) => (
        <li key={p.id}>{p.name}</li>
      ))}
    </ul>
  );
}
