# clinic-intake-app (test fixture)

A small Lovable-shaped clinic intake app (Vite + React, Supabase migrations, Deno edge functions) written
for prelaunch-audit-report's `--phi` tests. The health-data holes are seeded on purpose and listed in
`../clinic-intake-app.holes.json`, next to the controls that must not be flagged. All names and data are
made up. Do not deploy it.

`intake_forms` exists only in `src/integrations/supabase/types.ts`, the way a table made in the Supabase
dashboard shows up in a Lovable repo: the PHI map lists it, but no migration says how it is protected.
