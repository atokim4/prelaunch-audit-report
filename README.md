# prelaunch-audit-report

A command-line tool that audits a Next.js or Vite/React app on Supabase and Stripe and writes one report you
can hand to a founder: severity-rated findings with CWE ids, plain-language risks, effort estimates and a patch
for each finding it knows how to fix. Output is JSON, HTML and an A4 PDF.

Static checkers, including the one bundled here, read the policy text. This tool also runs your migrations in a local Postgres
([PGlite](https://github.com/electric-sql/pglite)), gives one test user a row in every table and then tries to
read and change that row as a visitor with no account and as a second user. A finding says what got through
("user B could select 1 of 1 of user A's rows"). After the patches are written, the same tries run once more with
all of them applied, and the report shows how many leaks are left (0 on both demo apps).

With the project owner's consent it can also probe the live Supabase project, read-only: it counts rows as a
visitor and as two test users the owner creates, never downloads a row, and puts the result next to the local
probe with a list of where the live database and the migrations disagree (a policy fixed or opened in the
dashboard, a table made there).

For health apps, `--phi` adds a health-data pass: it maps the columns that hold protected health information
(PHI), rates any read of them by someone other than the record's own account as Critical, follows the data into
session replay and analytics scripts, AI, email and SMS calls, function logs and public buckets, writes an
append-only audit-trail migration, and fills in Supabase's HIPAA checklist with what the code shows. It is a
technical scan, not a compliance assessment.

I built it as a personal project. The three sample reports below are runs on demo apps I wrote with security
holes on purpose. They are not client audits.

| Sample                                                                            | App shape                                                                   |
| --------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| [Vite + Supabase Edge Functions](examples/sample-report-vite-supabase/report.pdf) | React SPA, migrations, Deno edge functions (the shape AI builders generate) |
| [Next.js App Router](examples/sample-report/report.pdf)                           | Next.js 15, route handlers, migrations, storage buckets                     |
| [Clinic app, health-data mode](examples/sample-report-clinic-phi/report.pdf)      | Lovable-shaped Vite SPA with patient records, run with `--phi`              |

![Pages 1 to 3 of the Vite + Supabase sample report](media/cover-vite-1600x900.png)

## Run it

Node 22.18 or newer, git, and Google Chrome or Chromium for the PDF.

```bash
git clone https://github.com/atokim4/prelaunch-audit-report && cd prelaunch-audit-report
npm ci
node src/cli.ts path/to/your-app --out audit-out
```

`audit-out/` then holds `report.pdf`, `report.html`, `findings.json` and `patches/PA-01.diff`, …

To also check the deployed site, build [apify-launch-audit](https://github.com/atokim4/apify-launch-audit)
once (`npm ci && npm run build` in its folder) and pass its CLI:

```bash
node src/cli.ts path/to/your-app --url https://your-app.example --launch-audit-cli ../apify-launch-audit/dist/cli.js
```

| Option                       | What it does                                                 |
| ---------------------------- | ------------------------------------------------------------ |
| `--out <dir>`                | Output folder (default `audit-out`)                          |
| `--url <url>`                | Also scan the live site                                      |
| `--launch-audit-cli <path>`  | apify-launch-audit `dist/cli.js` (or set `LAUNCH_AUDIT_CLI`) |
| `--launch-audit-json <file>` | Use a saved `launch-audit <url> --json` run instead          |
| `--format json,html,pdf`     | Pick outputs (default all three)                             |
| `--note <text>`              | A line on the cover, for scope or a sample notice            |
| `--name <name>`              | App name on the report (default: `name` in package.json)     |
| `--date <ISO date>`          | Fixed report date, for reproducible output                   |
| `--skip-npm-audit`           | Don't run `npm audit` (it needs network)                     |
| `--phi`                      | Health-data mode (see below)                                 |
| `--live <project url>`       | Read-only probe of the live Supabase project (see below)     |
| `--i-own-this-project`       | Required with `--live`                                       |
| `--live-env <file>`          | Read the key and test logins from a file (`.env.example`)    |
| `--live-rate <n>`            | Requests per second, at most (default 5)                     |
| `--live-max-requests <n>`    | Stop after this many requests (default 600)                  |

Set `CHROME_PATH` if Chrome is somewhere unusual, and `CHROME_NO_SANDBOX=1` when Chrome runs inside a
container that has no sandbox.

## What it checks

The tool first works out the project shape (Next.js App or Pages Router, Vite + React SPA, number of
migrations, each Supabase Edge Function and its `verify_jwt` setting from `supabase/config.toml`) and prints it on
the cover.

### Row Level Security, by behaviour

`supabase/migrations/*.sql` are loaded in order into PGlite on top of a small stand-in for the parts of Supabase
they rely on (the `anon`, `authenticated` and `service_role` roles, `auth.users`, `auth.uid()`, storage tables,
Supabase's default grants, the realtime publication, Supabase's internal roles and a `cron.schedule` stand-in).
Extensions PGlite ships (`uuid-ossp`, `pgcrypto`, `pg_trgm`, `citext` and others) are loaded when a migration asks
for them; platform-only ones such as `pg_net` or `pg_cron` are stepped over and named in the appendix. Two users
are created. Every table in `public` gets one row owned by user A. Owner columns are the ones that reference
`auth.users`, or are called `user_id`, `owner_id` and similar; a table without one that has a foreign key to an
owned table (messages of a project) belongs to the parent row's owner. Parents are seeded first, and unique
columns get fresh values. Then, each in a transaction that is rolled back:

- as a visitor with only the public key: select, insert a row in A's name, update and delete A's rows;
- as user B: the same four on user A's rows;
- as user A: write a different value into their own `plan`, `role`, `credits`, `stripe_*` and similar columns,
  counting it only when the stored value really changed (a trigger that resets or rejects it counts as blocked);
- for views: select as the visitor and as user B.

Only a permission error or an RLS violation counts as "blocked". A try that fails for another reason (a check
constraint or trigger rejecting the test values) is shown as "?" and proves nothing either way.

What gets through decides the severity. A visitor reaching user rows is Critical. User B reaching A's rows, or
A upgrading their own plan, is High. A table that belongs to no user at all (a price list) may be readable by
everyone; only writes to it count. When no static rule explains a leak, it becomes its own finding pointing at the policy that
let it through. The two most common shapes it catches that policy linters pass are `using (auth.role() =
'authenticated')` on a select and `with check (auth.uid() is not null)` on an insert.

If a migration still does not load in PGlite (`vector` or `postgis`, which this PGlite build doesn't have, for
example), the report says so and only the static checks run.

### Repository rules

Checked with [vibe-preflight](https://github.com/atokim4/vibe-preflight) 1.3.0 (vendored, SHA-256
pinned, see [vendor/vibe-preflight](vendor/vibe-preflight/README.md)), then adjusted by the probe where it ran:

| Rule                                                                                                                         | Report severity                                                                                                                                                             | CWE  |
| ---------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- |
| `rls-disabled`: table in `public` with Row Level Security off                                                                | Critical                                                                                                                                                                    | 862  |
| `rls-permissive-policy`: `using (true)` / `with check (true)`                                                                | Critical on writes, High on reads; Critical if visitors really read user rows; Low for a select policy on a table that belongs to no user, when every write try was refused | 863  |
| `rls-update-privileged-column`: users can update their own `plan` / `role` / `credits`                                       | High                                                                                                                                                                        | 915  |
| `view-bypasses-rls`: view without `security_invoker`                                                                         | High, Critical if visitors really read user rows                                                                                                                            | 863  |
| `auth-users-exposed`: view over `auth.users` in `public`                                                                     | Critical                                                                                                                                                                    | 359  |
| `definer-function-anon`: SECURITY DEFINER function anon can call over RPC                                                    | Critical (explicit grant), High (default grant)                                                                                                                             | 269  |
| `definer-search-path`: SECURITY DEFINER function without `set search_path`                                                   | Medium                                                                                                                                                                      | 426  |
| `storage-public-bucket`: public bucket                                                                                       | Critical when anyone can list it, else Medium                                                                                                                               | 552  |
| `rls-no-policy`: RLS on and no policies (safe, but reads come back empty)                                                    | Low                                                                                                                                                                         | none |
| `server-secret-in-client`: service role or Stripe secret in browser code                                                     | Critical                                                                                                                                                                    | 668  |
| `public-env-secret`: secret behind `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_`                                                 | Critical or High                                                                                                                                                            | 668  |
| `stripe-webhook-unverified`: webhook without `constructEvent` (route handlers and Deno edge functions)                       | Critical                                                                                                                                                                    | 345  |
| `stripe-webhook-parsed-body`: signature checked against a parsed body                                                        | Medium                                                                                                                                                                      | 345  |
| `env-file-committed`: `.env` file with values tracked by git                                                                 | Critical, or Low when it holds only demo keys or public values                                                                                                              | 312  |
| `stripe-webhook-jwt-gate`: webhook edge function that checks the signature but keeps `verify_jwt = true`, so Stripe gets 401 | Medium (fails closed)                                                                                                                                                       | none |

### Credentials

A built-in scanner reads the files git would publish and every commit in
`git log -p --all`. It knows ten key formats with fixed prefixes (Stripe secret and webhook keys, Supabase
secret keys and service_role JWTs, AWS, GitHub, Anthropic, OpenAI, Slack, private key blocks). It skips
placeholders, anon JWTs and the Supabase CLI's local demo key, and masks every value it reports. A key still in
the files is Critical; one that only lives in history is High; Stripe test keys are Low. It does not look for
generic `password = "..."` strings, so it misses those on purpose.

### Dependencies

`npm audit --json --package-lock-only --omit=dev` when the repo has a `package-lock.json`. One finding per
package that carries an advisory (packages listed only because they depend on it are folded in), rated one level
below npm's rating, because the advisory says the version is affected, not that your code reaches the affected
function. Without a lockfile or network the report says dependencies were not checked.

### The live Supabase project (optional, read-only)

A repo scan cannot see what was changed in the Supabase dashboard. `--live` checks the running project, and
only when you own it or have the owner's written permission: it refuses to start without
`--i-own-this-project`.

```bash
cp .env.example .env.live   # the anon or publishable key, and two test logins
node src/cli.ts path/to/your-app --live https://<ref>.supabase.co --i-own-this-project --live-env .env.live
```

The owner creates two throwaway accounts, A and B, and gives A at least one row in each table (and a file under
`<user A id>/` in each bucket). Then, as a visitor with only the public key, as A and as B:

- for every table and view the migrations create, plus the ones only `src/integrations/supabase/types.ts` (the
  file Lovable and `supabase gen types` write) knows about: how many rows each can see, how many of A's rows B
  and the visitor get, and how many rows B sees that are not B's (for tables owned through a parent row);
- storage: the bucket list, and how many entries each can list in A's folder;
- RPC functions are listed from the migrations and the types file, never called.

It is read-only by construction. Counts come from `HEAD` requests with `Prefer: count=exact`, so the answer is a
`Content-Range` header and no row crosses the wire; an error is asked again with `limit=0` to read its code.
The HTTP layer refuses any `POST` other than sign-in, sign-out and storage listing, keeps to 5 requests a second by
default and stops at a request cap. The secret and `service_role` keys are refused before anything is sent,
because they skip RLS. The two sessions are signed out at the end. Only Postgres' own refusal (SQLSTATE 42501, or
a row-level security error) is "blocked"; a 401, a timeout or any other error is shown as "no answer".

Live leaks fold into the repo finding for the same table. A leak no repo finding explains becomes its own finding
(High when user B gets through, Critical for a visitor) with a patch: a restrictive select policy, owner only,
which Postgres ANDs with every other policy, so it closes the leak without knowing what the dashboard policy is
called. The report adds a "live project" page with the counts and a drift table: fixed in the dashboard only (the
repo still has the hole), opened in the dashboard, not in the migrations, not deployed.

What it does not do: try inserts, updates or deletes on the live project, call RPC functions, or probe tables the
repo does not name. The OpenAPI listing at `/rest/v1/` is closed to the public key on newer Supabase projects,
so the table list has to come from the repo.

### Live site (optional)

apify-launch-audit checks HTTPS and HSTS, security headers, cookie flags, keys in
the JavaScript bundles, public source maps, exposed `.env` or `.git`, robots and sitemap, slow responses. These
findings keep the severity that tool gives them.

### Health data (`--phi`)

For apps that store patient data. It reads files only, like the repo checks.

- **PHI map.** Columns are matched by name: clinical content (`diagnosis`, `medications`, `allergies`,
  `lab_*`, `clinical_*`; `notes` or `reason` only on tables such as `patients` or `appointments`) and identifiers
  (`date_of_birth`, `mrn`, `ssn`, `insurance_*`). A birthday on a plain `profiles` table is not counted. Views get
  the kinds of the columns they copy. Tables named like health records (`medical_records`, `vaccinations`,
  `lab_reports`) count as a whole when a column ties them to a person, and national ID columns (`tckn`, `aadhaar`,
  `cpf`, `passport*`) count as identifiers. Tables come from every `.sql` file outside archive folders
  (`supabase/migrations`, a `schema.sql`, `sql/`, `prisma/migrations`) and from the generated types file, so a
  table made in the dashboard shows up too. Tables the probe could not load are listed as "not tried".
- **Who can read it.** The map is joined with the RLS probe. With `--phi`, a PHI table or view that a visitor
  or a second user can read is Critical, where the same leak in a CRM is High. A view that skips RLS stays
  Critical when the probe had no row to disprove it (a view filtered to today's date, for example).
- **Scripts on PHI pages.** Session replay (PostHog unless `disable_session_recording: true`, Sentry Replay,
  Hotjar, Clarity, FullStory, LogRocket) is High; page-view analytics (Google Analytics and Tag Manager, Meta
  Pixel, Mixpanel, Segment, the Lovable editor script) is Medium. A script counts when it loads in a global file
  (`index.html`, `main.tsx`, `App.tsx`, `app/layout`, `pages/_app`) or on the page itself, and a page counts when
  it reads a PHI table and names a PHI column.
- **Vendors.** Server code (edge functions, `app/api`, `pages/api`, `server/`) that reads a PHI table, names PHI
  fields and calls OpenAI, Anthropic, Gemini, Resend, SendGrid, Postmark, Mailgun or Twilio is High: the vendor
  must sign a Business Associate Agreement (BAA) first. The report never says a vendor is or is not compliant.
- **Logs and buckets.** `console.*` calls in that server code that print PHI rows or fields (Medium), and public
  buckets whose name or upload code says they hold patient files (Critical).
- **Audit trail.** Without a trigger that writes changes of the PHI tables to an audit table, the report adds a
  migration: `phi_audit_log` with the user id from `auth.uid()`, the role, the operation and the row id (no row
  values, so the log holds no PHI), filled by a trigger on every PHI table, revoked from `anon` and
  `authenticated`, and guarded so even the table owner gets SQLSTATE 42501 on update, delete or truncate. The
  suite loads it in PGlite and proves both. When the app inserts audit rows from its own code instead, the
  finding drops to Low and names that file: the trail exists, but changes made outside the app are not in it.
- **Checklist.** The report copies the customer side of
  [Supabase's shared responsibility model](https://supabase.com/docs/guides/deployment/shared-responsibility-model)
  for health data (read 16 November 2026: BAA on the Team plan or above with the HIPAA add-on, High Compliance,
  MFA, PITR, SSL enforcement, network restrictions, connection logging, no PHI in public buckets, no transfer to
  a non-HIPAA organization) and marks the items the code can show as ok or gap; the rest say "confirm".

## What it does not check

The cover of every report lists this too:

- Business logic and authorization inside your own API routes, server actions and edge functions (beyond the
  Stripe webhook).
- The live database, unless `--live` ran. Policies or grants changed in the Supabase dashboard and never saved as
  migrations are invisible to a repo scan. With `--live`, only reads were tried there.
- Rate limiting, abuse protection, and the auth and email settings in the Supabase dashboard.
- Manual penetration testing. Every finding comes from an automated scanner, the local probe or read-only
  counts on the live project; nobody tried to break in by hand.

With `--phi`, also: HIPAA compliance as a whole (that needs a risk analysis, policies, training and signed
agreements), PHI in columns whose names don't give it away, reads of health records (triggers log changes only),
Next.js server actions outside `app/api`, and whether a vendor already signed a BAA with you.

The probe also has limits worth knowing: it seeds one row per table with guessed values, so a table whose check
constraints or triggers reject those values is listed as "not tried"; it tests the two API roles, not
`service_role`; functions called over `/rest/v1/rpc/` are checked statically, not called; and it only loads
`supabase/migrations`. SQL kept anywhere else is read statically (rules, PHI map), not run.

## Severity rubric

A rule gets the first level that fits:

1. **Critical**: anyone on the internet, without an account, can read private data, change data, take
   money-related actions or get a key that does those things.
2. **High**: a signed-in user can reach other users' data or give themselves something they did not pay for, or
   private data is exposed under a condition the scanner cannot rule out.
3. **Medium**: a missing safeguard that makes another bug easier to exploit or worse, or a bug that breaks a
   feature in a way that fails closed.
4. **Low**: hygiene and launch polish.

With `--phi` three placements come first: a read of health data by anyone but the record's own account, or
health files in a public bucket, is Critical; health data sent to a vendor that must sign a BAA, or a PHI table
with no migration, is High; PHI in logs, analytics on PHI pages and a missing audit trail are Medium.

Two rules that flag the same object (for example a view over `auth.users` that also lacks `security_invoker`)
become one finding, named after the more specific rule, with the other listed under "also flagged by".

## Patches

For 18 rules the tool writes a fix: a new Supabase migration for the database rules, or an edit of the file for
the code rules. Each patch is a unified diff that applies with `git apply` from the repo root, and the tool runs
`git apply --check` on it against the code as scanned before it calls the patch verified. Some of them:

- A leak only the probe found: each policy that let it through is rewritten in place (same name) so the owner
  column must equal `(select auth.uid())`.
- Stripe webhook in a Next.js route handler: raw body plus `constructEventAsync`.
- Stripe webhook in a Supabase Edge Function (Deno): raw body plus `constructEventAsync` with
  `Stripe.createSubtleCryptoProvider()`, because Deno has no Node crypto. The test suite runs the bench app's
  function in Node, with stand-ins for `serve`, `Deno.env` and the Supabase client, before and after the patch,
  and signs events with the real Stripe package: the original upgrades a plan for an unsigned POST, the patched
  one returns 400 for a missing or forged signature and 200 for a signed event.
- `phi-no-audit-log`: the append-only audit-trail migration described above.
- `phi-session-replay` for PostHog: adds `disable_session_recording: true` to `posthog.init`. Other replay
  vendors and the BAA findings get no patch, because the fix there is a decision (remove the script, sign a BAA,
  or stop sending the fields), and the report says so under the finding.
- `stripe-webhook-jwt-gate`: sets `verify_jwt = false` for that function in `supabase/config.toml`.
- A secret behind `VITE_` or `NEXT_PUBLIC_` in browser code: renamed everywhere so the next build no longer ships
  it. That patch is marked **partial** in the report, because the code that used the key still runs in the
  browser and has to move to an edge function or server route. A mechanical move would keep trusting whatever
  arguments the browser sends, so the tool leaves that to a person and says so.

"Verified" on a patch means `git apply --check` passed; it is not a test of the result. For the database the
re-run of the probe is that test: after all patches are drafted, the probe runs again on the migrations with
every verified patch applied, and each finding shows how many leaks are left. Every patch also lists what it cannot know, such as "check that owner_id
is who should have access". Read each one before applying it.

## Results on the demo apps

All three apps live in `test/fixtures` with their ground truth next to them. Holes are seeded on purpose; controls are
done right and must not be flagged at Medium or above.

**pipeline-crm-app** (Vite + React SPA, 7 migrations, 2 Deno edge functions): 9 holes, 7 controls.

- All 9 holes are reported: 5 Critical, 4 High, plus 1 Low (the public price list, see below).
- 2 of the 9 are found only by the probe: a select policy that checks `auth.role() = 'authenticated'` (any
  signed-in user reads every deal) and an insert policy that checks `auth.uid() is not null` (user B writes rows
  in user A's name). vibe-preflight passes both.
- The price list control has an open read policy. vibe-preflight rates that High; the probe finds no owner column
  and no write getting through, so the report rates it Low ("confirm it is meant to be public"). No control is
  flagged at Medium or above.
- All 9 Critical and High findings have a verified patch; one of them is partial (the Vite secret). With the
  patches applied the probe finds 0 leaks in all 9 tables and views, checked once inside the audit and once more by
  the test suite from the patched files.

**broken-notes-app** (Next.js App Router, 13 migrations): 12 holes, 7 controls, originally written for an earlier
benchmark of mine.

- All 12 holes are reported and none of the 7 controls is: 9 Critical, 1 High, 1 Medium, 1 Low. Two findings
  went from High to Critical once the probe ran, because a visitor without an account really read user rows
  through them (`messages` with `using (true)` and the `recent_notes` view).
- All Critical and High findings and the Medium one come with a verified patch. The suite applies every patch to a
  copy, re-runs all migrations and checks behaviour: anon gets no rows from `audit_log`, a third user cannot read a
  conversation, a user cannot set their own `plan` but can change `display_name`, the admin RPC and user
  directory are closed to the API roles, the view runs as the caller, the invoices bucket is private.
- `scripts/typecheck-patched-app.sh` installs that app's real dependencies (Next.js 15.5, Stripe 19.1,
  supabase-js 2.58) and type-checks the patched code. It needs network, so it is not part of `npm test`.

**clinic-intake-app** (Vite + React SPA, 5 migrations, 3 Deno edge functions, run with `--phi`): 10 holes,
5 controls, all patient data made up.

- All 10 holes are reported, each with the expected rule: 3 Critical, 4 High, 4 Medium, plus 1 Low (the public
  clinic address list). No control gets a PHI finding: the prescriptions table scoped through its patient, an edge
  function that sends a clinic's public description to the Anthropic API and logs only an id, a public logos
  bucket, and a page without health data. The logos bucket keeps the Medium that vibe-preflight gives every
  public bucket, which is why this app's controls are judged on PHI findings only.
- The patients leak (a select policy that checks `auth.role() = 'authenticated'`) is High without `--phi` and
  Critical with it.
- 6 findings have a verified patch, including all 3 Critical ones. The 3 High findings without one are the two
  vendor calls and the table that exists only in the types file. With every patch applied, the audit run again
  leaves the findings that need a decision (BAA or not, the dashboard-made table, analytics, the logging lines)
  and the audit trail covers every PHI table.
- `--phi` on the other two demo apps maps no PHI table and adds no finding.

Read these numbers for what they are. I wrote the demo apps and the scanner rules, so the apps test what the
tools know, and 9 of 9, 12 of 12 or 10 of 10 is not an independent detection rate. On someone else's app expect misses.
None of the apps has committed secrets, so they say nothing about the credential scanner; its tests use keys built at
runtime in temporary git repos.

**The live probe** is tested end to end against the real [PostgREST](https://postgrest.org) 16.5 binary (the server
behind `supabase.co/rest/v1`) running on PGlite through
[pglite-socket](https://github.com/electric-sql/pglite/tree/main/packages/pglite-socket), with the pipeline-crm
migrations, a file of changes "made in the dashboard" (`test/fixtures/pipeline-crm-live`) and made-up rows. Auth
and the API gateway are a small Node stand-in (`test/live/stand-in.ts`): it checks the key, answers the GoTrue
password grant with JWTs PostgREST verifies, and serves storage listing through PostgREST on the `storage` schema,
which has the same RLS but simpler answers than Supabase Storage. So counts, `Content-Range`, error codes and RLS
are real PostgREST and Postgres behaviour; auth and storage are emulated. On that stand-in the probe:

- finds all 4 seeded drifts: the leads policy fixed in the dashboard only, tasks opened to every signed-in user
  (and the `open_tasks` view over it), a `notes` table that only the types file knows;
- finds user B listing user A's folder in a private bucket whose policy checks the bucket and not the folder;
- leaves every row unchanged (a fingerprint of all tables before and after), sends only the allowed requests,
  and puts no row value in its output;
- has its two restrictive patches applied to a fresh stand-in in the suite, after which tasks, `open_tasks` and the
  bucket come back protected.

With the live part the Vite sample has 13 findings: 5 Critical, 7 High, 1 Low. 11 of the 12 Critical and High
ones have a verified patch; the `open_tasks` view has none of its own, because the tasks patch is its fix.

Regenerate the samples with `npm run sample`, `npm run sample:phi` and `npm run sample:vite` (the second one needs `npm run postgrest`
once, which downloads PostgREST and checks its SHA-256).

## Run on 7 real clinic codebases

The demo apps above test what I already knew to look for, so on 16 November 2026 I ran `--phi` on seven public
open-source clinic and health-record repos from GitHub. Static only: clone, scan the code and SQL, read every
finding by hand. Nothing was sent to their deployments. Each repo was pinned at one commit.

The first run (v0.4.0) gave 61 findings. 12 were wrong: RLS turned on by a `DO` loop of dynamic SQL read as RLS
off (5), policies in a `supabase/archive` folder that a later migration replaces (3), sample key headers inside a
committed `node_modules` (2), a Supabase anon key under an unusual env name (1), and a diet plan column read as a
paid plan (1). The PHI map was empty on all seven, because it only knew tables the probe had loaded from
`supabase/migrations`, and most of these repos keep their SQL somewhere else.

Each of those now has a fixture test in `test/real-repo-shapes.test.ts`, with a control case that must still be
reported. The same run also turned up a probe bug (an insert into a table where every column has a default) and
tables that are public on purpose (CMS sections, clinic schedules) rated High; with the SQL showing no owner and
no personal column, those are now Low with a "confirm it is meant to be public" line.

After the fixes, on the same commits:

| repo                            | Critical | High | Medium | Low | PHI tables | RLS probe                      |
| ------------------------------- | -------- | ---- | ------ | --- | ---------- | ------------------------------ |
| ahmedbahnese/clinic             | 0        | 0    | 4      | 9   | 2          | ran                            |
| kareeem7/clinic                 | 5        | 9    | 4      | 6   | 4          | no `supabase/migrations`       |
| goldhoang/clinic-booking        | 0        | 0    | 1      | 0   | 1          | failed (tables made by Prisma) |
| mustafakbaser/ClinicManager-App | 4        | 0    | 1      | 0   | 1          | no `supabase/migrations`       |
| pranavgawasproject/medi-care    | 0        | 2    | 1      | 2   | 6          | no `supabase/migrations`       |
| phanindraks2005/medivault       | 0        | 0    | 1      | 0   | 3          | no `supabase/migrations`       |
| Nico2603/ClinicAI               | 0        | 5    | 17     | 0   | 1          | no `supabase/migrations`       |

No wrong finding is left that I know of. Two calls are still debatable: kareeem7's 5 Critical are patient-portal
functions granted to visitors on purpose and gated by a session token inside, which needs a person to judge, and a
public doctors directory stays High because the table links to user accounts.

What it missed, found by reading the schemas:

- A user able to change their own `role` when the policy checks ownership through a wrapper function instead of
  `auth.uid()` directly. The static rule doesn't see it, and the probe would have, but it couldn't load that repo.
- A browser-side call to an AI API with clinical text. The PHI vendor check reads server code only, so the only
  signal was the `NEXT_PUBLIC_` key finding.
- A role change that leads to admin rights is rated High, where Critical would be fairer.
- An AI chat history table in a health app, whose column names say nothing about health.

Real gaps in these repos go to their maintainers, through the channel each repo asks for, and not into this
README.

## Development

```bash
npm ci
npm run postgrest   # once: PostgREST 16.5 for the live-probe tests (Linux x86-64; else set POSTGREST_BIN)
npm run check       # tsc, eslint, prettier, vitest (about two minutes: each probe boots Postgres in WASM)
```

The code runs as TypeScript directly on Node's type stripping, with no build step.

```
src/cli.ts              options, writes the output folder
src/audit.ts            project shape, scanners, probe, normalise, patches, re-probe
src/shape.ts            framework, migrations, edge functions and verify_jwt
src/probe/              the RLS probe (PGlite) and the Supabase stand-in it loads first
src/live/               the read-only live probe: table list, rate-limited HTTP, counts, drift
src/scanners/           vibe-preflight (subprocess), secrets, npm audit, launch-audit, probe → findings
src/rubric.ts           severity, CWE, effort and plain-language text per rule
src/normalize.ts        rubric + dedupe + ordering + ids
src/patches/            fixers per rule, SQL reading, diff and git apply --check
src/report/             HTML template and the PDF print (playwright-core + Chrome)
```

## Credits and licence

MIT, see [LICENSE](LICENSE). The vendored vibe-preflight bundle is MIT. Fonts embedded in the report are Source
Serif 4 and IBM Plex (SIL Open Font License, via Fontsource). PGlite is Apache-2.0 / PostgreSQL licensed. The
Stripe npm package (MIT) is a dev dependency, used only to sign test events. pglite-socket (Apache-2.0) is a dev
dependency; PostgREST (MIT) is downloaded for the tests, not shipped.
