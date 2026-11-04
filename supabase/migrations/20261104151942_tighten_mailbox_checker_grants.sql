/*
# Tighten Mailbox Hit Checker database access

1. Modified Tables
- `profiles`: remove public access and allow authenticated users to update only their own mailbox text.
- `test_presets`: remove public access; signed-in users keep owner-scoped CRUD.
- `scan_runs`: remove public access; signed-in users keep owner-scoped CRUD.
2. Security
- Revoke inherited anon and broad authenticated table privileges.
- Restore only the minimum grants needed by the protected policies.
- Keep the profile role and identity columns outside normal client writes.
3. Important Notes
- The JavaScript server uses the service role only after validating the Supabase session and profile role.
- Row Level Security remains enabled on all three tables.
*/

REVOKE ALL ON public.profiles FROM anon, authenticated;
REVOKE ALL ON public.test_presets FROM anon, authenticated;
REVOKE ALL ON public.scan_runs FROM anon, authenticated;

GRANT SELECT ON public.profiles TO authenticated;
GRANT UPDATE (mailboxes) ON public.profiles TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.test_presets TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scan_runs TO authenticated;
