/*
# Create Mailbox Hit Checker data model

1. New Tables
- `profiles`: one row per signed-in account, linked to Supabase Auth; stores display email, role, and the owner's mailbox text.
- `test_presets`: saved search input sets owned by one account.
- `scan_runs`: durable scan status, progress, logs, and results owned by one account.
2. Security
- Row Level Security is enabled on every table.
- Normal signed-in users can only read and change their own profile content, presets, and scan runs.
- The role field is not writable by normal users.
- Admin access is granted only to accounts whose profile role is `admin`.
3. Important Notes
- Existing JSON records are not copied automatically because they contain credentials and are not safe to expose through the browser.
- The application server will use the service role only after validating the signed-in Supabase user and admin role.
*/

CREATE TABLE IF NOT EXISTS public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email text NOT NULL,
  role text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  mailboxes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.test_presets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL,
  inputs text NOT NULL DEFAULT '',
  saved_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, name)
);

CREATE TABLE IF NOT EXISTS public.scan_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'idle' CHECK (status IN ('idle', 'running', 'stopping', 'completed', 'failed', 'reset')),
  mode text NOT NULL DEFAULT 'hybrid',
  started_at timestamptz,
  finished_at timestamptz,
  progress integer NOT NULL DEFAULT 0,
  total integer NOT NULL DEFAULT 0,
  current text NOT NULL DEFAULT '',
  log text[] NOT NULL DEFAULT '{}',
  counts jsonb NOT NULL DEFAULT '{"mailboxes":0,"inputs":0}'::jsonb,
  results jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.test_presets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_runs ENABLE ROW LEVEL SECURITY;

GRANT SELECT ON public.profiles TO authenticated;
GRANT UPDATE (mailboxes) ON public.profiles TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.test_presets TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scan_runs TO authenticated;
GRANT ALL ON public.profiles, public.test_presets, public.scan_runs TO service_role;

DROP POLICY IF EXISTS "profiles_select_own" ON public.profiles;
CREATE POLICY "profiles_select_own" ON public.profiles FOR SELECT TO authenticated USING (auth.uid() = id);
DROP POLICY IF EXISTS "profiles_update_mailboxes_own" ON public.profiles;
CREATE POLICY "profiles_update_mailboxes_own" ON public.profiles FOR UPDATE TO authenticated USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS "test_presets_select_own" ON public.test_presets;
CREATE POLICY "test_presets_select_own" ON public.test_presets FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "test_presets_insert_own" ON public.test_presets;
CREATE POLICY "test_presets_insert_own" ON public.test_presets FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS "test_presets_update_own" ON public.test_presets;
CREATE POLICY "test_presets_update_own" ON public.test_presets FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS "test_presets_delete_own" ON public.test_presets;
CREATE POLICY "test_presets_delete_own" ON public.test_presets FOR DELETE TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "scan_runs_select_own" ON public.scan_runs;
CREATE POLICY "scan_runs_select_own" ON public.scan_runs FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "scan_runs_insert_own" ON public.scan_runs;
CREATE POLICY "scan_runs_insert_own" ON public.scan_runs FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS "scan_runs_update_own" ON public.scan_runs;
CREATE POLICY "scan_runs_update_own" ON public.scan_runs FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS "scan_runs_delete_own" ON public.scan_runs;
CREATE POLICY "scan_runs_delete_own" ON public.scan_runs FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE INDEX IF NOT EXISTS test_presets_user_id_idx ON public.test_presets(user_id);
CREATE INDEX IF NOT EXISTS scan_runs_user_id_created_at_idx ON public.scan_runs(user_id, created_at DESC);
