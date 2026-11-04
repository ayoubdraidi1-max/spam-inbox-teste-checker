/*
# Auto-create profile on signup and handle first-user admin assignment

1. New Functions
- `public.handle_new_user()`: trigger function that creates a profile row when a new auth user is created. The first user ever to sign up gets the admin role; subsequent users get the user role.
2. Security
- The function runs as SECURITY DEFINER with a fixed search_path so it can insert into profiles regardless of the caller's permissions.
- EXECUTE is revoked from PUBLIC and anon so only Supabase Auth triggers can invoke it.
3. Important Notes
- This eliminates the need for a server-side signup endpoint; the Supabase client signUp() call creates the auth user, and the trigger creates the profile automatically.
*/

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_count integer;
  v_role text;
BEGIN
  SELECT count(*) INTO v_count FROM public.profiles;
  v_role := CASE WHEN v_count = 0 THEN 'admin' ELSE 'user' END;
  INSERT INTO public.profiles (id, email, role)
  VALUES (NEW.id, NEW.email, v_role);
  RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM PUBLIC, anon;

CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin');
$$;

REVOKE EXECUTE ON FUNCTION public.is_admin() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
