import { createClient } from "npm:@supabase/supabase-js@2.49.1";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const supabaseUrl = Deno.env.get("SUPABASE_URL");
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

const adminClient = createClient(supabaseUrl, serviceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

async function getCallerProfile(req) {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader) return null;
  const token = authHeader.replace("Bearer ", "");
  const { data: userData, error } = await adminClient.auth.getUser(token);
  if (error || !userData.user) return null;
  const { data: profile } = await adminClient
    .from("profiles")
    .select("id,email,role")
    .eq("id", userData.user.id)
    .maybeSingle();
  return profile;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
  const profile = await getCallerProfile(req);
  if (!profile || profile.role !== "admin") {
    return json({ error: "Admin only" }, 403);
  }

  const url = new URL(req.url);
  const action = url.searchParams.get("action") || req.method;

  if (req.method === "GET") {
    const { data, error } = await adminClient
      .from("profiles")
      .select("id,email,role,created_at,mailboxes")
      .neq("role", "admin")
      .order("created_at", { ascending: true });

    if (error) return json({ error: "Could not load users" }, 500);

    const users = (data || []).map((u) => ({
      ...u,
      mailbox_count: (u.mailboxes || "").split("\n").filter(Boolean).length,
    }));

    const presetCounts = {};
    if (users.length) {
      const { data: counts } = await adminClient
        .from("test_presets")
        .select("user_id")
        .in(
          "user_id",
          users.map((u) => u.id),
        );
      (counts || []).forEach((row) => {
        presetCounts[row.user_id] = (presetCounts[row.user_id] || 0) + 1;
      });
    }
    users.forEach((u) => (u.test_count = presetCounts[u.id] || 0));

    return json({ users });
  }

  if (req.method === "POST") {
    const body = await req.json();
    const op = body.op || "create";

    if (op === "create") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      if (!/^\S+@\S+\.\S+$/.test(email))
        return json({ error: "Enter a valid email address" }, 400);
      if (password.length < 6)
        return json({ error: "Password must be at least 6 characters" }, 400);

      const { data, error } = await adminClient.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
      });
      if (error || !data.user)
        return json({ error: "Could not create account" }, 400);

      const { error: profileError } = await adminClient
        .from("profiles")
        .insert({ id: data.user.id, email, role: "user" });
      if (profileError) {
        await adminClient.auth.admin.deleteUser(data.user.id);
        return json({ error: "Could not create account" }, 400);
      }
      return json({ status: "created", email });
    }

    if (op === "delete") {
      const email = String(body.email || "").trim().toLowerCase();
      const { data: userProfile } = await adminClient
        .from("profiles")
        .select("id,role")
        .eq("email", email)
        .maybeSingle();
      if (!userProfile || userProfile.role === "admin")
        return json({ error: "Cannot delete this account" }, 400);
      const { error } = await adminClient.auth.admin.deleteUser(
        userProfile.id,
      );
      if (error) return json({ error: "Could not delete account" }, 400);
      return json({ status: "deleted", email });
    }

    if (op === "reset") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      if (password.length < 6)
        return json(
          { error: "Password must be at least 6 characters" },
          400,
        );
      const { data: userProfile } = await adminClient
        .from("profiles")
        .select("id,role")
        .eq("email", email)
        .maybeSingle();
      if (!userProfile || userProfile.role === "admin")
        return json({ error: "Cannot reset this account" }, 400);
      const { error } = await adminClient.auth.admin.updateUserById(
        userProfile.id,
        { password },
      );
      if (error) return json({ error: "Could not reset account" }, 400);
      return json({ status: "reset", email });
    }

    return json({ error: "Unknown operation" }, 400);
  }

  return json({ error: "Method not allowed" }, 405);
  } catch (err) {
    return json({ error: "Server error" }, 500);
  }
});
