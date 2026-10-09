import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const reply = (body: Record<string, unknown>, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return reply({ error: "Method not allowed." }, 405);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !anonKey || !serviceKey) {
    return reply({ error: "Server configuration is incomplete." }, 500);
  }

  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return reply({ error: "Please sign in as an administrator." }, 401);
  const token = authHeader.slice("Bearer ".length);

  // Validate the caller's access token before checking their school role.
  const callerClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: callerData, error: callerError } = await callerClient.auth.getUser(token);
  if (callerError || !callerData.user) return reply({ error: "Your session is invalid or expired. Sign in again." }, 401);

  // The service key stays on the server; it is never sent to the browser.
  const adminClient = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: callerProfile, error: profileError } = await adminClient
    .from("school_profiles")
    .select("role")
    .eq("auth_user_id", callerData.user.id)
    .maybeSingle();

  if (profileError) return reply({ error: "Could not verify your school role." }, 500);
  if (callerProfile?.role !== "admin") return reply({ error: "Only a school administrator can register students." }, 403);

  let body: { full_name?: unknown; email?: unknown; class_name?: unknown };
  try {
    body = await req.json();
  } catch {
    return reply({ error: "Please provide valid student details." }, 400);
  }

  const fullName = typeof body.full_name === "string" ? body.full_name.trim() : "";
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const className = typeof body.class_name === "string" ? body.class_name.trim() : "";
  const allowedClasses = ["JSS 1", "JSS 2", "JSS 3", "SS 1", "SS 2", "SS 3"];

  if (fullName.length < 2 || fullName.length > 120) return reply({ error: "Enter a student name between 2 and 120 characters." }, 400);
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return reply({ error: "Enter a valid student email address." }, 400);
  if (!allowedClasses.includes(className)) return reply({ error: "Choose a valid class." }, 400);

  const { data: inviteData, error: inviteError } = await adminClient.auth.admin.inviteUserByEmail(email, {
    data: { full_name: fullName },
  });
  if (inviteError || !inviteData.user) {
    return reply({ error: inviteError?.message || "The student invitation could not be created." }, 400);
  }

  const { error: insertError } = await adminClient.from("school_profiles").insert({
    auth_user_id: inviteData.user.id,
    full_name: fullName,
    email,
    role: "student",
    class_name: className,
  });

  if (insertError) {
    // Roll back the newly invited account if its school profile could not be created.
    await adminClient.auth.admin.deleteUser(inviteData.user.id);
    return reply({ error: "The invitation was rolled back because the school profile could not be saved. Check for an existing profile and try again." }, 500);
  }

  return reply({ success: true, message: "Student invitation sent.", student: { full_name: fullName, email, class_name: className } }, 201);
});
