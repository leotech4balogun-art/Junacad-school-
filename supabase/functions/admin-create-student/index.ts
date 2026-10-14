import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const reply = (body: Record<string, unknown>, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return reply({ error: "Method not allowed." }, 405);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !anonKey || !serviceKey) return reply({ error: "Server configuration is incomplete." }, 500);

  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return reply({ error: "Please sign in as an administrator." }, 401);
  const token = authHeader.slice("Bearer ".length);
  const callerClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: callerData, error: callerError } = await callerClient.auth.getUser(token);
  if (callerError || !callerData.user) return reply({ error: "Your session is invalid or expired. Sign in again." }, 401);

  const adminClient = createClient(supabaseUrl, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: callerProfile, error: profileError } = await adminClient.from("school_profiles")
    .select("role").eq("auth_user_id", callerData.user.id).maybeSingle();
  if (profileError) return reply({ error: "Could not verify your school role." }, 500);
  if (callerProfile?.role !== "admin") return reply({ error: "Only a school administrator can manage student accounts." }, 403);

  let body: { action?: unknown; full_name?: unknown; email?: unknown; class_name?: unknown; role?: unknown; profile_id?: unknown; user_id?: unknown; password?: unknown };
  try { body = await req.json(); } catch { return reply({ error: "Please provide valid account details." }, 400); }

  const action = typeof body.action === "string" ? body.action : "create_and_invite";
  const validEmail = (value: string) => value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  const allowedClasses = ["JSS 1", "JSS 2", "JSS 3", "SS 1", "SS 2", "SS 3"];

  if (action === "reset_password") {
    const userId = typeof body.user_id === "string" ? body.user_id.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!userId || password.length < 8 || password.length > 72) return reply({ error: "Enter a valid user ID and a password between 8 and 72 characters." }, 400);
    const { error } = await adminClient.auth.admin.updateUserById(userId, { password });
    if (error) return reply({ error: error.message || "Password reset failed." }, 400);
    return reply({ success: true, message: "Student password updated." });
  }

  if (action === "update_student") {
    const profileId = typeof body.profile_id === "string" ? body.profile_id.trim() : "";
    const fullName = typeof body.full_name === "string" ? body.full_name.trim() : "";
    const className = typeof body.class_name === "string" ? body.class_name.trim() : "";
    if (!profileId) return reply({ error: "Select a student record." }, 400);
    if (fullName.length < 2 || fullName.length > 120) return reply({ error: "Enter a name between 2 and 120 characters." }, 400);
    if (!allowedClasses.includes(className)) return reply({ error: "Choose a valid class." }, 400);
    const { data: student, error: findError } = await adminClient.from("school_profiles")
      .select("id,role").eq("id", profileId).maybeSingle();
    if (findError || !student) return reply({ error: "Student record not found." }, 404);
    if (student.role !== "student") return reply({ error: "Only student records can be edited here." }, 400);
    const { error } = await adminClient.from("school_profiles")
      .update({ full_name: fullName, class_name: className }).eq("id", profileId).eq("role", "student");
    if (error) return reply({ error: "Student details could not be updated: " + error.message }, 400);
    return reply({ success: true, message: "Student details updated." });
  }

  if (action === "delete_student") {
    const profileId = typeof body.profile_id === "string" ? body.profile_id.trim() : "";
    if (!profileId) return reply({ error: "Select a student record." }, 400);
    const { data: student, error: findError } = await adminClient.from("school_profiles")
      .select("id,role,auth_user_id").eq("id", profileId).maybeSingle();
    if (findError || !student) return reply({ error: "Student record not found." }, 404);
    if (student.role !== "student") return reply({ error: "Only student records can be deleted here." }, 400);
    const { error: deleteProfileError } = await adminClient.from("school_profiles")
      .delete().eq("id", profileId).eq("role", "student");
    if (deleteProfileError) return reply({ error: "Student record could not be deleted: " + deleteProfileError.message }, 400);
    if (student.auth_user_id) {
      const { error: deleteAuthError } = await adminClient.auth.admin.deleteUser(student.auth_user_id);
      if (deleteAuthError) {
        return reply({ success: true, warning: "Student profile removed, but the linked sign-in account could not be removed automatically. Please contact technical support." });
      }
    }
    return reply({ success: true, message: "Student record and linked sign-in account deleted." });
  }

  if (action === "create_record") {
    const fullName = typeof body.full_name === "string" ? body.full_name.trim() : "";
    const className = typeof body.class_name === "string" ? body.class_name.trim() : "";
    if (fullName.length < 2 || fullName.length > 120) return reply({ error: "Enter a name between 2 and 120 characters." }, 400);
    if (!allowedClasses.includes(className)) return reply({ error: "Choose a valid class." }, 400);
    const { data, error } = await adminClient.from("school_profiles").insert({
      full_name: fullName, email: null, role: "student", class_name: className, auth_user_id: null,
    }).select("id,full_name,class_name").single();
    if (error) return reply({ error: "Student record could not be saved: " + error.message }, 400);
    return reply({ success: true, message: "Student record created without an email.", student: data }, 201);
  }

  if (action === "invite_existing") {
    const profileId = typeof body.profile_id === "string" ? body.profile_id.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    if (!profileId) return reply({ error: "Select a student record." }, 400);
    if (!validEmail(email)) return reply({ error: "Enter a valid email address." }, 400);
    const { data: student, error: studentError } = await adminClient.from("school_profiles")
      .select("id,full_name,class_name,role,auth_user_id,email").eq("id", profileId).maybeSingle();
    if (studentError || !student) return reply({ error: "Student record not found." }, 404);
    if (student.role !== "student") return reply({ error: "Email linking is only available for student records." }, 400);
    if (student.auth_user_id) return reply({ error: "This student already has a login account." }, 409);
    const { data: inviteData, error: inviteError } = await adminClient.auth.admin.inviteUserByEmail(email, {
      data: { full_name: student.full_name, role: "student" },
    });
    if (inviteError || !inviteData.user) return reply({ error: inviteError?.message || "The student invitation could not be created." }, 400);
    const { error: updateError } = await adminClient.from("school_profiles").update({
      auth_user_id: inviteData.user.id, email,
    }).eq("id", profileId).is("auth_user_id", null);
    if (updateError) {
      await adminClient.auth.admin.deleteUser(inviteData.user.id);
      return reply({ error: "Invitation rolled back because the student record could not be linked: " + updateError.message }, 500);
    }
    return reply({ success: true, message: "Email saved and invitation sent.", account: { full_name: student.full_name, email, class_name: student.class_name, role: "student" } }, 201);
  }

  const fullName = typeof body.full_name === "string" ? body.full_name.trim() : "";
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const className = typeof body.class_name === "string" ? body.class_name.trim() : "";
  const role = body.role === "teacher" ? "teacher" : "student";
  if (fullName.length < 2 || fullName.length > 120) return reply({ error: "Enter a name between 2 and 120 characters." }, 400);
  if (!validEmail(email)) return reply({ error: "Enter a valid email address." }, 400);
  if (!allowedClasses.includes(className)) return reply({ error: "Choose a valid class." }, 400);

  const { data: inviteData, error: inviteError } = await adminClient.auth.admin.inviteUserByEmail(email, {
    data: { full_name: fullName, role },
  });
  if (inviteError || !inviteData.user) return reply({ error: inviteError?.message || "The invitation could not be created." }, 400);
  const { error: insertError } = await adminClient.from("school_profiles").insert({
    auth_user_id: inviteData.user.id, full_name: fullName, email, role, class_name: className,
  });
  if (insertError) {
    await adminClient.auth.admin.deleteUser(inviteData.user.id);
    return reply({ error: "Invitation was rolled back because the school profile could not be saved. Check for an existing profile and try again." }, 500);
  }
  return reply({ success: true, message: role === "teacher" ? "Teacher invitation sent." : "Student invitation sent.", account: { full_name: fullName, email, class_name: className, role } }, 201);
});
