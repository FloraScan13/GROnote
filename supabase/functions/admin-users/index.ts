import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return reply({ error: "Method not allowed" }, 405);
  const url = Deno.env.get("SUPABASE_URL")!;
  const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
  const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!service) return reply({ error: "Server admin configuration is missing" }, 500);

  const authHeader = req.headers.get("Authorization") || "";
  const trimmedHeader = authHeader.trim();
  const token = trimmedHeader.toLowerCase().startsWith("bearer ")
    ? trimmedHeader.slice(7).trim()
    : trimmedHeader;
  if (!token) return reply({ error: "Authentication required" }, 401);

  const caller = createClient(url, anon, { global: { headers: { Authorization: `Bearer ${token}` } } });
  const { data: { user }, error: authError } = await caller.auth.getUser(token);
  if (authError || !user) return reply({ error: "Invalid session" }, 401);
  if (user.app_metadata?.role !== "admin") return reply({ error: "Administrator access required" }, 403);

  const admin = createClient(url, service, { auth: { autoRefreshToken: false, persistSession: false } });
  try {
    const body = await req.json();
    const action = body?.action;

    if (action === "list") {
      const allUsers = [];
      let page = 1;
      while (true) {
        const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 200 });
        if (error) throw error;
        allUsers.push(...data.users);
        if (data.users.length < 200) break;
        page += 1;
      }
      return reply({ users: allUsers.map(u => ({
        id: u.id,
        email: u.email,
        username: u.user_metadata?.username || "",
        created_at: u.created_at,
        last_sign_in_at: u.last_sign_in_at,
        email_confirmed_at: u.email_confirmed_at,
        registration_pending: !u.email_confirmed_at || !String(u.user_metadata?.username || "").trim(),
        disabled: !!u.banned_until && new Date(u.banned_until) > new Date(),
        role: u.app_metadata?.role === "admin" ? "admin" : "user"
      })) });
    }

    if (action === "invite") {
      const email = String(body.email || "").trim().toLowerCase();
      const name = String(body.name || "").trim().split(" ").filter(Boolean).join(" ");
      if (!name || name.length > 80) return reply({ error: "Enter the gardener's name (up to 80 characters)" }, 400);
      const at = email.indexOf("@");
      if (at < 1 || at !== email.lastIndexOf("@") || email.indexOf(".", at) < at + 2 || email.endsWith(".")) {
        return reply({ error: "Enter a valid email address" }, 400);
      }
      const requestOrigin = req.headers.get("origin");
      const requestedRedirect = String(body.redirectTo || "");
      if (!requestOrigin || !requestedRedirect) return reply({ error: "The app invitation return address is missing" }, 400);
      let redirectTo: string;
      try {
        const appOrigin = new URL(requestOrigin).origin;
        const target = new URL(requestedRedirect);
        if (target.origin !== appOrigin || target.searchParams.get("invite") !== "1") {
          return reply({ error: "Invalid invitation return address" }, 400);
        }
        redirectTo = target.toString();
      } catch {
        return reply({ error: "Invalid invitation return address" }, 400);
      }
      const { data, error } = await admin.auth.admin.inviteUserByEmail(email, {
        redirectTo,
        data: { name, full_name: name }
      });
      if (error) throw error;
      return reply({ invited: true, user: { id: data.user.id, email: data.user.email } });
    }

    if (action === "disable" || action === "enable") {
      const id = String(body.user_id || "");
      if (!id || id === user.id) return reply({ error: "You cannot change your own account status" }, 400);
      const { data: target, error: getError } = await admin.auth.admin.getUserById(id);
      if (getError || !target.user) return reply({ error: "User not found" }, 404);
      if (target.user.app_metadata?.role === "admin") return reply({ error: "Administrator accounts cannot be disabled here" }, 403);
      const { error } = await admin.auth.admin.updateUserById(id, {
        ban_duration: action === "disable" ? "876000h" : "none"
      });
      if (error) throw error;
      return reply({ updated: true });
    }

    return reply({ error: "Unknown action" }, 400);
  } catch (error) {
    return reply({ error: error instanceof Error ? error.message : "Request failed" }, 400);
  }
});
