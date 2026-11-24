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
  if (!service) return reply({ error: "Password reset service is not configured" }, 500);

  try {
    const body = await req.json();
    const usernameKey = String(body?.username || "").trim().toLowerCase();
    const requestedRedirect = String(body?.redirectTo || "");
    const requestOrigin = req.headers.get("origin");
    if (!usernameKey || usernameKey.length > 80) return reply({ error: "Enter a valid username" }, 400);
    if (!requestOrigin || !requestedRedirect) return reply({ error: "The password reset return address is missing" }, 400);

    let redirectTo: string;
    try {
      const origin = new URL(requestOrigin).origin;
      const target = new URL(requestedRedirect);
      if (target.origin !== origin || target.searchParams.get("password-recovery") !== "1") {
        return reply({ error: "Invalid password reset return address" }, 400);
      }
      redirectTo = target.toString();
    } catch {
      return reply({ error: "Invalid password reset return address" }, 400);
    }

    const admin = createClient(url, service, { auth: { autoRefreshToken: false, persistSession: false } });
    const { data: usernameRow, error: lookupError } = await admin
      .from("gronote_usernames")
      .select("user_id")
      .eq("username_key", usernameKey)
      .maybeSingle();
    if (lookupError) throw lookupError;

    if (usernameRow?.user_id) {
      const { data: userData, error: userError } = await admin.auth.admin.getUserById(usernameRow.user_id);
      if (userError) throw userError;
      const email = userData.user?.email;
      if (email) {
        const publicClient = createClient(url, anon, { auth: { autoRefreshToken: false, persistSession: false } });
        const { error } = await publicClient.auth.resetPasswordForEmail(email, { redirectTo });
        if (error) throw error;
      }
    }

    // Keep the response identical whether or not the username exists.
    return reply({ requested: true });
  } catch (error) {
    console.error("Username password reset failed:", error);
    return reply({ error: error instanceof Error ? error.message : "Password reset request failed" }, 400);
  }
});
