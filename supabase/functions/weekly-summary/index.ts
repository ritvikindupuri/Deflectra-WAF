import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, serviceKey);

    // Get all users with email alerts configured
    const { data: settings } = await supabase
      .from("waf_settings")
      .select("*")
      .not("alert_email", "is", null)
      .not("resend_api_key", "is", null);

    if (!settings || settings.length === 0) {
      return new Response(JSON.stringify({ message: "No users with email alerts configured" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const results: any[] = [];

    for (const userSettings of settings) {
      try {
        // Get threat stats for the past week
        const { data: threats, count: totalThreats } = await supabase
          .from("threat_logs")
          .select("*", { count: "exact" })
          .eq("user_id", userSettings.user_id)
          .gte("created_at", oneWeekAgo);

        const threatList = threats || [];
        const blocked = threatList.filter(t => t.action_taken === "blocked").length;
        const critical = threatList.filter(t => t.severity === "critical").length;
        const high = threatList.filter(t => t.severity === "high").length;
        const medium = threatList.filter(t => t.severity === "medium").length;
        const low = threatList.filter(t => t.severity === "low").length;

        // Group by threat type
        const typeMap: Record<string, number> = {};
        for (const t of threatList) {
          typeMap[t.threat_type] = (typeMap[t.threat_type] || 0) + 1;
        }
        const topTypes = Object.entries(typeMap)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5);

        // Top source IPs
        const ipMap: Record<string, number> = {};
        for (const t of threatList) {
          ipMap[t.source_ip] = (ipMap[t.source_ip] || 0) + 1;
        }
        const topIPs = Object.entries(ipMap)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5);

        // Get protected sites count
        const { count: siteCount } = await supabase
          .from("protected_sites")
          .select("*", { count: "exact", head: true })
          .eq("user_id", userSettings.user_id);

        const weekStart = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric" });
        const weekEnd = new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });

        const typeRows = topTypes.map(([type, count]) =>
          `<tr><td style="padding:4px 12px 4px 0;color:#e2e8f0;font-family:monospace;font-size:13px;">${type}</td><td style="padding:4px 0;color:#94a3b8;font-size:13px;">${count} events</td></tr>`
        ).join("") || '<tr><td style="padding:4px 0;color:#4ade80;font-size:13px;">No threats detected 🎉</td></tr>';

        const ipRows = topIPs.map(([ip, count]) =>
          `<tr><td style="padding:4px 12px 4px 0;color:#e2e8f0;font-family:monospace;font-size:13px;">${ip}</td><td style="padding:4px 0;color:#94a3b8;font-size:13px;">${count} attempts</td></tr>`
        ).join("") || '<tr><td style="padding:4px 0;color:#94a3b8;font-size:13px;">None</td></tr>';

        const emailHtml = `
          <div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;padding:24px;">
            <div style="background:#0a0e1a;border-radius:12px;padding:28px;color:#e2e8f0;">
              <h2 style="margin:0 0 4px;color:#06b6d4;">📊 Deflectra WAF — Weekly Summary</h2>
              <p style="margin:0 0 24px;color:#64748b;font-size:13px;">${weekStart} — ${weekEnd}</p>

              <div style="display:flex;gap:12px;margin-bottom:24px;">
                <div style="flex:1;background:#1e293b;border-radius:8px;padding:16px;text-align:center;">
                  <div style="font-size:28px;font-weight:700;color:#06b6d4;">${totalThreats || 0}</div>
                  <div style="font-size:11px;color:#64748b;margin-top:4px;">Total Threats</div>
                </div>
                <div style="flex:1;background:#1e293b;border-radius:8px;padding:16px;text-align:center;">
                  <div style="font-size:28px;font-weight:700;color:#f87171;">${blocked}</div>
                  <div style="font-size:11px;color:#64748b;margin-top:4px;">Blocked</div>
                </div>
                <div style="flex:1;background:#1e293b;border-radius:8px;padding:16px;text-align:center;">
                  <div style="font-size:28px;font-weight:700;color:#4ade80;">${siteCount || 0}</div>
                  <div style="font-size:11px;color:#64748b;margin-top:4px;">Sites Protected</div>
                </div>
              </div>

              <div style="margin-bottom:20px;">
                <h3 style="margin:0 0 8px;font-size:14px;color:#94a3b8;">Severity Breakdown</h3>
                <div style="display:flex;gap:8px;">
                  <span style="padding:4px 10px;border-radius:6px;font-size:12px;background:rgba(239,68,68,.15);color:#f87171;">${critical} Critical</span>
                  <span style="padding:4px 10px;border-radius:6px;font-size:12px;background:rgba(249,115,22,.15);color:#fb923c;">${high} High</span>
                  <span style="padding:4px 10px;border-radius:6px;font-size:12px;background:rgba(234,179,8,.15);color:#facc15;">${medium} Medium</span>
                  <span style="padding:4px 10px;border-radius:6px;font-size:12px;background:rgba(34,197,94,.15);color:#4ade80;">${low} Low</span>
                </div>
              </div>

              <div style="margin-bottom:20px;">
                <h3 style="margin:0 0 8px;font-size:14px;color:#94a3b8;">Top Threat Types</h3>
                <table style="width:100%;">${typeRows}</table>
              </div>

              <div>
                <h3 style="margin:0 0 8px;font-size:14px;color:#94a3b8;">Top Attacker IPs</h3>
                <table style="width:100%;">${ipRows}</table>
              </div>
            </div>
            <p style="margin:16px 0 0;font-size:11px;color:#6b7280;text-align:center;">Deflectra — Adaptive Web Shield</p>
          </div>`;

        const emailRes = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${userSettings.resend_api_key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            from: "Deflectra WAF <onboarding@resend.dev>",
            to: [userSettings.alert_email],
            subject: `📊 Deflectra Weekly Report — ${totalThreats || 0} threats detected (${weekStart} – ${weekEnd})`,
            html: emailHtml,
          }),
        });

        const emailData = await emailRes.json();
        results.push({ user_id: userSettings.user_id, success: emailRes.ok, data: emailData });
      } catch (userErr) {
        console.error(`Failed for user ${userSettings.user_id}:`, userErr);
        results.push({ user_id: userSettings.user_id, success: false, error: String(userErr) });
      }
    }

    return new Response(JSON.stringify({ sent: results.length, results }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("weekly-summary error:", error);
    return new Response(JSON.stringify({ error: error instanceof Error ? error.message : "Unknown error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
