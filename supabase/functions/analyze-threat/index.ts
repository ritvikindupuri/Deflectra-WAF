import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY not configured");

    const authHeader = req.headers.get("Authorization");
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");

    if (!supabaseUrl || !supabaseKey || !anonKey) {
      console.error("Missing env vars:", { url: !!supabaseUrl, key: !!supabaseKey, anon: !!anonKey });
      return new Response(JSON.stringify({ error: "Server configuration error" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabase = createClient(supabaseUrl, supabaseKey);

    // Get user from token
    let userId: string | null = null;
    if (authHeader) {
      const anonClient = createClient(supabaseUrl, anonKey);
      const { data: { user } } = await anonClient.auth.getUser(authHeader.replace("Bearer ", ""));
      userId = user?.id || null;
    }

    if (!userId) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const body = await req.json();
    const { request_data } = body;

    if (!request_data) {
      return new Response(JSON.stringify({ error: "request_data is required" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Use Lovable AI (Gemini) to analyze the request for threats
    const aiResponse = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3.1-pro-preview",
        messages: [
          {
            role: "system",
            content: `You are DEFLECTRA, an AI-powered Web Application Firewall threat analyzer. 
Analyze incoming HTTP requests for security threats. You must respond with a tool call.

Threat categories you detect:
- SQL Injection (sqli)
- Cross-Site Scripting (xss) 
- Command Injection (rce)
- Path Traversal (lfi)
- Bot/Crawler abuse (bot)
- Rate limit abuse (rate_abuse)
- Credential stuffing (credential_stuffing)
- API abuse (api_abuse)
- CSRF attempts (csrf)
- Malformed requests (malformed)

Severity levels: critical, high, medium, low
Actions: blocked, challenged, logged, allowed

Be thorough. If a request looks clean, mark it as severity:low action:allowed.
If it contains any suspicious patterns, classify appropriately.`
          },
          {
            role: "user",
            content: `Analyze this HTTP request for security threats:\n\n${JSON.stringify(request_data, null, 2)}`
          }
        ],
        tools: [
          {
            type: "function",
            function: {
              name: "classify_threat",
              description: "Classify the security threat level of an HTTP request",
              parameters: {
                type: "object",
                properties: {
                  is_threat: { type: "boolean", description: "Whether this request is a threat" },
                  threat_type: { type: "string", description: "Category of threat detected" },
                  severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
                  action: { type: "string", enum: ["blocked", "challenged", "logged", "allowed"] },
                  confidence: { type: "number", description: "Confidence score 0-100" },
                  explanation: { type: "string", description: "Brief explanation of the analysis" },
                  indicators: {
                    type: "array",
                    items: { type: "string" },
                    description: "Specific threat indicators found"
                  }
                },
                required: ["is_threat", "threat_type", "severity", "action", "confidence", "explanation", "indicators"],
                additionalProperties: false
              }
            }
          }
        ],
        tool_choice: { type: "function", function: { name: "classify_threat" } },
      }),
    });

    if (!aiResponse.ok) {
      const status = aiResponse.status;
      if (status === 429) {
        return new Response(JSON.stringify({ error: "AI rate limit exceeded. Try again shortly." }), {
          status: 429,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (status === 402) {
        return new Response(JSON.stringify({ error: "AI credits exhausted. Please add funds." }), {
          status: 402,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const errText = await aiResponse.text();
      console.error("AI error:", status, errText);
      throw new Error("AI analysis failed");
    }

    const aiResult = await aiResponse.json();
    const toolCall = aiResult.choices?.[0]?.message?.tool_calls?.[0];
    
    if (!toolCall) throw new Error("AI did not return threat classification");

    const analysis = JSON.parse(toolCall.function.arguments);

    // Log the threat to the database
    if (analysis.is_threat) {
      // Real geo-IP lookup
      let geoData = { lat: null as number | null, lng: null as number | null, country: null as string | null };
      const ip = request_data.ip || "unknown";
      if (ip && ip !== "unknown" && ip !== "127.0.0.1") {
        try {
          const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,lat,lon`, { signal: AbortSignal.timeout(3000) });
          if (geoRes.ok) {
            const geo = await geoRes.json();
            if (geo.status === "success") {
              geoData = { lat: geo.lat, lng: geo.lon, country: geo.country };
            }
          }
        } catch { /* geo lookup failed, continue */ }
      }

      await supabase.from("threat_logs").insert({
        user_id: userId,
        source_ip: ip,
        source_country: geoData.country,
        source_lat: geoData.lat,
        source_lng: geoData.lng,
        threat_type: analysis.threat_type,
        severity: analysis.severity,
        action_taken: analysis.action,
        request_path: request_data.path || request_data.url || null,
        request_method: request_data.method || "GET",
        user_agent: request_data.user_agent || null,
        details: {
          confidence: analysis.confidence,
          explanation: analysis.explanation,
          indicators: analysis.indicators,
          raw_request: request_data,
        },
      });
    }

    return new Response(JSON.stringify({
      analysis,
      logged: analysis.is_threat,
      model: "google/gemini-3.1-pro-preview",
      engine: "DEFLECTRA AI v3.1 Pro",
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (e) {
    console.error("analyze-threat error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
