import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

/**
 * Fetches the target site and extracts technical intelligence for WAF auto-setup.
 * 
 * Performs a REAL HTTP crawl of the target site to discover:
 * - Technology stack (React, Vue, Next.js, Supabase, WordPress, etc.)
 * - API endpoints (from script sources, meta tags, inline scripts)
 * - Authentication patterns
 * - Third-party integrations
 * - Form actions and link structure
 * 
 * This data is passed to Gemini 3 Flash so the AI generates rules
 * based on ACTUAL site content, not generic guesses from the URL alone.
 * 
 * @param siteUrl - The URL to analyze
 * @returns Object containing extracted site intelligence
 */
async function fetchSiteIntelligence(siteUrl: string): Promise<{
  html: string;
  technologies: string[];
  apiEndpoints: string[];
  metaTags: Record<string, string>;
  scriptSources: string[];
  linkHrefs: string[];
  formActions: string[];
  rawInlineScripts: string[];
}> {
  console.log(`[Site Crawler] Fetching: ${siteUrl}`);

  const result = {
    html: "",
    technologies: [] as string[],
    apiEndpoints: [] as string[],
    metaTags: {} as Record<string, string>,
    scriptSources: [] as string[],
    linkHrefs: [] as string[],
    formActions: [] as string[],
    rawInlineScripts: [] as string[],
  };

  try {
    const response = await fetch(siteUrl, {
      headers: {
        "User-Agent": "Deflectra-WAF-Crawler/1.0 (Security Analysis)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      redirect: "follow",
    });

    if (!response.ok) {
      console.warn(`[Site Crawler] HTTP ${response.status} for ${siteUrl}`);
      return result;
    }

    const html = await response.text();
    result.html = html.substring(0, 50000); // Limit to 50KB for LLM context

    // Extract meta tags
    const metaRegex = /<meta\s+(?:[^>]*?\s)?(?:name|property)=["']([^"']+)["'][^>]*?\scontent=["']([^"']+)["'][^>]*>/gi;
    let metaMatch;
    while ((metaMatch = metaRegex.exec(html)) !== null) {
      result.metaTags[metaMatch[1]] = metaMatch[2];
    }

    // Extract script sources
    const scriptSrcRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    let scriptMatch;
    while ((scriptMatch = scriptSrcRegex.exec(html)) !== null) {
      result.scriptSources.push(scriptMatch[1]);
    }

    // Extract inline scripts (limited)
    const inlineScriptRegex = /<script[^>]*>([^<]{10,2000})<\/script>/gi;
    let inlineMatch;
    while ((inlineMatch = inlineScriptRegex.exec(html)) !== null && result.rawInlineScripts.length < 5) {
      result.rawInlineScripts.push(inlineMatch[1].substring(0, 500));
    }

    // Extract link hrefs
    const linkRegex = /<a[^>]+href=["']([^"'#][^"']*)["']/gi;
    let linkMatch;
    while ((linkMatch = linkRegex.exec(html)) !== null && result.linkHrefs.length < 50) {
      result.linkHrefs.push(linkMatch[1]);
    }

    // Extract form actions
    const formRegex = /<form[^>]+action=["']([^"']+)["']/gi;
    let formMatch;
    while ((formMatch = formRegex.exec(html)) !== null) {
      result.formActions.push(formMatch[1]);
    }

    // Technology detection — 25+ frameworks, hosting, databases, etc.
    const techPatterns: [RegExp, string][] = [
      [/react/i, "React"],
      [/vue\.?js|vue@/i, "Vue.js"],
      [/angular/i, "Angular"],
      [/next\.?js|_next\//i, "Next.js"],
      [/nuxt/i, "Nuxt.js"],
      [/svelte/i, "Svelte"],
      [/supabase/i, "Supabase"],
      [/firebase/i, "Firebase"],
      [/vercel/i, "Vercel"],
      [/netlify/i, "Netlify"],
      [/cloudflare/i, "Cloudflare"],
      [/wordpress|wp-content/i, "WordPress"],
      [/shopify/i, "Shopify"],
      [/stripe/i, "Stripe"],
      [/auth0/i, "Auth0"],
      [/clerk/i, "Clerk"],
      [/tailwind/i, "Tailwind CSS"],
      [/bootstrap/i, "Bootstrap"],
      [/graphql/i, "GraphQL"],
      [/trpc/i, "tRPC"],
      [/prisma/i, "Prisma"],
      [/mongodb|mongo/i, "MongoDB"],
      [/postgresql|postgres/i, "PostgreSQL"],
      [/aws|amazonaws/i, "AWS"],
      [/google-analytics|gtag/i, "Google Analytics"],
      [/sentry/i, "Sentry"],
      [/datadog/i, "Datadog"],
    ];

    const htmlLower = html.toLowerCase();
    for (const [pattern, tech] of techPatterns) {
      if (pattern.test(htmlLower) || result.scriptSources.some(s => pattern.test(s))) {
        result.technologies.push(tech);
      }
    }

    // API endpoint discovery
    const apiPatterns = [
      /\/api\/[a-z0-9\/_-]+/gi,
      /\/functions\/v1\/[a-z0-9\/_-]+/gi,
      /\/rest\/v1\/[a-z0-9\/_-]+/gi,
      /\/graphql/gi,
      /\/v[0-9]+\/[a-z0-9\/_-]+/gi,
      /\/auth\/[a-z0-9\/_-]+/gi,
    ];

    for (const pattern of apiPatterns) {
      const matches = html.match(pattern);
      if (matches) {
        result.apiEndpoints.push(...matches);
      }
    }

    // Deduplicate
    result.apiEndpoints = [...new Set(result.apiEndpoints)];
    result.technologies = [...new Set(result.technologies)];

    console.log(`[Site Crawler] Discovered: ${result.technologies.length} techs, ${result.apiEndpoints.length} endpoints, ${result.scriptSources.length} scripts, ${result.formActions.length} forms`);
  } catch (error) {
    console.error(`[Site Crawler] Error fetching ${siteUrl}:`, error);
  }

  return result;
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY not configured");

    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;

    // Use the user's auth token so RLS applies correctly
    const supabase = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    // Verify user
    const token = authHeader.replace("Bearer ", "");
    const { data: claimsData, error: claimsError } = await supabase.auth.getClaims(token);
    if (claimsError || !claimsData?.claims) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const userId = claimsData.claims.sub;

    const body = await req.json();
    const { site_url, site_name, site_id, mode } = body;
    // mode: "preview" = crawl + AI config but DON'T write to DB
    //        "activate" = receive config payload and write to DB
    //        undefined/legacy = full auto (crawl + write)

    if (!site_url || !site_id) {
      return new Response(JSON.stringify({ error: "site_url and site_id are required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    console.log(`Auto-setup WAF for site: ${site_name} (${site_url}), user: ${userId}`);

    // ── ACTIVATE MODE: Write previously generated config to DB ──
    if (mode === "activate") {
      const { config } = body;
      if (!config) {
        return new Response(JSON.stringify({ error: "config payload required for activate mode" }), {
          status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      let rulesCreated = 0, rateLimitsCreated = 0, endpointsMonitored = 0;

      if (config.waf_rules?.length > 0) {
        const rules = config.waf_rules.map((r: any) => ({
          user_id: userId, name: r.name, description: r.description,
          pattern: r.pattern, category: r.category, severity: r.severity,
          priority: r.priority, rule_type: "block", enabled: true,
        }));
        const { error } = await supabase.from("waf_rules").insert(rules);
        if (!error) rulesCreated = rules.length;
        else console.error("Failed to insert rules:", error);
      }

      if (config.rate_limits?.length > 0) {
        const rateLimits = config.rate_limits.map((r: any) => ({
          user_id: userId, name: r.name, path: r.path,
          max_requests: r.max_requests, window_seconds: r.window_seconds,
          action: r.action, enabled: true,
        }));
        const { error } = await supabase.from("rate_limit_rules").insert(rateLimits);
        if (!error) rateLimitsCreated = rateLimits.length;
        else console.error("Failed to insert rate limits:", error);
      }

      if (config.api_endpoints?.length > 0) {
        const endpoints = config.api_endpoints.map((e: any) => ({
          user_id: userId, method: e.method, path: e.path,
          schema_validation: e.schema_validation, jwt_inspection: e.jwt_inspection,
          rate_limited: e.rate_limited,
        }));
        const { error } = await supabase.from("api_endpoints").insert(endpoints);
        if (!error) endpointsMonitored = endpoints.length;
        else console.error("Failed to insert endpoints:", error);
      }

      await supabase.from("protected_sites").update({ status: "active" }).eq("id", site_id);

      return new Response(JSON.stringify({
        success: true, activated: true,
        rules_created: rulesCreated,
        rate_limits_created: rateLimitsCreated,
        endpoints_monitored: endpointsMonitored,
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // STEP 1: Real HTTP crawl of the target site
    const intel = await fetchSiteIntelligence(site_url);

    // Build the intelligence summary for the AI
    const intelSummary = `
=== REAL CRAWL DATA FOR ${site_url} ===

DETECTED TECHNOLOGIES: ${intel.technologies.length > 0 ? intel.technologies.join(", ") : "Unable to detect (site may use SSR or be protected)"}

DISCOVERED API ENDPOINTS:
${intel.apiEndpoints.length > 0 ? intel.apiEndpoints.map(e => `  - ${e}`).join("\n") : "  - No API endpoints discovered in HTML"}

META TAGS:
${Object.keys(intel.metaTags).length > 0 ? Object.entries(intel.metaTags).slice(0, 10).map(([k, v]) => `  - ${k}: ${v}`).join("\n") : "  - No meta tags found"}

SCRIPT SOURCES (sample):
${intel.scriptSources.slice(0, 8).map(s => `  - ${s}`).join("\n") || "  - No external scripts"}

FORM ACTIONS:
${intel.formActions.length > 0 ? intel.formActions.map(f => `  - ${f}`).join("\n") : "  - No forms discovered"}

LINK HREFS (sample):
${intel.linkHrefs.slice(0, 15).map(l => `  - ${l}`).join("\n") || "  - No links discovered"}

=== END CRAWL DATA ===
`;

    // STEP 2: Ask AI to generate WAF config using real crawl data
    const aiResponse = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          {
            role: "system",
            content: `You are DEFLECTRA, an AI-powered Web Application Firewall configuration engine.

You have been provided with REAL CRAWL DATA extracted from the target website via an HTTP fetch.
Use this actual data to generate highly specific and accurate security configurations.

CRITICAL INSTRUCTIONS:
1. Base ALL rules, rate limits, and endpoint configs on the REAL crawl data provided
2. If technologies were detected (e.g., React, Supabase, WordPress), generate rules targeting those specific stacks
3. If API endpoints were discovered, protect those EXACT endpoints
4. Do NOT generate generic/placeholder rules — everything must be informed by the crawl data
5. If the crawl returned limited data (e.g., SSR app, bot protection), make reasonable inferences from the detected technologies

You must generate:
1. WAF rules (regex patterns targeting attack vectors specific to the detected tech stack)
2. Rate limiting rules (appropriate limits for discovered endpoints)
3. API endpoints to monitor (based on actually discovered paths)`
          },
          {
            role: "user",
            content: `Generate a complete WAF security configuration for this site based on the real crawl data below:

URL: ${site_url}
Name: ${site_name || 'Unknown'}

${intelSummary}

Use the discovered technologies, endpoints, and patterns above to generate TARGETED security rules.
For example:
- If Supabase was detected, add SQL injection rules targeting Supabase query patterns
- If React was detected, add XSS rules targeting React-specific injection vectors
- If specific API endpoints like /functions/v1/* were found, create rate limits for those exact paths
- If forms were discovered, protect those form action endpoints`
          }
        ],
        tools: [
          {
            type: "function",
            function: {
              name: "configure_waf",
              description: "Configure WAF rules, rate limits, and API monitoring based on real site crawl data",
              parameters: {
                type: "object",
                properties: {
                  app_type: { type: "string", description: "Detected application type based on crawl data" },
                  waf_rules: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        name: { type: "string" },
                        description: { type: "string" },
                        pattern: { type: "string", description: "Regex pattern to match" },
                        category: { type: "string", enum: ["sqli", "xss", "rce", "lfi", "bot", "custom"] },
                        severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
                        priority: { type: "number" }
                      },
                      required: ["name", "description", "pattern", "category", "severity", "priority"],
                      additionalProperties: false
                    }
                  },
                  rate_limits: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        name: { type: "string" },
                        path: { type: "string" },
                        max_requests: { type: "number" },
                        window_seconds: { type: "number" },
                        action: { type: "string", enum: ["block", "challenge", "throttle"] }
                      },
                      required: ["name", "path", "max_requests", "window_seconds", "action"],
                      additionalProperties: false
                    }
                  },
                  api_endpoints: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE", "PATCH"] },
                        path: { type: "string" },
                        schema_validation: { type: "boolean" },
                        jwt_inspection: { type: "boolean" },
                        rate_limited: { type: "boolean" }
                      },
                      required: ["method", "path", "schema_validation", "jwt_inspection", "rate_limited"],
                      additionalProperties: false
                    }
                  }
                },
                required: ["app_type", "waf_rules", "rate_limits", "api_endpoints"],
                additionalProperties: false
              }
            }
          }
        ],
        tool_choice: { type: "function", function: { name: "configure_waf" } },
      }),
    });

    if (!aiResponse.ok) {
      const status = aiResponse.status;
      const errBody = await aiResponse.text().catch(() => "");
      console.error(`AI API error [${status}]: ${errBody}`);
      if (status === 429) {
        return new Response(JSON.stringify({ error: "AI rate limit exceeded. Try again shortly." }), {
          status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (status === 402) {
        return new Response(JSON.stringify({ error: "AI credits exhausted." }), {
          status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      throw new Error(`AI configuration failed [${status}]`);
    }

    const aiResult = await aiResponse.json();
    const toolCall = aiResult.choices?.[0]?.message?.tool_calls?.[0];
    if (!toolCall) throw new Error("AI did not return configuration");

    const config = JSON.parse(toolCall.function.arguments);
    console.log(`AI detected app type: ${config.app_type}, rules: ${config.waf_rules?.length}, rate_limits: ${config.rate_limits?.length}, endpoints: ${config.api_endpoints?.length}`);
    console.log(`Crawl summary: ${intel.technologies.length} techs detected, ${intel.apiEndpoints.length} endpoints discovered`);

    // ── PREVIEW MODE: Return crawl data + config without writing ──
    if (mode === "preview") {
      return new Response(JSON.stringify({
        success: true,
        preview: true,
        app_type: config.app_type,
        config,
        crawl_report: {
          technologies: intel.technologies,
          api_endpoints: intel.apiEndpoints,
          script_sources: intel.scriptSources.slice(0, 15),
          link_hrefs: intel.linkHrefs.slice(0, 20),
          form_actions: intel.formActions,
          meta_tags: intel.metaTags,
          html_snippet: intel.html.substring(0, 3000),
        },
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ── LEGACY MODE: Full auto (crawl + write) ──
    // Insert WAF rules
    if (config.waf_rules?.length > 0) {
      const rules = config.waf_rules.map((r: any) => ({
        user_id: userId,
        name: r.name,
        description: r.description,
        pattern: r.pattern,
        category: r.category,
        severity: r.severity,
        priority: r.priority,
        rule_type: "block",
        enabled: true,
      }));
      const { error: rulesError } = await supabase.from("waf_rules").insert(rules);
      if (rulesError) console.error("Failed to insert rules:", rulesError);
      else console.log(`Inserted ${rules.length} WAF rules`);
    }

    // Insert rate limit rules
    if (config.rate_limits?.length > 0) {
      const rateLimits = config.rate_limits.map((r: any) => ({
        user_id: userId,
        name: r.name,
        path: r.path,
        max_requests: r.max_requests,
        window_seconds: r.window_seconds,
        action: r.action,
        enabled: true,
      }));
      const { error: rlError } = await supabase.from("rate_limit_rules").insert(rateLimits);
      if (rlError) console.error("Failed to insert rate limits:", rlError);
      else console.log(`Inserted ${rateLimits.length} rate limit rules`);
    }

    // Insert API endpoints
    if (config.api_endpoints?.length > 0) {
      const endpoints = config.api_endpoints.map((e: any) => ({
        user_id: userId,
        method: e.method,
        path: e.path,
        schema_validation: e.schema_validation,
        jwt_inspection: e.jwt_inspection,
        rate_limited: e.rate_limited,
      }));
      const { error: epError } = await supabase.from("api_endpoints").insert(endpoints);
      if (epError) console.error("Failed to insert endpoints:", epError);
      else console.log(`Inserted ${endpoints.length} API endpoints`);
    }

    // Mark site as active
    await supabase.from("protected_sites")
      .update({ status: "active" })
      .eq("id", site_id);

    return new Response(JSON.stringify({
      success: true,
      app_type: config.app_type,
      rules_created: config.waf_rules?.length || 0,
      rate_limits_created: config.rate_limits?.length || 0,
      endpoints_monitored: config.api_endpoints?.length || 0,
      discovered: {
        technologies: intel.technologies,
        endpoints: intel.apiEndpoints.slice(0, 10),
      },
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (e) {
    console.error("auto-setup error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
