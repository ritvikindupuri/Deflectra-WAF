import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch } from "../_shared/url-validator.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

/**
 * Fetches the target site and extracts technical intelligence for WAF configuration.
 * 
 * This function performs REAL HTTP crawling of the target site to discover:
 * - Technology stack (React, Vue, Next.js, Supabase, etc.)
 * - API endpoints (from script sources, meta tags, inline scripts)
 * - Authentication patterns
 * - Third-party integrations
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
    const fetchResult = await safeFetch(siteUrl, {
      headers: {
        "User-Agent": "Deflectra-WAF-Crawler/1.0 (Security Analysis)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    if (!fetchResult.ok || !fetchResult.response) {
      console.warn(`[Site Crawler] Failed to fetch ${siteUrl}: ${fetchResult.error}`);
      return result;
    }

    const response = fetchResult.response;

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

    // Technology detection
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

    console.log(`[Site Crawler] Discovered: ${result.technologies.length} techs, ${result.apiEndpoints.length} endpoints`);
  } catch (error) {
    console.error(`[Site Crawler] Error fetching ${siteUrl}:`, error);
  }

  return result;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "Unauthorized: Authentication required" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;

    const supabase = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const token = authHeader.replace("Bearer ", "");
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized: Invalid token" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { site_url, context, field } = await req.json();

    if (!site_url) {
      return new Response(JSON.stringify({ error: "site_url is required" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      return new Response(JSON.stringify({ error: "LOVABLE_API_KEY not configured" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // STEP 1: Actually fetch and analyze the target site
    const siteIntelligence = await fetchSiteIntelligence(site_url);

    // Build the system prompt based on context and field
    const systemPrompt = buildSystemPrompt(context, field);
    const userPrompt = buildUserPrompt(site_url, context, field, siteIntelligence);

    // Define the tool based on context and field
    const tool = buildTool(context, field);

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
        tools: [tool],
        tool_choice: { type: "function", function: { name: tool.function.name } },
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("AI Gateway error:", response.status, errorText);
      return new Response(JSON.stringify({ error: "AI analysis failed" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const data = await response.json();
    const toolCall = data.choices?.[0]?.message?.tool_calls?.[0];
    
    if (!toolCall) {
      return new Response(JSON.stringify({ error: "No response from AI" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const result = JSON.parse(toolCall.function.arguments);

    // Include discovered intelligence in response for transparency
    return new Response(JSON.stringify({ 
      success: true, 
      data: result,
      discovered: {
        technologies: siteIntelligence.technologies,
        endpoints: siteIntelligence.apiEndpoints.slice(0, 10),
      }
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("Error:", error);
    return new Response(JSON.stringify({ error: error.message || "Unknown error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});

function buildSystemPrompt(context: string, field?: string): string {
  const base = `You are a security expert that analyzes REAL crawl data from web applications to generate accurate WAF configurations.

CRITICAL INSTRUCTIONS:
1. You have been provided with ACTUAL data extracted from crawling the target site
2. Use the discovered technologies, endpoints, and patterns to generate highly specific configurations
3. Do NOT make up generic patterns - base everything on the real crawl data provided
4. If the crawl data is limited, make reasonable inferences based on detected technologies

The crawl data includes:
- Detected technology stack (frameworks, hosting, databases)
- Discovered API endpoints
- Meta tags and site configuration
- Script sources and inline scripts
- Form actions and links
`;

  if (field) {
    return base + `\n\nYou are generating ONLY the "${field}" field value. Focus on accuracy for this specific field.`;
  }

  return base;
}

function buildUserPrompt(
  site_url: string, 
  context: string, 
  field: string | undefined,
  intel: Awaited<ReturnType<typeof fetchSiteIntelligence>>
): string {
  const fieldNote = field ? ` Generate ONLY the "${field}" field value.` : "";
  
  // Build the site intelligence summary
  const intelSummary = `
=== REAL CRAWL DATA FOR ${site_url} ===

DETECTED TECHNOLOGIES: ${intel.technologies.length > 0 ? intel.technologies.join(", ") : "Unable to detect (site may use SSR or be protected)"}

DISCOVERED API ENDPOINTS:
${intel.apiEndpoints.length > 0 ? intel.apiEndpoints.map(e => `  - ${e}`).join("\n") : "  - No API endpoints discovered in HTML"}

META TAGS:
${Object.keys(intel.metaTags).length > 0 ? Object.entries(intel.metaTags).slice(0, 10).map(([k, v]) => `  - ${k}: ${v}`).join("\n") : "  - No meta tags found"}

SCRIPT SOURCES (sample):
${intel.scriptSources.slice(0, 5).map(s => `  - ${s}`).join("\n") || "  - No external scripts"}

FORM ACTIONS:
${intel.formActions.length > 0 ? intel.formActions.map(f => `  - ${f}`).join("\n") : "  - No forms discovered"}

LINK HREFS (sample):
${intel.linkHrefs.slice(0, 10).map(l => `  - ${l}`).join("\n") || "  - No links discovered"}

=== END CRAWL DATA ===
`;

  switch (context) {
    case "ai_detection":
      return `${intelSummary}

Based on the REAL crawl data above, generate attack simulation scenarios that would test THIS specific app's defenses.${fieldNote}

For each scenario:
- path: Use ACTUAL endpoint patterns discovered, or patterns typical of the detected technologies
- method: Match the likely HTTP method for that endpoint type
- body: Craft attack payloads targeting schemas the app would expect
- user_agent: Use realistic attacker user agents

IMPORTANT: If Supabase/functions/v1 endpoints were detected, include attacks targeting those. If React was detected, include XSS attacks targeting React patterns.`;

    case "custom_attack":
      return `${intelSummary}

The user wants to simulate a SPECIFIC type of attack: "${field}"

Based on the REAL crawl data above and the user's requested attack type, generate a SINGLE highly realistic attack scenario that:
1. Targets actual endpoints/patterns discovered on THIS specific app
2. Uses the exact attack technique the user described
3. Crafts a convincing, realistic payload that would test the WAF's detection
4. Includes appropriate HTTP method, path, body, and user agent for this attack type

Be creative and realistic. This is for security testing — make the attack scenario as realistic as possible so the WAF can be properly tested.`;

    case "rate_limiting":
      return `${intelSummary}

Based on the REAL crawl data above, generate rate limiting rules that protect THIS specific app's sensitive endpoints.${fieldNote}

For each rule:
- name: Descriptive name for the rule
- path: Use ACTUAL endpoint paths discovered, or typical paths for the detected stack
- max_requests: Appropriate limit based on the endpoint's purpose
- window_seconds: Time window (be stricter for auth endpoints)
- action: block/challenge/throttle based on severity

IMPORTANT: If auth/login endpoints were discovered, apply strict limits. If Supabase functions were detected, protect those.`;

    case "api_shield":
      return `${intelSummary}

Based on the REAL crawl data above, generate API Shield configurations for the endpoints you see.${fieldNote}

For each endpoint:
- method: The HTTP method used (infer from endpoint naming patterns)
- path: The ACTUAL endpoint path from crawl data
- jwt_inspection: Enable for authenticated routes
- schema_validation: Enable for endpoints likely accepting JSON bodies
- rate_limited: Enable for expensive operations

IMPORTANT: Use the discovered API endpoints. If none were found, generate endpoints typical of the detected tech stack.`;

    case "rule_engine":
      return `${intelSummary}

Based on the REAL crawl data above, generate WAF rules targeting vulnerabilities specific to the detected stack.${fieldNote}

For each rule:
- name: Descriptive attack name
- pattern: Regex pattern that catches attacks against the detected stack
- category: sqli/xss/rce/lfi/custom
- severity: Based on potential impact to this specific app
- description: Why this rule matters for this specific app

IMPORTANT: Tailor rules to the detected technologies. React apps need XSS protection. Supabase apps need SQL injection protection. etc.`;

    default:
      return `${intelSummary}\n\nAnalyze the crawl data and generate appropriate security configurations.${fieldNote}`;
  }
}

function buildTool(context: string, field?: string): any {
  // If generating a single field, return a simpler tool
  if (field) {
    return buildFieldTool(context, field);
  }

  // Full form generation tools
  switch (context) {
    case "ai_detection":
      return {
        type: "function",
        function: {
          name: "generate_attack_scenarios",
          description: "Generate attack simulation scenarios based on real crawl data from the target application",
          parameters: {
            type: "object",
            properties: {
              scenarios: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    path: { type: "string", description: "Request path with attack payload" },
                    method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE"] },
                    body: { type: "string", description: "Request body with attack payload" },
                    user_agent: { type: "string", description: "Attacker user agent" },
                  },
                  required: ["path", "method"],
                },
              },
              detected_stack: {
                type: "object",
                properties: {
                  frontend: { type: "string" },
                  backend: { type: "string" },
                  hosting: { type: "string" },
                },
              },
            },
            required: ["scenarios", "detected_stack"],
          },
        },
      };

    case "rate_limiting":
      return {
        type: "function",
        function: {
          name: "generate_rate_limit_rules",
          description: "Generate rate limiting rules based on real crawl data from the target application",
          parameters: {
            type: "object",
            properties: {
              rules: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    path: { type: "string" },
                    max_requests: { type: "number" },
                    window_seconds: { type: "number" },
                    action: { type: "string", enum: ["block", "challenge", "throttle"] },
                  },
                  required: ["name", "path", "max_requests", "window_seconds", "action"],
                },
              },
              detected_endpoints: {
                type: "array",
                items: { type: "string" },
                description: "List of discovered endpoints from crawl",
              },
            },
            required: ["rules", "detected_endpoints"],
          },
        },
      };

    case "api_shield":
      return {
        type: "function",
        function: {
          name: "generate_api_endpoints",
          description: "Generate API Shield endpoint configurations based on real crawl data",
          parameters: {
            type: "object",
            properties: {
              endpoints: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE", "PATCH"] },
                    path: { type: "string" },
                    schema_validation: { type: "boolean" },
                    jwt_inspection: { type: "boolean" },
                    rate_limited: { type: "boolean" },
                  },
                  required: ["method", "path", "schema_validation", "jwt_inspection", "rate_limited"],
                },
              },
              api_type: {
                type: "string",
                enum: ["REST", "GraphQL", "Mixed"],
              },
            },
            required: ["endpoints", "api_type"],
          },
        },
      };

    case "rule_engine":
      return {
        type: "function",
        function: {
          name: "generate_waf_rules",
          description: "Generate WAF rules tailored to the technology stack discovered in crawl data",
          parameters: {
            type: "object",
            properties: {
              rules: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    pattern: { type: "string" },
                    category: { type: "string", enum: ["sqli", "xss", "rce", "lfi", "custom"] },
                    severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
                    rule_type: { type: "string", enum: ["block", "challenge", "log"] },
                    description: { type: "string" },
                  },
                  required: ["name", "pattern", "category", "severity", "rule_type", "description"],
                },
              },
              detected_vulnerabilities: {
                type: "array",
                items: { type: "string" },
                description: "Potential vulnerabilities based on detected stack",
              },
            },
            required: ["rules", "detected_vulnerabilities"],
          },
        },
      };

    case "custom_attack":
      return {
        type: "function",
        function: {
          name: "generate_custom_attack",
          description: "Generate a single realistic attack scenario based on the user's described attack type and real crawl data",
          parameters: {
            type: "object",
            properties: {
              scenario: {
                type: "object",
                properties: {
                  path: { type: "string", description: "Request path with attack payload" },
                  method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE"] },
                  body: { type: "string", description: "Request body with attack payload (empty string if not needed)" },
                  user_agent: { type: "string", description: "Attacker user agent string" },
                  attack_name: { type: "string", description: "Short name for the attack type" },
                  explanation: { type: "string", description: "Brief explanation of what this attack does and why it targets this specific app" },
                },
                required: ["path", "method", "body", "user_agent", "attack_name", "explanation"],
              },
            },
            required: ["scenario"],
          },
        },
      };

    default:
      throw new Error(`Unknown context: ${context}`);
  }
}

function buildFieldTool(context: string, field: string): any {
  // Build a single-field generation tool
  const fieldName = `generate_${field.toLowerCase().replace(/[^a-z0-9]/g, '_')}`;
  
  switch (context) {
    case "custom_attack":
      return {
        type: "function",
        function: {
          name: "generate_custom_attack",
          description: "Generate a single realistic attack scenario based on the user's description and crawl data",
          parameters: {
            type: "object",
            properties: {
              scenario: {
                type: "object",
                properties: {
                  path: { type: "string", description: "Attack request path" },
                  method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE"] },
                  body: { type: "string", description: "Request body with attack payload (empty string if GET)" },
                  user_agent: { type: "string", description: "Attacker user agent string" },
                  attack_name: { type: "string", description: "Short name for this attack" },
                  explanation: { type: "string", description: "Why this attack targets the specific app" },
                },
                required: ["path", "method", "body", "user_agent", "attack_name", "explanation"],
                additionalProperties: false,
              },
            },
            required: ["scenario"],
            additionalProperties: false,
          },
        },
      };

    case "ai_detection":
      if (field === "path") {
        return {
          type: "function",
          function: {
            name: fieldName,
            description: "Generate a realistic attack path based on discovered endpoints from crawl",
            parameters: {
              type: "object",
              properties: {
                value: { type: "string", description: "The attack path (e.g., /api/users?id=1 OR 1=1)" },
                reasoning: { type: "string", description: "Why this path targets the specific app based on crawl data" },
              },
              required: ["value", "reasoning"],
            },
          },
        };
      }
      if (field === "body") {
        return {
          type: "function",
          function: {
            name: fieldName,
            description: "Generate a malicious request body targeting detected technology",
            parameters: {
              type: "object",
              properties: {
                value: { type: "string", description: "JSON body with attack payload" },
                attack_type: { type: "string", description: "Type of attack (SQLi, XSS, etc.)" },
              },
              required: ["value", "attack_type"],
            },
          },
        };
      }
      break;

    case "rate_limiting":
      if (field === "path") {
        return {
          type: "function",
          function: {
            name: fieldName,
            description: "Generate a path pattern for rate limiting based on discovered endpoints",
            parameters: {
              type: "object",
              properties: {
                value: { type: "string", description: "Path pattern (e.g., /api/auth/*)" },
                endpoint_type: { type: "string", description: "Type of endpoint (auth, api, public)" },
              },
              required: ["value", "endpoint_type"],
            },
          },
        };
      }
      if (field === "name") {
        return {
          type: "function",
          function: {
            name: fieldName,
            description: "Generate a descriptive rule name",
            parameters: {
              type: "object",
              properties: {
                value: { type: "string", description: "Descriptive name for the rate limit rule" },
              },
              required: ["value"],
            },
          },
        };
      }
      if (field === "max_requests") {
        return {
          type: "function",
          function: {
            name: fieldName,
            description: "Determine appropriate request limit based on endpoint type",
            parameters: {
              type: "object",
              properties: {
                value: { type: "number", description: "Max requests allowed" },
                reasoning: { type: "string", description: "Why this limit is appropriate" },
              },
              required: ["value", "reasoning"],
            },
          },
        };
      }
      break;

    case "api_shield":
      if (field === "path") {
        return {
          type: "function",
          function: {
            name: fieldName,
            description: "Generate an API endpoint path based on crawl data",
            parameters: {
              type: "object",
              properties: {
                value: { type: "string", description: "API endpoint path" },
                endpoint_purpose: { type: "string", description: "What this endpoint does" },
                requires_auth: { type: "boolean", description: "Whether this endpoint needs authentication" },
              },
              required: ["value", "endpoint_purpose", "requires_auth"],
            },
          },
        };
      }
      if (field === "method") {
        return {
          type: "function",
          function: {
            name: fieldName,
            description: "Determine the HTTP method for an endpoint",
            parameters: {
              type: "object",
              properties: {
                value: { type: "string", enum: ["GET", "POST", "PUT", "DELETE", "PATCH"] },
                reasoning: { type: "string", description: "Why this method is used" },
              },
              required: ["value", "reasoning"],
            },
          },
        };
      }
      break;

    case "rule_engine":
      if (field === "pattern") {
        return {
          type: "function",
          function: {
            name: fieldName,
            description: "Generate a regex pattern for attack detection targeting the detected stack",
            parameters: {
              type: "object",
              properties: {
                value: { type: "string", description: "Regex pattern" },
                targets: { type: "string", description: "What attacks this pattern catches" },
              },
              required: ["value", "targets"],
            },
          },
        };
      }
      if (field === "name") {
        return {
          type: "function",
          function: {
            name: fieldName,
            description: "Generate a descriptive rule name",
            parameters: {
              type: "object",
              properties: {
                value: { type: "string", description: "Rule name" },
              },
              required: ["value"],
            },
          },
        };
      }
      break;
  }

  // Fallback for any other field
  return {
    type: "function",
    function: {
      name: fieldName,
      description: `Generate the ${field} field value based on crawl data`,
      parameters: {
        type: "object",
        properties: {
          value: { type: "string", description: `The ${field} value` },
        },
        required: ["value"],
      },
    },
  };
}
