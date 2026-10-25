/**
 * CORS origin allowlist helper (modeled on Blastline-AI's _shared/security.ts).
 *
 * Allowed origins come from the ALLOWED_ORIGINS env var (comma-separated,
 * exact match only). If unset, defaults to the production site plus localhost
 * dev servers. Wildcards are ignored.
 */
const DEFAULT_ALLOWED_ORIGINS = [
  "https://aiwaf.netlify.app",
  "http://localhost:8080",
  "http://localhost:5173",
  "http://127.0.0.1:8080",
  "http://127.0.0.1:5173",
];

const ALLOWED_HEADERS =
  "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version";

export function getAllowedOrigins(): string[] {
  const env = Deno.env.get("ALLOWED_ORIGINS");
  if (!env) return DEFAULT_ALLOWED_ORIGINS;
  const list = env.split(",").map((o) => o.trim()).filter((o) => o && o !== "*");
  return list.length ? list : DEFAULT_ALLOWED_ORIGINS;
}

export function isOriginAllowed(origin: string | null): boolean {
  return !!origin && getAllowedOrigins().includes(origin);
}

export function getCorsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("origin");
  const headers: Record<string, string> = {
    "Access-Control-Allow-Headers": ALLOWED_HEADERS,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
  if (isOriginAllowed(origin)) headers["Access-Control-Allow-Origin"] = origin!;
  return headers;
}

/** Handle CORS preflight. Returns a Response for OPTIONS, otherwise null. */
export function handleCorsPreflight(req: Request): Response | null {
  if (req.method !== "OPTIONS") return null;
  const origin = req.headers.get("origin");
  if (!isOriginAllowed(origin)) return new Response(null, { status: 403 });
  return new Response(null, { status: 204, headers: getCorsHeaders(req) });
}
