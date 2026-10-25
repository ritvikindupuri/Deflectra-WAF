/**
 * URL validation utilities to prevent SSRF attacks.
 *
 * Defenses:
 *  - https-only
 *  - hostname literal IPs are classified (IPv4, IPv6, IPv4-mapped/compatible IPv6)
 *  - DNS names are resolved (A + AAAA) and rejected if ANY record is non-public
 *  - redirects are followed manually (redirect: "manual"), each hop re-validated,
 *    with a hop cap
 *
 * KNOWN LIMITATION (DNS rebinding / TOCTOU): we resolve the hostname ourselves,
 * then `fetch()` resolves it again. An attacker-controlled DNS server with a
 * very short TTL could answer with a public IP to our check and a private IP to
 * fetch's lookup. Deno's fetch does not let us pin the connection to the
 * pre-resolved IP while keeping TLS SNI/cert validation for the hostname, so
 * this window cannot be fully closed here. Full mitigation requires an egress
 * proxy or network-level egress policy that blocks private ranges.
 */

export const MAX_REDIRECTS = 5;

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
  "metadata",
]);

/** Parse dotted-quad IPv4 into 4 octets, or null. Strict: decimal octets only. */
export function parseIPv4(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

/** Returns true if the IPv4 address is NOT globally routable / safe to fetch. */
export function isBlockedIPv4(ip: string): boolean {
  const o = parseIPv4(ip);
  if (!o) return true; // unparseable => block
  const [a, b, c] = o;
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // 10/8 private
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12 private
  if (a === 192 && b === 168) return true; // 192.168/16 private
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64/10 CGNAT
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0/24 IETF protocol assignments
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18/15 benchmarking
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // 224/4 multicast + 240/4 reserved + broadcast
  return false;
}

/** Expand an IPv6 string into 8 16-bit groups, or null. Handles embedded IPv4. */
export function parseIPv6(input: string): number[] | null {
  let ip = input.toLowerCase();
  const zone = ip.indexOf("%");
  if (zone !== -1) ip = ip.slice(0, zone);
  if (!ip.includes(":")) return null;

  // Embedded dotted IPv4 tail
  let tail: number[] = [];
  const lastColon = ip.lastIndexOf(":");
  const maybeV4 = ip.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    const v4 = parseIPv4(maybeV4);
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    ip = ip.slice(0, lastColon + 1) + "0"; // placeholder, replaced below
    // remove placeholder group; we'll append tail
    ip = ip.slice(0, -1);
    if (ip.endsWith("::")) {
      // fine
    } else if (ip.endsWith(":")) {
      ip = ip.slice(0, -1);
    }
  }

  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const parseGroups = (s: string): number[] | null => {
    if (s === "") return [];
    const gs = s.split(":");
    const res: number[] = [];
    for (const g of gs) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      res.push(parseInt(g, 16));
    }
    return res;
  };
  const head = parseGroups(halves[0]);
  if (!head) return null;
  let groups: number[];
  const needed = 8 - tail.length;
  if (halves.length === 2) {
    const rest = parseGroups(halves[1]);
    if (!rest) return null;
    const fill = needed - head.length - rest.length;
    if (fill < 0) return null;
    groups = [...head, ...new Array(fill).fill(0), ...rest];
  } else {
    groups = head;
    if (groups.length !== needed) return null;
  }
  groups = [...groups, ...tail];
  return groups.length === 8 ? groups : null;
}

/** Returns true if the IPv6 address is NOT globally routable / safe to fetch. */
export function isBlockedIPv6(ip: string): boolean {
  const g = parseIPv6(ip);
  if (!g) return true;
  const allZeroPrefix = (n: number) => g.slice(0, n).every((x) => x === 0);
  // :: unspecified and ::1 loopback
  if (allZeroPrefix(7) && (g[7] === 0 || g[7] === 1)) return true;
  // IPv4-mapped ::ffff:a.b.c.d -> block outright (never needed for outbound fetch)
  if (allZeroPrefix(5) && g[5] === 0xffff) return true;
  // IPv4-compatible (deprecated) ::a.b.c.d
  if (allZeroPrefix(6)) return true;
  // IPv4/IPv6 translation 64:ff9b::/96 -> classify embedded IPv4
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) {
    const v4 = `${g[6] >> 8}.${g[6] & 0xff}.${g[7] >> 8}.${g[7] & 0xff}`;
    return isBlockedIPv4(v4);
  }
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 site-local (deprecated)
  if ((g[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // documentation
  if (g[0] === 0x2002) {
    // 6to4: embedded IPv4 in groups 1-2
    const v4 = `${g[1] >> 8}.${g[1] & 0xff}.${g[2] >> 8}.${g[2] & 0xff}`;
    return isBlockedIPv4(v4);
  }
  return false;
}

/** Strip surrounding brackets from URL.hostname for IPv6 literals. */
export function normalizeHostname(hostname: string): string {
  let h = hostname.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.endsWith(".")) h = h.slice(0, -1); // trailing-dot FQDN
  return h;
}

/** Classify an IP literal. Returns null if not an IP literal. */
export function isBlockedIP(ip: string): boolean | null {
  if (parseIPv4(ip)) return isBlockedIPv4(ip);
  if (ip.includes(":")) return isBlockedIPv6(ip);
  return null;
}

/**
 * Synchronous structural validation (no DNS). https-only, no credentials,
 * hostname not a blocked name or blocked IP literal.
 */
export function validateUrl(urlString: string): { valid: boolean; error?: string; url?: URL } {
  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    return { valid: false, error: "Invalid URL format" };
  }
  if (url.protocol !== "https:") {
    return { valid: false, error: "Only HTTPS URLs are allowed" };
  }
  if (url.username || url.password) {
    return { valid: false, error: "Credentials in URL are not allowed" };
  }
  const host = normalizeHostname(url.hostname);
  if (!host) return { valid: false, error: "Missing hostname" };
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith(".localhost") || host.endsWith(".internal")) {
    return { valid: false, error: "Hostname is not allowed" };
  }
  const literal = isBlockedIP(host);
  if (literal === true) {
    return { valid: false, error: "Private, loopback, link-local or reserved addresses are not allowed" };
  }
  // Non-dotted numeric hosts (e.g. "2130706433") are normalised by WHATWG URL
  // to dotted IPv4, so they are covered above.
  return { valid: true, url };
}

type Resolver = (host: string, type: "A" | "AAAA") => Promise<string[]>;
const defaultResolver: Resolver = (host, type) => Deno.resolveDns(host, type);

/**
 * Full validation: structural checks + DNS resolution of A and AAAA records.
 * Rejects if resolution yields no records or ANY record is non-public.
 */
export async function validateUrlWithDns(
  urlString: string,
  resolver: Resolver = defaultResolver,
): Promise<{ valid: boolean; error?: string; url?: URL }> {
  const basic = validateUrl(urlString);
  if (!basic.valid || !basic.url) return basic;
  const host = normalizeHostname(basic.url.hostname);
  if (isBlockedIP(host) === false) return basic; // public IP literal, no DNS needed

  const records: string[] = [];
  for (const type of ["A", "AAAA"] as const) {
    try {
      records.push(...(await resolver(host, type)));
    } catch {
      // NXDOMAIN / no records of this type: ignore, checked below
    }
  }
  if (records.length === 0) {
    return { valid: false, error: "Hostname did not resolve" };
  }
  for (const r of records) {
    if (isBlockedIP(r) !== false) {
      return { valid: false, error: "Hostname resolves to a private or reserved address" };
    }
  }
  return basic;
}

/**
 * Safely fetches a URL with SSRF protection.
 * - https-only, DNS-validated on every hop
 * - redirect: "manual"; follows at most MAX_REDIRECTS hops, re-validating each
 * - 303 (and 301/302 for non-GET/HEAD) downgrade to GET without body, per fetch spec
 * See the DNS-rebinding limitation in the file header.
 */
export async function safeFetch(
  urlString: string,
  options?: RequestInit,
  resolver: Resolver = defaultResolver,
): Promise<{ ok: boolean; response?: Response; error?: string }> {
  let current = urlString;
  let init: RequestInit = { ...(options || {}) };

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const v = await validateUrlWithDns(current, resolver);
    if (!v.valid) {
      return { ok: false, error: hop === 0 ? v.error : `Redirect to forbidden URL: ${v.error}` };
    }
    let response: Response;
    try {
      response = await fetch(current, { ...init, redirect: "manual" });
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : "Fetch failed" };
    }

    if (response.status >= 300 && response.status < 400 && response.headers.has("location")) {
      const location = response.headers.get("location")!;
      try { await response.body?.cancel(); } catch { /* ignore */ }
      let next: string;
      try {
        next = new URL(location, current).toString();
      } catch {
        return { ok: false, error: "Invalid redirect location" };
      }
      const method = (init.method || "GET").toUpperCase();
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && method !== "GET" && method !== "HEAD")) {
        const { body: _b, ...rest } = init;
        const headers = new Headers(rest.headers);
        headers.delete("content-type");
        headers.delete("content-length");
        init = { ...rest, method: method === "HEAD" ? "HEAD" : "GET", headers };
      }
      // Drop credentials on cross-origin redirect
      if (new URL(next).origin !== new URL(current).origin) {
        const headers = new Headers(init.headers);
        headers.delete("authorization");
        headers.delete("cookie");
        init = { ...init, headers };
      }
      current = next;
      continue;
    }
    return { ok: true, response };
  }
  return { ok: false, error: `Too many redirects (max ${MAX_REDIRECTS})` };
}
