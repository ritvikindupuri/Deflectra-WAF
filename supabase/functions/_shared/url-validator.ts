/**
 * URL validation utilities to prevent SSRF attacks
 */

const BLOCKED_IP_RANGES = [
  // Private IPv4 ranges
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  // Loopback
  /^127\./,
  /^::1$/,
  /^localhost$/i,
  // Link-local
  /^169\.254\./,
  /^fe80:/i,
  // Cloud metadata endpoints
  /^169\.254\.169\.254$/, // AWS, Azure, GCP
  /^metadata\.google\.internal$/i,
  /^100\.(6[4-9]|[7-9]\d|1[0-2]\d)\./, // AWS ECS/Fargate metadata
];

/**
 * Validates a URL to prevent SSRF attacks.
 * - Must be HTTPS only
 * - Blocks private IPs, loopback, link-local, and cloud metadata endpoints
 * - Validates hostname format
 */
export function validateUrl(urlString: string): { valid: boolean; error?: string; url?: URL } {
  let url: URL;
  
  try {
    url = new URL(urlString);
  } catch {
    return { valid: false, error: "Invalid URL format" };
  }

  // Only allow HTTPS
  if (url.protocol !== "https:") {
    return { valid: false, error: "Only HTTPS URLs are allowed" };
  }

  // Check hostname
  const hostname = url.hostname.toLowerCase();

  // Block obvious localhost/loopback patterns
  if (hostname === "localhost" || hostname === "::1" || hostname.startsWith("127.")) {
    return { valid: false, error: "Localhost and loopback addresses are not allowed" };
  }

  // Block link-local addresses
  if (hostname.startsWith("169.254.") || hostname.startsWith("fe80:")) {
    return { valid: false, error: "Link-local addresses are not allowed" };
  }

  // Block cloud metadata endpoints
  if (hostname === "169.254.169.254" || hostname === "metadata.google.internal") {
    return { valid: false, error: "Cloud metadata endpoints are not allowed" };
  }

  // Block private IP ranges (IPv4 patterns)
  if (/^10\./.test(hostname)) {
    return { valid: false, error: "Private IP addresses are not allowed" };
  }
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) {
    return { valid: false, error: "Private IP addresses are not allowed" };
  }
  if (/^192\.168\./.test(hostname)) {
    return { valid: false, error: "Private IP addresses are not allowed" };
  }

  // Block AWS ECS/Fargate metadata range
  if (/^100\.(6[4-9]|[7-9]\d|1[0-2]\d)\./.test(hostname)) {
    return { valid: false, error: "Private IP addresses are not allowed" };
  }

  // Additional safety: block IPv6 private/link-local patterns
  if (hostname.startsWith("fc") || hostname.startsWith("fd")) {
    return { valid: false, error: "Private IPv6 addresses are not allowed" };
  }

  return { valid: true, url };
}

/**
 * Safely fetches a URL with SSRF protection.
 * - Validates URL before fetching
 * - Follows redirects (fetch does this by default)
 * - Note: This cannot fully prevent DNS rebinding or redirect-based SSRF,
 *   but it covers common attack vectors.
 */
export async function safeFetch(
  urlString: string,
  options?: RequestInit
): Promise<{ ok: boolean; response?: Response; error?: string }> {
  const validation = validateUrl(urlString);
  if (!validation.valid) {
    return { ok: false, error: validation.error };
  }

  try {
    const response = await fetch(urlString, {
      ...options,
      redirect: "follow",
    });

    // After redirect, check final URL
    const finalUrl = response.url;
    if (finalUrl !== urlString) {
      const finalValidation = validateUrl(finalUrl);
      if (!finalValidation.valid) {
        return { ok: false, error: `Redirect to forbidden URL: ${finalValidation.error}` };
      }
    }

    return { ok: true, response };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "Fetch failed" };
  }
}
