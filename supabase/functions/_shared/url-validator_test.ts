import { assertEquals } from "https://deno.land/std@0.168.0/testing/asserts.ts";
import {
  isBlockedIP,
  normalizeHostname,
  safeFetch,
  validateUrl,
  validateUrlWithDns,
} from "./url-validator.ts";

const blocked = [
  "0.0.0.0", "0.1.2.3", "10.0.0.1", "127.0.0.1", "127.255.255.254", "169.254.169.254",
  "169.254.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1",
  "100.127.255.255", "224.0.0.1", "239.255.255.250", "255.255.255.255", "240.0.0.1",
  "::", "::1", "0:0:0:0:0:0:0:1", "fc00::1", "fd12:3456::1", "fe80::1", "febf::1",
  "fe80::1%eth0", "ff02::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:8.8.8.8",
  "::ffff:169.254.169.254", "::127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:a00:1::",
  "2001:db8::1", "not-an-ip:zz",
];
const allowed = ["8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111", "2001:4860:4860::8888"];

Deno.test("IP classifier blocks non-public ranges", () => {
  for (const ip of blocked) assertEquals(isBlockedIP(ip), true, ip);
});
Deno.test("IP classifier allows public addresses", () => {
  for (const ip of allowed) assertEquals(isBlockedIP(ip), false, ip);
});
Deno.test("hostname brackets are stripped", () => {
  assertEquals(normalizeHostname(new URL("https://[::1]/").hostname), "::1");
  assertEquals(normalizeHostname("Example.COM."), "example.com");
});
Deno.test("validateUrl rejects bad URLs", () => {
  for (const u of [
    "http://example.com", "ftp://example.com", "https://[::1]/", "https://[fe80::1]/",
    "https://[::ffff:127.0.0.1]/", "https://127.0.0.1/", "https://2130706433/", "https://0x7f.1/",
    "https://169.254.169.254/latest/meta-data", "https://localhost/", "https://foo.localhost/",
    "https://metadata.google.internal/", "https://user:pw@example.com/", "not a url",
  ]) assertEquals(validateUrl(u).valid, false, u);
  assertEquals(validateUrl("https://example.com/x").valid, true);
});

const fakeDns = (map: Record<string, { A?: string[]; AAAA?: string[] }>) =>
  (host: string, type: "A" | "AAAA") => {
    const r = map[host]?.[type];
    return r ? Promise.resolve(r) : Promise.reject(new Error("NXDOMAIN"));
  };

Deno.test("DNS: rejects if any A/AAAA record is private", async () => {
  const dns = fakeDns({
    "good.test": { A: ["93.184.216.34"], AAAA: ["2606:2800:220:1::1"] },
    "mixed.test": { A: ["93.184.216.34", "10.0.0.5"] },
    "v6bad.test": { A: ["93.184.216.34"], AAAA: ["::1"] },
    "meta.test": { A: ["169.254.169.254"] },
  });
  assertEquals((await validateUrlWithDns("https://good.test/", dns)).valid, true);
  assertEquals((await validateUrlWithDns("https://mixed.test/", dns)).valid, false);
  assertEquals((await validateUrlWithDns("https://v6bad.test/", dns)).valid, false);
  assertEquals((await validateUrlWithDns("https://meta.test/", dns)).valid, false);
  assertEquals((await validateUrlWithDns("https://nx.test/", dns)).valid, false);
});

Deno.test("safeFetch rejects before any network call when DNS is private", async () => {
  const dns = fakeDns({ "internal.test": { A: ["192.168.0.10"] } });
  const r = await safeFetch("https://internal.test/", undefined, dns);
  assertEquals(r.ok, false);
});

Deno.test("safeFetch re-validates redirect hops and caps hops", async () => {
  const dns = fakeDns({ "a.test": { A: ["93.184.216.34"] }, "b.test": { A: ["10.1.1.1"] } });
  const orig = globalThis.fetch;
  const seen: string[] = [];
  try {
    globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
      seen.push(String(input));
      assertEquals(init?.redirect, "manual");
      const u = new URL(String(input));
      if (u.pathname === "/to-private") return Promise.resolve(new Response(null, { status: 302, headers: { location: "https://b.test/" } }));
      if (u.pathname === "/to-meta") return Promise.resolve(new Response(null, { status: 301, headers: { location: "https://169.254.169.254/" } }));
      if (u.pathname === "/to-http") return Promise.resolve(new Response(null, { status: 307, headers: { location: "http://a.test/" } }));
      if (u.pathname === "/loop") return Promise.resolve(new Response(null, { status: 302, headers: { location: "/loop" } }));
      return Promise.resolve(new Response("ok", { status: 200 }));
    }) as typeof fetch;
    assertEquals((await safeFetch("https://a.test/to-private", undefined, dns)).ok, false);
    assertEquals((await safeFetch("https://a.test/to-meta", undefined, dns)).ok, false);
    assertEquals((await safeFetch("https://a.test/to-http", undefined, dns)).ok, false);
    seen.length = 0;
    const loop = await safeFetch("https://a.test/loop", undefined, dns);
    assertEquals(loop.ok, false);
    assertEquals(seen.length, 6); // initial + MAX_REDIRECTS
    assertEquals((await safeFetch("https://a.test/ok", undefined, dns)).ok, true);
  } finally {
    globalThis.fetch = orig;
  }
});
