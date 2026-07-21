# Deflectra — Adaptive Web Shield

An AI-powered Web Application Firewall (WAF) that operates as a Layer 7 reverse proxy, combining regex-based pattern matching, Google Gemini AI threat classification, JWT validation, schema enforcement, and per-IP rate limiting to protect web applications from common attacks.

> **[Live Demo → https://aiwaf.netlify.app](https://aiwaf.netlify.app/)**

> **[Full Technical Documentation →](DOCUMENTATION.md)**

**Anyone can create an account** and connect their own web applications for AI-powered WAF protection.

---

## Key Features

- **AI-Powered Threat Detection** — Google Gemini 3.1 Pro analyzes suspicious requests in real-time, classifying attack intent with adjustable paranoia levels (1–4)
- **Regex Rule Engine** — Pre-built and custom regex patterns for SQLi, XSS, RCE, LFI, and path traversal with priority-based execution ordering
- **Per-IP Rate Limiting** — Configurable request thresholds per endpoint with block, throttle, or challenge actions
- **API Protection** — JWT token inspection, JSON schema validation, and per-endpoint rate limiting for REST APIs
- **3D Threat Globe** — Real-time Mapbox GL visualization showing attack origins with animated arcs and country-level attribution via real IP geolocation
- **Setup Wizard with Config Review** — Interactive 4-phase setup tracker with live crawl verification, side-by-side config diff, and safe test mode before activation
- **Real IP Geolocation** — Verified geo data from ip-api.com with in-memory caching, rate limiting, and UI indicators for lookup status
- **Auto-Configuration** — AI analyzes your application's tech stack and auto-generates tailored WAF rules, rate limits, and API endpoint protections
- **Real-Time Dashboard** — Live threat logs, traffic analytics, block rate metrics, and top attack type breakdowns via Supabase Realtime
- **Branded Block Pages** — Custom-styled block pages served to attackers with threat details and incident IDs
- **Email & Webhook Alerts** — Configurable notifications via Resend API and webhook integrations for Slack, Discord, or custom endpoints
- **Multi-Site Management** — Protect multiple web applications from a single dashboard with per-site analytics

---

## System Architecture

<p align="center">
  <img src="https://i.imgur.com/DTzhcSz.png" alt="Deflectra Cloud-Native Layer 7 Security & Threat Detection Architecture" width="100%" />
</p>
<p align="center"><strong>Figure 1 — Deflectra Cloud-Native Layer 7 Security & Threat Detection Architecture</strong></p>

---

## System Flow & Component Overview

Deflectra's architecture is structured into **5 Security Zones** containing **10 Core System Nodes** and **13 Directional Data Flow Arrows**:

### 1. Security Zones Overview
- **Zone 1: Untrusted**: Public Internet & Client Traffic (End Users, Web Browsers, Crawlers, or Attackers).
- **Zone 2: Edge Ingress**: Serverless Edge Inspection Proxy (`waf-proxy` Supabase Edge Functions running on Deno / TypeScript).
- **Zone 3: Control Plane**: Deflectra Management Plane (React SPA + Supabase PostgreSQL with Row-Level Security).
- **Zone 4: AI & Telemetry**: Out-of-band external services (Google Gemini 3.1 Pro, ip-api.com, Resend API, Webhooks, Mapbox GL).
- **Zone 5: Protected Origin**: Customer Application Backend (Web Applications, APIs, Internal Services, Databases).

---

### 2. Node-by-Node Component Breakdown (Nodes 1–10)

1. **User / Attacker Client (Node 1)**: End users, browsers, crawlers, or attackers sending HTTP/HTTPS requests.
2. **Cloudflare Worker (Optional - Node 2)**: Edge proxy / CDN that intercepts and routes ingress payload to Deflectra proxy.
3. **waf-proxy Edge Function (Node 3)**: Serverless reverse proxy executing the 6-Stage Inspection Pipeline:
   - **Stage 1: JWT Inspection**: Validates Authorization bearer tokens (`401 Unauthorized` on failure).
   - **Stage 2: JSON Schema Validation**: Checks POST/PUT request body against defined schemas (`400 Bad Request` on failure).
   - **Stage 3: Per-IP Rate Limiting**: Token bucket frequency check per window (`429 Too Many Requests` on breach).
   - **Stage 4: Regex Rule Matching**: Prioritized regex matching for SQLi, XSS, RCE, LFI, and custom patterns (`403 Forbidden` on match).
   - **Stage 5: AI Threat Classification**: Deep context analysis via Google Gemini 3.1 Pro with paranoia levels 1–4.
   - **Stage 6: Decision Execution**: Forwards clean traffic to origin OR returns branded block page.
4. **Supabase PostgreSQL Database (Node 4)**: RLS-enabled data store containing `protected_sites`, `waf_rules`, `rate_limit_rules`, `api_endpoints`, `threat_logs`, `waf_settings`, and `notifications`.
5. **Real IP Geolocation Service (Node 5)**: IP-to-country, lat/long, and ISP attribution via `ip-api.com` with in-memory caching.
6. **Google Gemini 3.1 Pro AI Engine (Node 6)**: Real-time threat intent classification, risk scoring, and auto-generated WAF rules.
7. **Blocked Response (Node 7 / 8)**: Serves custom branded HTML block page containing threat details, incident ID, and timestamp (`403 / 429 / 401`).
8. **Supabase Realtime Engine (Node 8)**: WebSocket Pub/Sub bus pushing live threat events (`INSERT`) to the frontend console.
9. **Notification Dispatcher (Node 9)**: Async email delivery via Resend API and webhook alerts to Slack, Discord, or SIEM endpoints.
10. **Customer Protected Origin Server (Node 10)**: Application backend receiving verified, clean HTTP/HTTPS traffic.

---

### 3. Step-by-Step Data Flow Arrows (Flows 1–13)

- **Flow 1 (HTTP/HTTPS Request)**: Client $\rightarrow$ Cloudflare Worker / Direct Proxy Ingress.
- **Flow 2 (Forward Ingress Payload)**: Cloudflare Worker $\rightarrow$ `waf-proxy` Edge Function.
- **Flow 3 (Query Active WAF & Site Rules)**: `waf-proxy` $\rightarrow$ Supabase PostgreSQL Database.
- **Flow 4 (Return Active Rules & Config JSON)**: Supabase PostgreSQL $\rightarrow$ `waf-proxy`.
- **Flow 5 (Resolve IP Geolocation)**: `waf-proxy` $\rightarrow$ Real IP Geolocation Service (`ip-api.com`).
- **Flow 6 (Deep AI Threat Inspection)**: `waf-proxy` $\rightarrow$ Google Gemini 3.1 Pro AI Engine.
- **Flow 7 (Out-of-Band High/Critical Alert)**: `waf-proxy` $\rightarrow$ Notification Dispatcher / Realtime Engine.
- **Flow 8 (Blocked Response)**: `waf-proxy` $\rightarrow$ Attacker Client (Returns custom `403 / 429 / 401` Branded Block Page).
- **Flow 9 (Forward Clean Traffic)**: `waf-proxy` $\rightarrow$ Customer Protected Origin Server (HTTP/HTTPS Reverse Proxy).
- **Flow 10 (Write Audit & Threat Logs)**: `waf-proxy` $\rightarrow$ Supabase PostgreSQL (`threat_logs` table insert).
- **Flow 11 (Realtime Event Stream INSERT)**: Supabase PostgreSQL $\rightarrow$ Supabase Realtime Engine (WebSocket Bus).
- **Flow 12 (Live Stream to Dashboard & 3D Globe)**: Supabase Realtime Engine $\rightarrow$ Deflectra Management Console (React Frontend).
- **Flow 13 (Async Email & Webhook Alerts)**: Notification Dispatcher $\rightarrow$ Resend API / Webhooks (Slack, Discord, SIEM).

---

### 4. End-to-End Data Flow Summary
1. Inbound request sent from client to Cloudflare or proxy (`HTTPS`).
2. Cloudflare forwards request payload to Deflectra `waf-proxy`.
3. `waf-proxy` loads active rules & configs from Supabase DB.
4. WAF proxy executes 6-stage inspection pipeline (JWT, Schema, Rate Limit, Regex, AI, Decision).
5. Geolocation & AI analysis return threat context & risk score.
6. Clean traffic is forwarded to origin server; blocked traffic receives custom `403/429/401` response.
7. All requests are audited & logged to Supabase DB.
8. Logs stream in real time to frontend dashboard and 3D Threat Globe via WebSockets.
9. High/Critical threats trigger async email and webhook alerts.

---

## Tech Stack

### Frontend
| Technology | Purpose |
|-----------|---------|
| **React 18** | Component-based UI framework |
| **Vite** | Build tooling and dev server |
| **TypeScript** | Type-safe development |
| **Tailwind CSS** | Utility-first styling |
| **shadcn/ui** | Accessible component library |
| **Recharts** | Traffic and analytics charts |
| **Mapbox GL JS** | 3D threat globe visualization |
| **Framer Motion** | Page transitions and animations |

### Backend & Infrastructure
| Technology | Purpose |
|-----------|---------|
| **Supabase PostgreSQL** | Database with Row-Level Security |
| **Supabase Edge Functions** | Serverless WAF proxy and AI analysis |
| **Supabase Auth** | User authentication and session management |
| **Supabase Realtime** | Live threat log streaming via WebSocket |
| **Google Gemini 3.1 Pro** | AI-powered threat classification |
| **Cloudflare Workers** | Optional edge-level traffic interception |
| **Resend API** | Email alert delivery |

---

## Setup Guide

### Step 1: Access the Application

There are two ways to access Deflectra:

#### Option A — Use the Live Deployment (Quickest)

1. Open **[https://aiwaf.netlify.app](https://aiwaf.netlify.app/)**
2. You will land on the **Auth** page — skip to Step 2

#### Option B — Run Locally

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/deflectra.git
   cd deflectra
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment variables:**
   Create a `.env` file in the project root with the following:
   ```env
   VITE_SUPABASE_URL=your-supabase-url
   VITE_SUPABASE_PUBLISHABLE_KEY=your-supabase-anon-key
   VITE_SUPABASE_PROJECT_ID=your-supabase-project-id
   ```
   These values come from your Supabase project dashboard under **Settings → API**.

4. **Push database migrations:**
   ```bash
   npx supabase db push
   ```
   This creates all required tables (`waf_rules`, `threat_logs`, `protected_sites`, `rate_limit_rules`, `api_endpoints`, `waf_settings`, `notifications`, `rate_limit_hits`) with Row-Level Security policies.

5. **Deploy Edge Functions:**
   ```bash
   npx supabase functions deploy waf-proxy analyze-threat auto-setup-waf auto-generate-fields send-notification
   ```

6. **Set backend secrets:**
   ```bash
   npx supabase secrets set LOVABLE_API_KEY=your-lovable-api-key
   ```
   The `LOVABLE_API_KEY` powers the AI threat analysis and auto-generation features.

7. **Start the development server:**
   ```bash
   npm run dev
   ```
   The app will be available at `http://localhost:5173`. You will land on the **Auth** page.

### Step 2: Create Your Account

1. Click the **Sign Up** tab
2. Enter your email address and choose a password
3. Click **Sign Up**
4. Check your email inbox for a verification link
5. Click the verification link to confirm your account
6. Return to the app and **Sign In** with your credentials

### Step 3: Explore the Dashboard

Once logged in, you will see the main dashboard with:
- **Requests blocked** — total threats stopped
- **Block rate** — percentage of malicious traffic
- **Traffic over time** — request volume charts
- **Recent threats** — latest blocked attacks

The sidebar on the left provides access to every feature. There is also a **Setup Guide** tab in the sidebar that walks you through the entire configuration process step by step within the application itself.

### Step 4: Add Your First Protected Site

1. Navigate to **Sites** in the sidebar
2. Click **Add Site**
3. Enter your application's URL (e.g., `https://myapp.com`)
4. Give it a name (optional — defaults to the hostname)
5. Click **Protect Site**

The **Setup Wizard** opens automatically and performs a live HTTP crawl of your site. You will see a real-time progress tracker showing:
- **Crawl** — Fetching your site's HTML and resources
- **Detect** — Analyzing your tech stack and discovering API endpoints
- **AI Analysis** — Generating tailored WAF rules, rate limits, and API endpoint configs
- **Ready** — Configuration complete and ready for your review

After analysis, the wizard displays:
- A **crawl verification report** showing discovered technologies, endpoints, scripts, and forms
- A **config diff view** with every generated WAF rule, rate limit, and API endpoint setting
- A **safe test mode** where you can validate rules against 8 sample attack payloads without affecting real traffic

Only when you click **Activate Protection** are the rules saved to the database and your site goes live. You will then see a **WAF Proxy Endpoint** URL that you will use to route traffic through the firewall.

### Step 5: Configure WAF Rules

1. Navigate to **Rules** in the sidebar
2. Click **Generate with AI** to auto-create rules based on your site's tech stack
3. AI generates rules for SQLi, XSS, RCE, LFI, and path traversal specific to your stack
4. Each rule shows its name, regex pattern, category, severity, and priority
5. Toggle individual rules on or off as needed
6. To add a custom rule, click **Add Rule** and fill in the pattern, category, severity, priority (1–1000, lower runs first), and action (block, log, or challenge)

### Step 6: Configure Rate Limiting

1. Navigate to **Rate Limiting** in the sidebar
2. Click **Generate with AI** to auto-create rate limits based on detected endpoints
3. AI sets sensible defaults — for example, 5 requests/minute for login, 100 for general API endpoints
4. To add a custom rule, click **Add Rule** and specify the path, max requests, window (seconds), and action
5. Recommended starting points:
   - `/login` → 5 requests / 60 seconds
   - `/register` → 3 requests / 60 seconds
   - `/api/*` → 100 requests / 60 seconds
   - Contact forms → 10 requests / 60 seconds

### Step 7: Configure API Protection

1. Navigate to **API Protection** in the sidebar
2. Click **Generate with AI** to auto-discover and protect your API endpoints
3. For each endpoint, configure:
   - **JWT Inspection** — toggle on for any authenticated route
   - **Schema Validation** — toggle on for POST/PUT endpoints to validate request bodies
   - **Rate Limited** — toggle on to apply rate limiting to the endpoint
4. To manually add an endpoint, click **Add Endpoint** and specify the path and HTTP method

### Step 8: Configure AI Detection

1. Navigate to **AI Detection** in the sidebar
2. Toggle **AI Detection Enabled** to ON
3. Set the **Paranoia Level** (1–4):
   - Level 1 — low sensitivity, fewer false positives
   - Level 2 — balanced (recommended for most applications)
   - Level 3 — high sensitivity, may flag legitimate requests
   - Level 4 — maximum paranoia, aggressive blocking
4. Set the **Default Action** for detected threats (block, log, or challenge)
5. Optionally enter an **Alert Email** to receive notifications when threats are blocked
6. Optionally enter a **Webhook URL** to send alerts to Slack, Discord, or a custom endpoint

### Step 9: Route Traffic Through the WAF

After configuration, integrate the WAF proxy into your application. The proxy endpoint follows this format:

```
https://<project-url>/functions/v1/waf-proxy?site_id=YOUR_SITE_ID&path=/your-endpoint
```

**Option A — Direct API Calls (recommended for specific endpoints):**

```typescript
// Before: Direct call
const response = await fetch('https://your-backend.com/api/contact', {
  method: 'POST',
  body: JSON.stringify(data)
});

// After: Through Deflectra WAF
const WAF_PROXY = 'https://<project-url>/functions/v1/waf-proxy';
const SITE_ID = 'your-site-id-from-deflectra';

const response = await fetch(`${WAF_PROXY}?site_id=${SITE_ID}&path=/api/contact`, {
  method: 'POST',
  body: JSON.stringify(data)
});
```

**Option B — Cloudflare Worker (full traffic interception):**

```javascript
const WAF_PROXY = 'https://<project-url>/functions/v1/waf-proxy';
const SITE_ID = 'your-site-id';

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const wafUrl = `${WAF_PROXY}?site_id=${SITE_ID}&path=${url.pathname}`;
    return fetch(wafUrl, {
      method: request.method,
      headers: request.headers,
      body: request.body
    });
  }
};
```

### Step 10: Monitor and Tune

1. **Threat Globe** (`/globe`) — watch real-time attack origins on a 3D map with animated arcs
2. **Threats** (`/threats`) — review detailed logs with IP, country, attack type, matched rule, severity, and action taken
3. **Notifications** — check the notification center for alerts on critical and high-severity threats
4. **Settings** — verify all protection layers are enabled (AI Detection, Rate Limiting, API Protection)

Review the threats page weekly to identify false positives. If legitimate requests are being blocked, lower the paranoia level or disable specific rules that are too aggressive.

> **Tip:** Deflectra includes a built-in **Setup Guide** tab in the sidebar that walks you through every configuration step directly within the application.

---

## License

MIT
