import { useState, useEffect } from 'react';
import { Plus, Globe, Shield, Trash2, ExternalLink, CheckCircle, XCircle, Copy } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import SetupWizard from '@/components/SetupWizard';
import type { Tables } from '@/integrations/supabase/types';

type ProtectedSite = Tables<'protected_sites'>;

export default function SiteManager() {
  const { user } = useAuth();
  const [sites, setSites] = useState<ProtectedSite[]>([]);
  const [newUrl, setNewUrl] = useState('');
  const [newName, setNewName] = useState('');
  const [adding, setAdding] = useState(false);
  const [loading, setLoading] = useState(true);
  const [wizardSite, setWizardSite] = useState<ProtectedSite | null>(null);

  const proxyBaseUrl = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/waf-proxy`;

  useEffect(() => {
    if (!user) return;
    loadSites();
  }, [user]);

  const loadSites = async () => {
    const { data, error } = await supabase
      .from('protected_sites')
      .select('*')
      .order('created_at', { ascending: false });
    if (!error) setSites(data || []);
    setLoading(false);
  };

  const handleAddSite = async () => {
    if (!user || !newUrl) {
      toast.error("Please enter your app's URL");
      return;
    }
    try { new URL(newUrl); } catch { toast.error('Please enter a valid URL'); return; }

    const { data, error } = await supabase
      .from('protected_sites')
      .insert({
        user_id: user.id,
        url: newUrl,
        name: newName || new URL(newUrl).hostname,
        status: 'pending',
        ssl_valid: newUrl.startsWith('https'),
      })
      .select()
      .single();

    if (error) { toast.error('Failed to add site'); return; }

    setSites(prev => [data, ...prev]);
    setNewUrl('');
    setNewName('');
    setAdding(false);

    // Open the setup wizard
    setWizardSite(data);
  };

  const removeSite = async (id: string) => {
    if (!user) return;
    
    // Delete all user data across all tables
    const [siteDel, rulesDel, rateDel, apiDel, threatDel, rateLimitHitsDel] = await Promise.all([
      supabase.from('protected_sites').delete().eq('id', id),
      supabase.from('waf_rules').delete().eq('user_id', user.id),
      supabase.from('rate_limit_rules').delete().eq('user_id', user.id),
      supabase.from('api_endpoints').delete().eq('user_id', user.id),
      supabase.from('threat_logs').delete().eq('user_id', user.id),
      supabase.from('rate_limit_hits').delete().eq('user_id', user.id),
    ]);

    if (siteDel.error) { toast.error('Failed to remove site'); return; }
    setSites(prev => prev.filter(s => s.id !== id));
    toast.success('Site and all associated data removed');
  };

  const copyProxyUrl = (siteId: string) => {
    const url = `${proxyBaseUrl}?site_id=${siteId}&path=/`;
    navigator.clipboard.writeText(url);
    toast.success('WAF proxy URL copied to clipboard');
  };

  const statusStyles: Record<string, string> = {
    active: 'text-primary',
    inactive: 'text-muted-foreground',
    pending: 'text-warning animate-pulse',
  };

  if (loading) return <div className="text-xs text-muted-foreground">Loading sites...</div>;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Protected Sites</h2>
          <p className="text-xs text-muted-foreground">Add your app's URL — AI will auto-configure WAF rules, rate limits & threat detection</p>
        </div>
        <Button
          size="sm"
          onClick={() => setAdding(!adding)}
          className="bg-primary text-primary-foreground rounded-xl"
        >
          <Plus className="w-4 h-4 mr-1" />
          Add Site
        </Button>
      </div>

      {adding && (
        <div className="glass-card gradient-border rounded-xl p-5 space-y-3">
          <p className="text-xs font-semibold text-primary">Add Your App to Deflectra</p>
          <p className="text-xs text-muted-foreground">Enter the URL of your web application. Our AI will automatically analyze it and generate WAF rules, rate limits, and API monitoring tailored to your app type.</p>
          <Input
            placeholder="https://your-app.com"
            value={newUrl}
            onChange={(e) => setNewUrl(e.target.value)}
            className="bg-secondary/50 border-border font-mono text-sm rounded-xl h-10"
          />
          <Input
            placeholder="Site name (optional)"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            className="bg-secondary/50 border-border text-sm rounded-xl h-10"
          />
          <div className="flex gap-2">
            <Button size="sm" onClick={handleAddSite} className="bg-primary text-primary-foreground rounded-lg">
              <Shield className="w-3.5 h-3.5 mr-1" /> Protect Site
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setAdding(false)} className="text-muted-foreground rounded-lg">Cancel</Button>
          </div>
        </div>
      )}

      {/* Setup Wizard */}
      {wizardSite && (
        <SetupWizard
          siteId={wizardSite.id}
          siteUrl={wizardSite.url}
          siteName={wizardSite.name}
          onComplete={() => { setWizardSite(null); loadSites(); }}
          onCancel={() => setWizardSite(null)}
        />
      )}

      {sites.length === 0 && !adding && (
        <div className="glass-card rounded-xl p-12 text-center">
          <Globe className="w-10 h-10 text-muted-foreground mx-auto mb-3 opacity-50" />
          <p className="text-sm text-muted-foreground font-medium">No protected sites yet</p>
          <p className="text-xs text-muted-foreground mt-1">Add your first web app — AI will handle the rest</p>
        </div>
      )}

      <div className="space-y-3">
        {sites.map((site) => (
          <div key={site.id} className="glass-card-hover rounded-xl p-5">
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center mt-0.5">
                  <Globe className="w-5 h-5 text-primary" />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-semibold text-foreground">{site.name}</p>
                    <span className={cn("text-[10px] font-mono uppercase flex items-center gap-1", statusStyles[site.status])}>
                      <span className="w-1.5 h-1.5 rounded-full bg-current" />
                      {site.status}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-muted-foreground">{site.url}</p>
                  
                  <div className="mt-2 bg-secondary/30 rounded-lg px-3 py-2 flex items-center justify-between gap-2">
                    <div>
                      <p className="text-[10px] font-mono text-muted-foreground">WAF PROXY ENDPOINT</p>
                      <p className="text-[10px] font-mono text-primary truncate max-w-[400px]">
                        {proxyBaseUrl}?site_id={site.id}&path=/your-path
                      </p>
                    </div>
                    <Button size="icon" variant="ghost" className="w-7 h-7 text-muted-foreground hover:text-primary shrink-0" onClick={() => copyProxyUrl(site.id)}>
                      <Copy className="w-3 h-3" />
                    </Button>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <p className="text-[10px] font-mono text-muted-foreground">BLOCKED</p>
                  <p className="text-sm font-bold text-foreground">{site.threats_blocked.toLocaleString()}</p>
                </div>
                <div className="text-right">
                  <p className="text-[10px] font-mono text-muted-foreground">SSL</p>
                  {site.ssl_valid ? <CheckCircle className="w-4 h-4 text-primary" /> : <XCircle className="w-4 h-4 text-destructive" />}
                </div>
                <div className="flex gap-1">
                  <Button size="icon" variant="ghost" className="w-8 h-8 text-muted-foreground hover:text-foreground rounded-lg">
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Button>
                  <Button size="icon" variant="ghost" className="w-8 h-8 text-muted-foreground hover:text-destructive rounded-lg" onClick={() => removeSite(site.id)}>
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {sites.length > 0 && (
        <div className="glass-card rounded-xl p-4">
          <h4 className="text-xs font-semibold text-foreground mb-2">How Deflectra WAF Protection Works</h4>
          <ol className="text-xs text-muted-foreground space-y-1.5 list-decimal list-inside">
            <li>Add your app's URL — AI automatically generates WAF rules, rate limits & API monitoring</li>
            <li>Copy the WAF proxy endpoint shown for your site</li>
            <li>Route traffic through the proxy — it inspects every request with your rules + AI</li>
            <li>Clean traffic is forwarded to your origin; threats are blocked and logged</li>
          </ol>
        </div>
      )}
    </div>
  );
}
