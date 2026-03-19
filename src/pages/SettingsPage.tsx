import { useState, useEffect } from 'react';
import { Shield, Bell, Key, LogOut, Send, Mail, Brain, Gauge, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { toast } from 'sonner';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';

export default function SettingsPage() {
  const { user, signOut } = useAuth();
  const [paranoiaLevel, setParanoiaLevel] = useState('1');
  const [defaultAction, setDefaultAction] = useState('block');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [alertEmail, setAlertEmail] = useState('');
  const [resendApiKey, setResendApiKey] = useState('');
  const [aiDetectionEnabled, setAiDetectionEnabled] = useState(true);
  const [apiProtectionEnabled, setApiProtectionEnabled] = useState(true);
  const [rateLimitingEnabled, setRateLimitingEnabled] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [testingSend, setTestingSend] = useState(false);

  useEffect(() => {
    if (!user) return;
    loadSettings();
  }, [user]);

  const loadSettings = async () => {
    const { data } = await supabase.from('waf_settings').select('*').eq('user_id', user!.id).maybeSingle();
    if (data) {
      setParanoiaLevel(data.paranoia_level.toString());
      setDefaultAction(data.default_action);
      setWebhookUrl(data.webhook_url || '');
      setAlertEmail(data.alert_email || '');
      setResendApiKey((data as any).resend_api_key || '');
      setAiDetectionEnabled(data.ai_detection_enabled);
      setApiProtectionEnabled(data.api_protection_enabled);
      setRateLimitingEnabled(data.rate_limiting_enabled);
    }
    setLoaded(true);
  };

  const saveSettings = async () => {
    if (!user) return;
    setSaving(true);
    
    // Save resend key to localStorage
    if (resendApiKey) {
      localStorage.setItem('deflectra_resend_key', resendApiKey);
    } else {
      localStorage.removeItem('deflectra_resend_key');
    }

    const { error } = await supabase.from('waf_settings').upsert({
      user_id: user.id,
      paranoia_level: parseInt(paranoiaLevel),
      default_action: defaultAction,
      webhook_url: webhookUrl || null,
      alert_email: alertEmail || null,
      ai_detection_enabled: aiDetectionEnabled,
      api_protection_enabled: apiProtectionEnabled,
      rate_limiting_enabled: rateLimitingEnabled,
    }, { onConflict: 'user_id' });
    if (error) toast.error('Failed to save');
    else toast.success('Settings saved');
    setSaving(false);
  };

  const sendTestEmail = async () => {
    if (!resendApiKey) {
      toast.error('Please enter your Resend API key first');
      return;
    }
    if (!alertEmail) {
      toast.error('Please enter an alert email address');
      return;
    }
    setTestingSend(true);
    try {
      const { data, error } = await supabase.functions.invoke('send-notification', {
        body: {
          resendApiKey,
          to: alertEmail,
          subject: '🛡️ Deflectra WAF — Test Notification',
          html: `
            <div style="font-family: system-ui, sans-serif; max-width: 500px; margin: 0 auto; padding: 24px;">
              <h2 style="color: #1a7a6d;">Deflectra WAF Alert</h2>
              <p>This is a test notification from your Deflectra WAF dashboard.</p>
              <p>Email notifications are configured and working correctly.</p>
              <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 16px 0;" />
              <p style="font-size: 12px; color: #6b7280;">Deflectra — Adaptive Web Shield</p>
            </div>
          `,
        },
      });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);
      toast.success('Test email sent! Check your inbox.');
    } catch (err: any) {
      toast.error(err.message || 'Failed to send test email');
    }
    setTestingSend(false);
  };

  if (!loaded) return <div className="text-xs text-muted-foreground">Loading...</div>;

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Settings</h1>
        <p className="text-sm text-muted-foreground mt-1">Configure your Deflectra WAF</p>
      </div>

      {/* Feature Toggles */}
      <div className="glass-card rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-primary" /> Protection Features
        </h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Brain className="w-4 h-4 text-primary" />
              <div>
                <p className="text-sm font-medium text-foreground">AI Threat Detection</p>
                <p className="text-xs text-muted-foreground">Use Gemini AI to detect unknown threats</p>
              </div>
            </div>
            <Switch checked={aiDetectionEnabled} onCheckedChange={setAiDetectionEnabled} />
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-4 h-4 text-primary" />
              <div>
                <p className="text-sm font-medium text-foreground">API Protection</p>
                <p className="text-xs text-muted-foreground">JWT validation & schema enforcement</p>
              </div>
            </div>
            <Switch checked={apiProtectionEnabled} onCheckedChange={setApiProtectionEnabled} />
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Gauge className="w-4 h-4 text-accent" />
              <div>
                <p className="text-sm font-medium text-foreground">Rate Limiting</p>
                <p className="text-xs text-muted-foreground">Per-IP request limits</p>
              </div>
            </div>
            <Switch checked={rateLimitingEnabled} onCheckedChange={setRateLimitingEnabled} />
          </div>
        </div>
      </div>

      <div className="glass-card rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Shield className="w-4 h-4 text-primary" /> Security
        </h3>
        <div className="space-y-3">
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1.5">Paranoia Level</label>
            <select value={paranoiaLevel} onChange={(e) => setParanoiaLevel(e.target.value)} className="bg-secondary/50 border border-border rounded-xl px-3 py-2.5 text-sm text-foreground w-full">
              <option value="1">Level 1 — Low (fewer false positives)</option>
              <option value="2">Level 2 — Balanced</option>
              <option value="3">Level 3 — Aggressive</option>
              <option value="4">Level 4 — Maximum protection</option>
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1.5">Default Action</label>
            <select value={defaultAction} onChange={(e) => setDefaultAction(e.target.value)} className="bg-secondary/50 border border-border rounded-xl px-3 py-2.5 text-sm text-foreground w-full">
              <option value="block">Block</option>
              <option value="challenge">Challenge</option>
              <option value="log">Log Only</option>
            </select>
          </div>
        </div>
      </div>

      <div className="glass-card rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Bell className="w-4 h-4 text-primary" /> Notifications
        </h3>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1.5">Webhook URL</label>
          <Input placeholder="https://hooks.slack.com/..." value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} className="bg-secondary/50 border-border text-sm rounded-xl h-10" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1.5">Alert Email</label>
          <Input placeholder="security@company.com" type="email" value={alertEmail} onChange={(e) => setAlertEmail(e.target.value)} className="bg-secondary/50 border-border text-sm rounded-xl h-10" />
        </div>
      </div>

      <div className="glass-card rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Mail className="w-4 h-4 text-primary" /> Email Notifications (Resend)
        </h3>
        <p className="text-xs text-muted-foreground">
          Enter your <a href="https://resend.com/api-keys" target="_blank" rel="noopener noreferrer" className="text-primary underline">Resend API key</a> to enable email notifications for threat alerts.
        </p>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1.5">Resend API Key</label>
          <Input
            placeholder="re_xxxxxxxxxxxx"
            type="password"
            value={resendApiKey}
            onChange={(e) => setResendApiKey(e.target.value)}
            className="bg-secondary/50 border-border font-mono text-sm rounded-xl h-10"
          />
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={sendTestEmail}
          disabled={testingSend || !resendApiKey || !alertEmail}
          className="rounded-lg"
        >
          <Send className="w-3.5 h-3.5 mr-1.5" />
          {testingSend ? 'Sending...' : 'Send Test Email'}
        </Button>
        {(!resendApiKey || !alertEmail) && (
          <p className="text-[10px] text-muted-foreground">
            {!resendApiKey ? 'Enter your Resend API key' : 'Enter an alert email above'} to send a test.
          </p>
        )}
      </div>

      <div className="glass-card rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Key className="w-4 h-4 text-primary" /> Account
        </h3>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Logged in as</label>
          <p className="text-sm font-mono text-foreground">{user?.email}</p>
        </div>
        <Button variant="outline" size="sm" onClick={signOut} className="text-destructive border-destructive/30 hover:bg-destructive/10 rounded-lg">
          <LogOut className="w-3.5 h-3.5 mr-1" /> Sign Out
        </Button>
      </div>

      <Button onClick={saveSettings} disabled={saving} className="bg-primary text-primary-foreground rounded-xl">
        {saving ? 'Saving...' : 'Save Settings'}
      </Button>
    </div>
  );
}
