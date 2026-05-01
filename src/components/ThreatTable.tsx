import { useEffect, useState } from 'react';
import { cn } from '@/lib/utils';
import { supabase } from '@/integrations/supabase/client';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { useAuth } from '@/hooks/useAuth';
import { MapPin, MapPinOff } from 'lucide-react';
import type { Tables } from '@/integrations/supabase/types';

type ThreatLog = Tables<'threat_logs'>;

const severityStyles: Record<string, string> = {
  critical: 'bg-threat-critical/15 text-threat-critical border-threat-critical/30',
  high: 'bg-threat-high/15 text-threat-high border-threat-high/30',
  medium: 'bg-threat-medium/15 text-threat-medium border-threat-medium/30',
  low: 'bg-threat-low/15 text-threat-low border-threat-low/30',
};

const actionStyles: Record<string, string> = {
  blocked: 'bg-destructive/15 text-destructive border-destructive/30',
  challenged: 'bg-warning/15 text-warning border-warning/30',
  logged: 'bg-primary/15 text-primary border-primary/30',
  allowed: 'bg-accent/15 text-accent border-accent/30',
};

export default function ThreatTable() {
  const { user } = useAuth();
  const [threats, setThreats] = useState<ThreatLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) return;
    loadThreats();
  }, [user]);

  const loadThreats = async () => {
    const { data, error } = await supabase
      .from('threat_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(50);
    if (!error) setThreats(data || []);
    setLoading(false);
  };

  return (
    <div className="glass-card rounded-xl overflow-hidden">
      <div className="px-5 py-3 border-b border-border/50 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-foreground">Recent Threats</h3>
        <span className="text-xs font-mono text-muted-foreground">
          {threats.length > 0 ? `${threats.length} logged` : 'No threats yet'}
        </span>
      </div>

      {loading ? (
        <div className="p-8 text-center text-xs text-muted-foreground">Loading...</div>
      ) : threats.length === 0 ? (
        <div className="p-12 text-center">
          <p className="text-sm text-muted-foreground">No threats logged yet</p>
          <p className="text-xs text-muted-foreground mt-1">
            Add a protected site, then use AI Detection to analyze incoming traffic
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border/50 bg-secondary/20">
                <th className="text-left px-5 py-2.5 text-muted-foreground font-medium font-mono text-[10px] tracking-wider">TIME</th>
                <th className="text-left px-5 py-2.5 text-muted-foreground font-medium font-mono text-[10px] tracking-wider">SOURCE</th>
                <th className="text-left px-5 py-2.5 text-muted-foreground font-medium font-mono text-[10px] tracking-wider">TYPE</th>
                <th className="text-left px-5 py-2.5 text-muted-foreground font-medium font-mono text-[10px] tracking-wider">SEVERITY</th>
                <th className="text-left px-5 py-2.5 text-muted-foreground font-medium font-mono text-[10px] tracking-wider">ACTION</th>
                <th className="text-left px-5 py-2.5 text-muted-foreground font-medium font-mono text-[10px] tracking-wider">TARGET</th>
              </tr>
            </thead>
            <tbody>
              {threats.map((t) => (
                <tr key={t.id} className="border-b border-border/30 hover:bg-secondary/20 transition-colors">
                  <td className="px-5 py-3 text-muted-foreground font-mono">
                    {new Date(t.created_at).toLocaleTimeString()}
                  </td>
                  <td className="px-5 py-3 font-mono">
                    <span className="text-foreground">{t.source_ip}</span>
                    {t.source_country && <span className="text-muted-foreground ml-1.5">({t.source_country})</span>}
                    <TooltipProvider delayDuration={200}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          {(t.details as any)?.geo_source === 'ip-api' ? (
                            <MapPin className="inline-block w-3 h-3 ml-1.5 text-accent" />
                          ) : (
                            <MapPinOff className="inline-block w-3 h-3 ml-1.5 text-muted-foreground/50" />
                          )}
                        </TooltipTrigger>
                        <TooltipContent side="top" className="text-xs">
                          {(t.details as any)?.geo_source === 'ip-api'
                            ? 'Verified location via IP geolocation'
                            : 'Geo data unavailable (private IP or lookup failed)'}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </td>
                  <td className="px-5 py-3 text-foreground">{t.threat_type}</td>
                  <td className="px-5 py-3">
                    <span className={cn("px-2 py-0.5 rounded-md text-[10px] uppercase border font-mono font-medium", severityStyles[t.severity] || severityStyles.low)}>
                      {t.severity}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    <TooltipProvider delayDuration={200}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className={cn("px-2 py-0.5 rounded-md text-[10px] uppercase border font-mono font-medium cursor-help", actionStyles[t.action_taken] || actionStyles.logged)}>
                            {t.action_taken}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="max-w-xs p-3 space-y-1.5 text-xs">
                          <p className="font-semibold text-foreground">
                            {t.request_method || 'GET'} <span className="font-mono text-muted-foreground">{t.request_path || '/'}</span>
                          </p>
                          <p className="text-muted-foreground leading-relaxed">
                            {t.action_taken === 'blocked'
                              ? `Blocked: matched "${t.threat_type}" rule. The request pattern was flagged as ${t.severity} severity and automatically denied.`
                              : t.action_taken === 'challenged'
                              ? `Challenged: suspicious "${t.threat_type}" pattern detected. Client was issued a verification challenge.`
                              : t.action_taken === 'logged'
                              ? `Logged: "${t.threat_type}" pattern observed but below action threshold. Recorded for monitoring.`
                              : `Allowed: request passed all security checks.`}
                          </p>
                          {t.source_ip && (
                            <p className="font-mono text-[10px] text-muted-foreground/70">
                              From: {t.source_ip}{t.source_country ? ` (${t.source_country})` : ''}
                            </p>
                          )}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </td>
                  <td className="px-5 py-3 text-muted-foreground max-w-[200px] truncate font-mono">
                    {t.request_path || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
