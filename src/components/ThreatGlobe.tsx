import { useRef, useEffect, useState } from 'react';
import mapboxgl from 'mapbox-gl';
import 'mapbox-gl/dist/mapbox-gl.css';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';

mapboxgl.accessToken = 'pk.eyJ1IjoicmluZHVwdXIiLCJhIjoiY21taWJkOTVqMHozODJyb2ltOWd2d2drZCJ9.ODEM31xGFeSoZqY7UOBh0g';

interface ThreatPoint {
  lat: number;
  lng: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  country?: string;
  type?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff3333',
  high: '#ff8833',
  medium: '#ffaa33',
  low: '#00ddff',
};

const SEVERITY_RADIUS: Record<string, number> = {
  critical: 12,
  high: 9,
  medium: 7,
  low: 5,
};

export default function ThreatGlobe({ className }: { className?: string }) {
  const { user } = useAuth();
  const mapContainer = useRef<HTMLDivElement>(null);
  const map = useRef<mapboxgl.Map | null>(null);
  const [threats, setThreats] = useState<ThreatPoint[]>([]);

  useEffect(() => {
    if (!user) return;
    loadThreats();
  }, [user]);

  const loadThreats = async () => {
    const { data } = await supabase
      .from('threat_logs')
      .select('source_lat, source_lng, severity, source_country, threat_type')
      .select('source_lat, source_lng, severity, source_country, threat_type, details')
      .not('source_lat', 'is', null)
      .not('source_lng', 'is', null)
      .order('created_at', { ascending: false })
      .limit(100);

    if (data && data.length > 0) {
      setThreats(data.map(t => ({
        lat: t.source_lat!,
        lng: t.source_lng!,
        severity: t.severity as ThreatPoint['severity'],
        country: t.source_country || undefined,
        type: t.threat_type || undefined,
        geoSource: (t.details as any)?.geo_source || 'unavailable',
      })));
    }
  };

  useEffect(() => {
    if (!mapContainer.current || map.current) return;

    map.current = new mapboxgl.Map({
      container: mapContainer.current,
      style: 'mapbox://styles/mapbox/light-v11',
      center: [20, 20],
      zoom: 1.5,
      projection: 'globe',
      attributionControl: false,
    });

    // Add zoom controls
    map.current.addControl(new mapboxgl.NavigationControl({ showCompass: false }), 'top-right');

    map.current.on('style.load', () => {
      if (!map.current) return;
      
      // Globe atmosphere
      map.current.setFog({
        color: 'rgb(220, 235, 245)',
        'high-color': 'rgb(180, 210, 235)',
        'horizon-blend': 0.08,
        'space-color': 'rgb(235, 242, 248)',
        'star-intensity': 0,
      });
    });

    // Slow auto-rotate
    const rotateGlobe = () => {
      if (!map.current) return;
      const center = map.current.getCenter();
      center.lng -= 0.15;
      map.current.easeTo({ center, duration: 100, easing: (t) => t });
      requestAnimationFrame(rotateGlobe);
    };

    let rotating = true;
    map.current.on('load', () => {
      rotateGlobe();
    });

    map.current.on('mousedown', () => { rotating = false; });
    map.current.on('dragstart', () => { rotating = false; });

    return () => {
      map.current?.remove();
      map.current = null;
    };
  }, []);

  // Add threat markers when threats or map change
  useEffect(() => {
    if (!map.current || threats.length === 0) return;

    const addMarkers = () => {
      if (!map.current) return;

      // Remove existing source/layer
      if (map.current.getSource('threats')) {
        map.current.removeLayer('threats-glow');
        map.current.removeLayer('threats-points');
        map.current.removeSource('threats');
      }

      // Build GeoJSON
      const geojson: GeoJSON.FeatureCollection = {
        type: 'FeatureCollection',
        features: threats.map(t => ({
          type: 'Feature',
          geometry: { type: 'Point', coordinates: [t.lng, t.lat] },
          properties: {
            severity: t.severity,
            color: SEVERITY_COLORS[t.severity] || SEVERITY_COLORS.low,
            radius: SEVERITY_RADIUS[t.severity] || 5,
            country: t.country || 'Unknown',
            type: t.type || 'Unknown',
          },
        })),
      };

      map.current.addSource('threats', { type: 'geojson', data: geojson });

      // Glow layer
      map.current.addLayer({
        id: 'threats-glow',
        type: 'circle',
        source: 'threats',
        paint: {
          'circle-radius': ['*', ['get', 'radius'], 2.5],
          'circle-color': ['get', 'color'],
          'circle-opacity': 0.15,
          'circle-blur': 1,
        },
      });

      // Point layer
      map.current.addLayer({
        id: 'threats-points',
        type: 'circle',
        source: 'threats',
        paint: {
          'circle-radius': ['get', 'radius'],
          'circle-color': ['get', 'color'],
          'circle-opacity': 0.85,
          'circle-stroke-width': 1.5,
          'circle-stroke-color': '#ffffff',
          'circle-stroke-opacity': 0.6,
        },
      });

      // Popup on click
      map.current.on('click', 'threats-points', (e) => {
        if (!e.features?.[0]) return;
        const props = e.features[0].properties!;
        const coords = (e.features[0].geometry as GeoJSON.Point).coordinates;
        new mapboxgl.Popup({ closeButton: false, className: 'threat-popup' })
          .setLngLat(coords as [number, number])
          .setHTML(`
            <div style="font-family: monospace; font-size: 11px; padding: 4px;">
              <div style="font-weight: bold; color: ${props.color}; text-transform: uppercase;">${props.severity} THREAT</div>
              <div style="margin-top: 2px;">Type: ${props.type}</div>
              <div>Origin: ${props.country}</div>
            </div>
          `)
          .addTo(map.current!);
      });

      map.current.on('mouseenter', 'threats-points', () => {
        if (map.current) map.current.getCanvas().style.cursor = 'pointer';
      });
      map.current.on('mouseleave', 'threats-points', () => {
        if (map.current) map.current.getCanvas().style.cursor = '';
      });
    };

    if (map.current.isStyleLoaded()) {
      addMarkers();
    } else {
      map.current.on('load', addMarkers);
    }
  }, [threats]);

  return (
    <div className={`relative ${className || ''}`}>
      <div ref={mapContainer} className="w-full h-full rounded-b-lg" />
      {threats.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <p className="text-xs font-mono text-muted-foreground bg-background/80 px-3 py-1.5 rounded-lg">
            No threats logged yet — add a protected site to generate data
          </p>
        </div>
      )}
    </div>
  );
}
