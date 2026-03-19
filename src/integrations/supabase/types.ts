export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.1"
  }
  public: {
    Tables: {
      api_endpoints: {
        Row: {
          blocked_today: number
          created_at: string
          id: string
          jwt_inspection: boolean
          method: string
          path: string
          rate_limited: boolean
          requests_today: number
          schema_validation: boolean
          updated_at: string
          user_id: string
        }
        Insert: {
          blocked_today?: number
          created_at?: string
          id?: string
          jwt_inspection?: boolean
          method?: string
          path: string
          rate_limited?: boolean
          requests_today?: number
          schema_validation?: boolean
          updated_at?: string
          user_id: string
        }
        Update: {
          blocked_today?: number
          created_at?: string
          id?: string
          jwt_inspection?: boolean
          method?: string
          path?: string
          rate_limited?: boolean
          requests_today?: number
          schema_validation?: boolean
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      notifications: {
        Row: {
          created_at: string
          dismissed: boolean
          id: string
          message: string
          metadata: Json | null
          read: boolean
          severity: string
          title: string
          type: string
          user_id: string
        }
        Insert: {
          created_at?: string
          dismissed?: boolean
          id?: string
          message: string
          metadata?: Json | null
          read?: boolean
          severity?: string
          title: string
          type?: string
          user_id: string
        }
        Update: {
          created_at?: string
          dismissed?: boolean
          id?: string
          message?: string
          metadata?: Json | null
          read?: boolean
          severity?: string
          title?: string
          type?: string
          user_id?: string
        }
        Relationships: []
      }
      protected_sites: {
        Row: {
          created_at: string
          id: string
          last_check: string | null
          name: string
          ssl_valid: boolean
          status: string
          threats_blocked: number
          updated_at: string
          url: string
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          last_check?: string | null
          name: string
          ssl_valid?: boolean
          status?: string
          threats_blocked?: number
          updated_at?: string
          url: string
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          last_check?: string | null
          name?: string
          ssl_valid?: boolean
          status?: string
          threats_blocked?: number
          updated_at?: string
          url?: string
          user_id?: string
        }
        Relationships: []
      }
      rate_limit_hits: {
        Row: {
          client_ip: string
          created_at: string
          id: string
          path: string
          user_id: string
        }
        Insert: {
          client_ip: string
          created_at?: string
          id?: string
          path: string
          user_id: string
        }
        Update: {
          client_ip?: string
          created_at?: string
          id?: string
          path?: string
          user_id?: string
        }
        Relationships: []
      }
      rate_limit_rules: {
        Row: {
          action: string
          created_at: string
          enabled: boolean
          id: string
          max_requests: number
          name: string
          path: string
          triggered_count: number
          updated_at: string
          user_id: string
          window_seconds: number
        }
        Insert: {
          action?: string
          created_at?: string
          enabled?: boolean
          id?: string
          max_requests?: number
          name: string
          path: string
          triggered_count?: number
          updated_at?: string
          user_id: string
          window_seconds?: number
        }
        Update: {
          action?: string
          created_at?: string
          enabled?: boolean
          id?: string
          max_requests?: number
          name?: string
          path?: string
          triggered_count?: number
          updated_at?: string
          user_id?: string
          window_seconds?: number
        }
        Relationships: []
      }
      threat_logs: {
        Row: {
          action_taken: string
          created_at: string
          details: Json | null
          id: string
          request_method: string | null
          request_path: string | null
          rule_id: string | null
          severity: string
          site_id: string | null
          source_country: string | null
          source_ip: string
          source_lat: number | null
          source_lng: number | null
          threat_type: string
          user_agent: string | null
          user_id: string
        }
        Insert: {
          action_taken?: string
          created_at?: string
          details?: Json | null
          id?: string
          request_method?: string | null
          request_path?: string | null
          rule_id?: string | null
          severity?: string
          site_id?: string | null
          source_country?: string | null
          source_ip: string
          source_lat?: number | null
          source_lng?: number | null
          threat_type: string
          user_agent?: string | null
          user_id: string
        }
        Update: {
          action_taken?: string
          created_at?: string
          details?: Json | null
          id?: string
          request_method?: string | null
          request_path?: string | null
          rule_id?: string | null
          severity?: string
          site_id?: string | null
          source_country?: string | null
          source_ip?: string
          source_lat?: number | null
          source_lng?: number | null
          threat_type?: string
          user_agent?: string | null
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "threat_logs_rule_id_fkey"
            columns: ["rule_id"]
            isOneToOne: false
            referencedRelation: "waf_rules"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "threat_logs_site_id_fkey"
            columns: ["site_id"]
            isOneToOne: false
            referencedRelation: "protected_sites"
            referencedColumns: ["id"]
          },
        ]
      }
      waf_rules: {
        Row: {
          category: string
          created_at: string
          description: string | null
          enabled: boolean
          id: string
          name: string
          pattern: string
          priority: number
          rule_type: string
          severity: string
          updated_at: string
          user_id: string
        }
        Insert: {
          category?: string
          created_at?: string
          description?: string | null
          enabled?: boolean
          id?: string
          name: string
          pattern: string
          priority?: number
          rule_type?: string
          severity?: string
          updated_at?: string
          user_id: string
        }
        Update: {
          category?: string
          created_at?: string
          description?: string | null
          enabled?: boolean
          id?: string
          name?: string
          pattern?: string
          priority?: number
          rule_type?: string
          severity?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      waf_settings: {
        Row: {
          ai_detection_enabled: boolean
          alert_email: string | null
          api_protection_enabled: boolean
          created_at: string
          default_action: string
          id: string
          paranoia_level: number
          rate_limiting_enabled: boolean
          resend_api_key: string | null
          updated_at: string
          user_id: string
          webhook_url: string | null
        }
        Insert: {
          ai_detection_enabled?: boolean
          alert_email?: string | null
          api_protection_enabled?: boolean
          created_at?: string
          default_action?: string
          id?: string
          paranoia_level?: number
          rate_limiting_enabled?: boolean
          resend_api_key?: string | null
          updated_at?: string
          user_id: string
          webhook_url?: string | null
        }
        Update: {
          ai_detection_enabled?: boolean
          alert_email?: string | null
          api_protection_enabled?: boolean
          created_at?: string
          default_action?: string
          id?: string
          paranoia_level?: number
          rate_limiting_enabled?: boolean
          resend_api_key?: string | null
          updated_at?: string
          user_id?: string
          webhook_url?: string | null
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
