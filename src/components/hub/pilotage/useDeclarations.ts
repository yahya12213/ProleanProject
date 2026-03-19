
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
// Supabase supprimé, toute la logique doit passer par l'API Express locale

export type DeclarationsFilter = {
  startDate: string; // YYYY-MM-DD
  endDate: string;   // YYYY-MM-DD
  segmentId?: string | null; // null ou undefined => tous
};

export type DeclarationRow = {
  id: string;
  declared_at: string;
  profile_id: string;
  classe_id: string;
  segment_id: string;
  inscriptions_count: number;
  inscriptions_ratees_count: number;
};

export function useDeclarations(filter: DeclarationsFilter) {
  const { startDate, endDate, segmentId } = filter;

  const query = useQuery({
    queryKey: ["declarations_inscriptions", startDate, endDate, segmentId || "all"],
    queryFn: async () => {
  // TODO: Remplacer par appel API Express ou mock
        .from("declarations_inscriptions")
        .select("id, declared_at, profile_id, classe_id, segment_id, inscriptions_count, inscriptions_ratees_count")
        .gte("declared_at", startDate)
        .lte("declared_at", endDate);

      if (segmentId && segmentId !== "all") {
        q = q.eq("segment_id", segmentId);
      }

      const { data, error } = await q;
      if (error) throw error;
      return (data || []) as DeclarationRow[];
    },
  });

  const aggregates = useMemo(() => {
    const rows = query.data || [];
    // Totaux globaux
    const totalInscrits = rows.reduce((acc, r) => acc + (r.inscriptions_count || 0), 0);
    const totalRates = rows.reduce((acc, r) => acc + (r.inscriptions_ratees_count || 0), 0);

    // Agrégation par profil
    const byProfile = new Map<string, {
      profile_id: string;
      totalInscrits: number;
      totalRates: number;
      lastSegmentId: string | null;
      lastDeclaredAt: string | null;
    }>();

    // Agrégation par segment
    const bySegment = new Map<string, {
      segment_id: string;
      totalInscrits: number;
      totalRates: number;
    }>();

    for (const r of rows) {
      // Profiles
      const p = byProfile.get(r.profile_id) || {
        profile_id: r.profile_id,
        totalInscrits: 0,
        totalRates: 0,
        lastSegmentId: null,
        lastDeclaredAt: null,
      };
      p.totalInscrits += r.inscriptions_count || 0;
      p.totalRates += r.inscriptions_ratees_count || 0;
      if (!p.lastDeclaredAt || r.declared_at > p.lastDeclaredAt) {
        p.lastDeclaredAt = r.declared_at;
        p.lastSegmentId = r.segment_id || null;
      }
      byProfile.set(r.profile_id, p);

      // Segments
      const s = bySegment.get(r.segment_id) || {
        segment_id: r.segment_id,
        totalInscrits: 0,
        totalRates: 0,
      };
      s.totalInscrits += r.inscriptions_count || 0;
      s.totalRates += r.inscriptions_ratees_count || 0;
      bySegment.set(r.segment_id, s);
    }

    // Série temporelle (par mois)
    const byMonth = new Map<string, { label: string; inscriptions: number; rates: number }>();
    for (const r of rows) {
      const key = r.declared_at.slice(0, 7); // YYYY-MM
      const m = byMonth.get(key) || { label: key, inscriptions: 0, rates: 0 };
      m.inscriptions += r.inscriptions_count || 0;
      m.rates += r.inscriptions_ratees_count || 0;
      byMonth.set(key, m);
    }
    const timeSeries = Array.from(byMonth.values())
      .sort((a, b) => a.label.localeCompare(b.label))
      .map((v) => ({ mois: v.label, inscriptions: v.inscriptions, rates: v.rates }));

    return {
      totalInscrits,
      totalRates,
      byProfile,
      bySegment,
      timeSeries,
    };
  }, [query.data]);

  return {
    ...query,
    aggregates,
  };
}
