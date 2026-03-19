import { useMemo, useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { TrendingUp, Euro, Users, Calendar } from "lucide-react";
import { useDeclarations } from "./pilotage/useDeclarations";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "../../lib/supabaseClient"; // Ajout de l'importation de supabase
// Supabase supprimé, toute la logique doit passer par l'API Express locale
import DeclarationDialog from "./pilotage/DeclarationDialog";
import RankingsTable, { RankingRow } from "./pilotage/RankingsTable";

// Remplacement de `any` par des types spécifiques
const profilesMap = new Map<string, Profile>();
const segmentsMap = new Map<string, Segment>();

// Exemple de typage pour les profils et segments
interface Profile {
  id: string;
  nom: string;
  prenom: string;
  photo_url?: string;
}

interface Segment {
  id: string;
  nom: string;
  logo_url?: string;
  couleur?: string;
}

// Remplacement des types `any` restants
const mapProfiles = (data: Profile[]) => {
  const map = new Map<string, Profile>();
  data.forEach((p) => map.set(p.id, p));
  return map;
};

const mapSegments = (data: Segment[]) => {
  const map = new Map<string, Segment>();
  data.forEach((s) => map.set(s.id, s));
  return map;
};

export function PilotageCommercial() {
  // Filtres
  const [selectedPeriod, setSelectedPeriod] = useState<"week" | "month" | "range">("month");
  const [selectedSegmentId, setSelectedSegmentId] = useState<string>("all");
  const [startDate, setStartDate] = useState<string>(() => new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().slice(0,10));
  const [endDate, setEndDate] = useState<string>(() => new Date().toISOString().slice(0,10));

  // Charger segments pour le filtre
  const { data: segments } = useQuery({
    queryKey: ["segments"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("segments")
        .select("id, nom, logo_url, couleur")
        .order("nom", { ascending: true });

      if (error) throw error;
      return data || [];
    },
  });

  // Mettre à jour dates selon période
  useEffect(() => {
    const now = new Date();
    if (selectedPeriod === "month") {
      const first = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0,10);
      const last = new Date().toISOString().slice(0,10);
      setStartDate(first);
      setEndDate(last);
    } else if (selectedPeriod === "week") {
      const day = now.getDay(); // 0 dim ... 6 sam
      const diffToMonday = (day === 0 ? -6 : 1 - day);
      const monday = new Date(now);
      monday.setDate(now.getDate() + diffToMonday);
      const sunday = new Date(monday);
      sunday.setDate(monday.getDate() + 6);
      setStartDate(monday.toISOString().slice(0,10));
      setEndDate(sunday.toISOString().slice(0,10));
    }
    // "range": laisse l'utilisateur gérer
  }, [selectedPeriod]);

  const { data: declarations, aggregates, isLoading } = useDeclarations({
    startDate,
    endDate,
    segmentId: selectedSegmentId === "all" ? null : selectedSegmentId,
  });

  // Metrics simples depuis les déclarations
  const metrics = useMemo(() => {
    return [
      { label: "Inscriptions", value: aggregates.totalInscrits.toString(), change: "", icon: Users, color: "text-green-600" },
      { label: "Inscrits ratés", value: aggregates.totalRates.toString(), change: "", icon: Calendar, color: "text-red-600" },
      { label: "Période", value: `${startDate} → ${endDate}`, change: "", icon: TrendingUp, color: "text-blue-600" },
      { label: "Segments filtrés", value: selectedSegmentId === "all" ? "Tous" : (segments || []).find((s:any) => s.id === selectedSegmentId)?.nom || "", change: "", icon: Euro, color: "text-purple-600" },
    ];
  }, [aggregates, startDate, endDate, selectedSegmentId, segments]);

  // Correction de la fonction queryFn pour charger les profils
  const { data: profilesMapData } = useQuery({
    queryKey: ["profiles", aggregates.byProfile.size],
    queryFn: async () => {
      const profileIds = Array.from(aggregates.byProfile.keys());
      if (profileIds.length === 0) return new Map<string, any>();

      const { data, error } = await supabase
        .from("profiles")
        .select("id, nom, prenom, photo_url")
        .in("id", profileIds);

      if (error) throw error;
      const map = new Map<string, any>();
      (data || []).forEach((p: any) => map.set(p.id, p));
      return map;
    },
    enabled: !!declarations && declarations.length > 0,
  });

  // Correction de la fonction queryFn pour charger les segments
  const { data: segmentsMapData } = useQuery({
    queryKey: ["segments-for-ranking", declarations?.length || 0],
    queryFn: async () => {
      const segIds = Array.from(aggregates.byProfile.values())
        .map((v) => v.lastSegmentId)
        .filter(Boolean) as string[];
      const unique = Array.from(new Set(segIds));
      if (unique.length === 0) return new Map<string, any>();

      const { data, error } = await supabase
        .from("segments")
        .select("id, nom, logo_url")
        .in("id", unique);

      if (error) throw error;
      const map = new Map<string, any>();
      (data || []).forEach((s: any) => map.set(s.id, s));
      return map;
    },
    enabled: !!declarations && declarations.length > 0,
  });

  // Remplacement des types `any` dans les fonctions de mappage et les composants
  const rankingRows: RankingRow[] = useMemo(() => {
    const list = Array.from(aggregates.byProfile.values())
      .map((v) => {
        const p = profilesMap.get(v.profile_id);
        const seg = segmentsMap.get(v.lastSegmentId || "");
        const fullName = p ? `${p.prenom || ""} ${p.nom || ""}`.trim() : v.profile_id;
        return {
          ...v,
          fullName,
          segmentName: seg?.nom || "",
        };
      });
    return list;
  }, [aggregates.byProfile]);

  // Données pour charts
  const chartData = useMemo(() => aggregates.timeSeries, [aggregates.timeSeries]);

  const segmentData = useMemo(() => {
    const rows = Array.from(aggregates.bySegment.values());
    return rows.map((r) => {
      const seg = (segments || []).find((s:any) => s.id === r.segment_id);
      return {
        name: seg?.nom || r.segment_id,
        value: r.totalInscrits,
        color: seg?.couleur || "#60a5fa",
      };
    });
  }, [aggregates.bySegment, segments]);

  return (
    <div className="space-y-6">
      {/* Métriques principales */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {metrics.map((metric, index) => (
          <Card key={index}>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">{metric.label}</p>
                  <p className="text-2xl font-bold">{metric.value}</p>
                  {metric.change ? <p className={`text-sm ${metric.color}`}>{metric.change}</p> : null}
                </div>
                <metric.icon className={`h-8 w-8 ${metric.color}`} />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Filtres et actions */}
      <div className="flex flex-col sm:flex-row gap-4 items-center justify-between">
        <div className="flex flex-wrap gap-4 items-end">
          <div>
            <Label>Période</Label>
            <Select value={selectedPeriod} onValueChange={(v: "week" | "month" | "range") => setSelectedPeriod(v)}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Période" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="week">Cette semaine</SelectItem>
                <SelectItem value="month">Ce mois</SelectItem>
                <SelectItem value="range">Plage de dates</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {selectedPeriod === "range" && (
            <div className="flex gap-2">
              <div>
                <Label>Du</Label>
                <Input type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} className="w-40" />
              </div>
              <div>
                <Label>Au</Label>
                <Input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} className="w-40" />
              </div>
            </div>
          )}

          <div>
            <Label>Segment</Label>
            <Select value={selectedSegmentId} onValueChange={setSelectedSegmentId}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="Tous les segments" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Tous les segments</SelectItem>
                {(segments || []).map((s: Segment) => (
                  <SelectItem key={s.id} value={s.id}>{s.nom}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <DeclarationDialog />
      </div>

      <Tabs defaultValue="classement" className="space-y-4">
        <TabsList>
          <TabsTrigger value="classement">Classement</TabsTrigger>
          <TabsTrigger value="evolution">Évolution</TabsTrigger>
          <TabsTrigger value="segments">Par Segment</TabsTrigger>
        </TabsList>

        <TabsContent value="classement">
          <Card>
            <CardHeader>
              <CardTitle>Classement des Assistants</CardTitle>
              <CardDescription>Basé sur les déclarations d'inscrits sur la période sélectionnée</CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="text-sm text-muted-foreground">Chargement…</div>
              ) : rankingRows.length === 0 ? (
                <div className="text-sm text-muted-foreground">Aucune donnée pour la période sélectionnée.</div>
              ) : (
                <RankingsTable rows={rankingRows} />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="evolution">
          <Card>
            <CardHeader>
              <CardTitle>Évolution</CardTitle>
              <CardDescription>Inscriptions et inscrits ratés sur la période</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <BarChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="mois" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="inscriptions" fill="#60a5fa" name="Inscriptions" />
                  <Bar dataKey="rates" fill="#f87171" name="Inscrits ratés" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="segments">
          <Card>
            <CardHeader>
              <CardTitle>Répartition par Segment</CardTitle>
              <CardDescription>Distribution des inscrits par segment</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <PieChart>
                  <Pie
                    data={segmentData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, value }) => `${name}: ${value}`}
                    outerRadius={150}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {segmentData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
