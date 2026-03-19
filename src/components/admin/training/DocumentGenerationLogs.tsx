import React, { useState, useEffect } from 'react';
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { RefreshCw, Download, Search, Calendar, User, FileText } from "lucide-react";
import { toast } from "@/hooks/use-toast";

interface DocumentLog {
  id: string;
  etudiant_id: string;
  formation_id: string;
  famille_type: string;
  modele_id: string;
  modele_nom: string;
  status: 'started' | 'success' | 'failed' | 'not_found';
  error_message: string;
  file_path: string;
  file_name: string;
  execution_time_ms: number;
  metadata: any;
  created_at: string;
  updated_at: string;
  // Relations
  etudiants?: {
    nom: string;
    prenom: string;
  };
  formations?: {
    titre: string;
  };
}

export function DocumentGenerationLogs() {
  const [logs, setLogs] = useState<DocumentLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [familleFilter, setFamilleFilter] = useState('all');
  const [dateFilter, setDateFilter] = useState('today');

  const fetchLogs = async () => {
    try {
      setLoading(true);
      
      let query = supabase
        .from('document_generation_logs')
        .select(`
          *,
          etudiants:etudiant_id(nom, prenom),
          formations:formation_id(titre)
        `)
        .order('created_at', { ascending: false });

      // Filtres
      if (statusFilter !== 'all') {
        query = query.eq('status', statusFilter);
      }

      if (familleFilter !== 'all') {
        query = query.eq('famille_type', familleFilter);
      }

      // Filtre par date
      if (dateFilter === 'today') {
        const today = new Date().toISOString().split('T')[0];
        query = query.gte('created_at', today);
      } else if (dateFilter === 'week') {
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        query = query.gte('created_at', weekAgo.toISOString());
      }

      const { data, error } = await query.limit(100);

      if (error) throw error;

      setLogs((data as DocumentLog[]) || []);
    } catch (error: any) {
      console.error('Erreur lors du chargement des logs:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les logs de génération",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [statusFilter, familleFilter, dateFilter]);

  const filteredLogs = logs.filter(log => {
    const searchLower = searchTerm.toLowerCase();
    return (
      log.modele_nom?.toLowerCase().includes(searchLower) ||
      log.etudiants?.nom?.toLowerCase().includes(searchLower) ||
      log.etudiants?.prenom?.toLowerCase().includes(searchLower) ||
      log.famille_type?.toLowerCase().includes(searchLower) ||
      log.error_message?.toLowerCase().includes(searchLower)
    );
  });

  const getStatusBadge = (status: string) => {
    const variants = {
      success: 'default',
      failed: 'destructive',
      started: 'secondary',
      not_found: 'outline'
    } as const;

    const labels = {
      success: 'Succès',
      failed: 'Échec',
      started: 'Démarré',
      not_found: 'Non trouvé'
    };

    return (
      <Badge variant={variants[status as keyof typeof variants] || 'outline'}>
        {labels[status as keyof typeof labels] || status}
      </Badge>
    );
  };

  const downloadFile = async (filePath: string, fileName: string) => {
    try {
      const { data, error } = await supabase.storage
        .from('generated-documents')
        .download(filePath);

      if (error) throw error;

      const url = URL.createObjectURL(data);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast({
        title: "Téléchargement",
        description: `Fichier ${fileName} téléchargé avec succès`
      });
    } catch (error: any) {
      console.error('Erreur téléchargement:', error);
      toast({
        title: "Erreur",
        description: `Impossible de télécharger ${fileName}`,
        variant: "destructive"
      });
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Logs de Génération de Documents
          </CardTitle>
          <Button onClick={fetchLogs} disabled={loading} size="sm">
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Actualiser
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {/* Filtres */}
        <div className="flex flex-wrap gap-4 mb-6">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4" />
            <Input
              placeholder="Rechercher..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-64"
            />
          </div>

          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Statut" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous les statuts</SelectItem>
              <SelectItem value="success">Succès</SelectItem>
              <SelectItem value="failed">Échec</SelectItem>
              <SelectItem value="started">Démarré</SelectItem>
              <SelectItem value="not_found">Non trouvé</SelectItem>
            </SelectContent>
          </Select>

          <Select value={familleFilter} onValueChange={setFamilleFilter}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous les types</SelectItem>
              <SelectItem value="badge">Badge</SelectItem>
              <SelectItem value="certificat">Certificat</SelectItem>
              <SelectItem value="attestation">Attestation</SelectItem>
              <SelectItem value="convention">Convention</SelectItem>
            </SelectContent>
          </Select>

          <Select value={dateFilter} onValueChange={setDateFilter}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Période" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="today">Aujourd'hui</SelectItem>
              <SelectItem value="week">Cette semaine</SelectItem>
              <SelectItem value="all">Toutes les dates</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Statistiques rapides */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-green-600">
                {logs.filter(l => l.status === 'success').length}
              </div>
              <div className="text-sm text-muted-foreground">Succès</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-red-600">
                {logs.filter(l => l.status === 'failed').length}
              </div>
              <div className="text-sm text-muted-foreground">Échecs</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-orange-600">
                {logs.filter(l => l.status === 'not_found').length}
              </div>
              <div className="text-sm text-muted-foreground">Non trouvés</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold">
                {logs.length}
              </div>
              <div className="text-sm text-muted-foreground">Total</div>
            </CardContent>
          </Card>
        </div>

        {/* Table des logs */}
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Date</TableHead>
                <TableHead>Étudiant</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Modèle</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead>Erreur</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredLogs.map((log) => (
                <TableRow key={log.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Calendar className="h-4 w-4" />
                      {new Date(log.created_at).toLocaleString('fr-FR')}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <User className="h-4 w-4" />
                      {log.etudiants ? 
                        `${log.etudiants.nom} ${log.etudiants.prenom}` : 
                        'Étudiant inconnu'
                      }
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{log.famille_type}</Badge>
                  </TableCell>
                  <TableCell>{log.modele_nom || 'N/A'}</TableCell>
                  <TableCell>{getStatusBadge(log.status)}</TableCell>
                  <TableCell>
                    {log.error_message && (
                      <div className="max-w-xs truncate text-red-600 text-sm">
                        {log.error_message}
                      </div>
                    )}
                  </TableCell>
                  <TableCell>
                    {log.status === 'success' && log.file_path && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => downloadFile(log.file_path, log.file_name)}
                      >
                        <Download className="h-4 w-4" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        {filteredLogs.length === 0 && !loading && (
          <div className="text-center py-8 text-muted-foreground">
            Aucun log trouvé pour les critères sélectionnés
          </div>
        )}
      </CardContent>
    </Card>
  );
}