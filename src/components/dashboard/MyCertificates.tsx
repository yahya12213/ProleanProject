import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Award, Download, Share2, Search, Filter, Calendar, CheckCircle, Clock } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

export const MyCertificates = () => {
  const { toast } = useToast();
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');

  const certificates = [
    {
      id: 1,
      titre: "Project Management Professional (PMP)",
      formation: "Project Management Professional",
      organisme: "PMI",
      dateObtention: "2024-01-15",
      dateExpiration: "2027-01-15",
      statut: "valide",
      score: 85,
      creditsProfessionnels: 35,
      numeroSerie: "PMP-2024-001234",
      image: "/api/placeholder/400/300",
      competences: ["Gestion de projet", "Leadership", "Planification", "Gestion des risques"]
    },
    {
      id: 2,
      titre: "Digital Marketing Strategy Certification",
      formation: "Digital Marketing Strategy",
      organisme: "PROLEAN Formation",
      dateObtention: "2024-01-20",
      dateExpiration: null,
      statut: "valide",
      score: 92,
      creditsProfessionnels: 20,
      numeroSerie: "DMS-2024-005678",
      image: "/api/placeholder/400/300",
      competences: ["Marketing digital", "SEO/SEM", "Réseaux sociaux", "Analytics"]
    },
    {
      id: 3,
      titre: "Leadership & Communication Certificate",
      formation: "Leadership & Communication",
      organisme: "PROLEAN Formation",
      dateObtention: "2023-12-30",
      dateExpiration: null,
      statut: "valide",
      score: 88,
      creditsProfessionnels: 25,
      numeroSerie: "LDC-2023-009876",
      image: "/api/placeholder/400/300",
      competences: ["Leadership", "Communication", "Gestion d'équipe", "Négociation"]
    },
    {
      id: 4,
      titre: "Data Analysis Fundamentals",
      formation: "Data Analysis & Visualization",
      organisme: "PROLEAN Formation",
      dateObtention: "2023-11-15",
      dateExpiration: "2025-11-15",
      statut: "expire_bientot",
      score: 79,
      creditsProfessionnels: 30,
      numeroSerie: "DAF-2023-012345",
      image: "/api/placeholder/400/300",
      competences: ["Analyse de données", "Python", "Statistiques", "Visualization"]
    },
    {
      id: 5,
      titre: "Agile Project Management",
      formation: "Agile & Scrum Methodology",
      organisme: "Scrum Alliance",
      dateObtention: "2023-08-10",
      dateExpiration: "2025-08-10",
      statut: "valide",
      score: 90,
      creditsProfessionnels: 40,
      numeroSerie: "APM-2023-567890",
      image: "/api/placeholder/400/300",
      competences: ["Agile", "Scrum", "Kanban", "Product Management"]
    }
  ];

  const getStatusBadge = (statut: string) => {
    switch (statut) {
      case 'valide':
        return <Badge className="bg-green-500"><CheckCircle className="h-3 w-3 mr-1" />Valide</Badge>;
      case 'expire_bientot':
        return <Badge variant="destructive"><Clock className="h-3 w-3 mr-1" />Expire bientôt</Badge>;
      case 'expire':
        return <Badge variant="secondary">Expiré</Badge>;
      default:
        return <Badge variant="outline">{statut}</Badge>;
    }
  };

  const handleDownload = (certificateId: number) => {
    toast({
      title: "Téléchargement en cours",
      description: "Votre certificat est en cours de téléchargement...",
    });
  };

  const handleShare = (certificateId: number) => {
    navigator.clipboard.writeText(`https://prolean.com/certificate/${certificateId}`);
    toast({
      title: "Lien copié",
      description: "Le lien de partage a été copié dans le presse-papiers.",
    });
  };

  const filteredCertificates = certificates.filter(cert => {
    const matchesSearch = cert.titre.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         cert.formation.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         cert.organisme.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesFilter = filterStatus === 'all' || cert.statut === filterStatus;
    
    return matchesSearch && matchesFilter;
  });

  const validCertificates = certificates.filter(c => c.statut === 'valide').length;
  const expiringCertificates = certificates.filter(c => c.statut === 'expire_bientot').length;
  const totalCredits = certificates.reduce((sum, cert) => sum + cert.creditsProfessionnels, 0);

  return (
    <div className="space-y-6">
      {/* Statistiques */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Certificats valides</p>
                <p className="text-2xl font-bold text-green-600">{validCertificates}</p>
              </div>
              <Award className="h-8 w-8 text-green-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Expiration proche</p>
                <p className="text-2xl font-bold text-orange-600">{expiringCertificates}</p>
              </div>
              <Clock className="h-8 w-8 text-orange-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Crédits professionnels</p>
                <p className="text-2xl font-bold text-blue-600">{totalCredits}</p>
              </div>
              <CheckCircle className="h-8 w-8 text-blue-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filtres et recherche */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Rechercher un certificat..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>
        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="w-full sm:w-48">
            <SelectValue placeholder="Filtrer par statut" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Tous les statuts</SelectItem>
            <SelectItem value="valide">Valides</SelectItem>
            <SelectItem value="expire_bientot">Expiration proche</SelectItem>
            <SelectItem value="expire">Expirés</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Liste des certificats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {filteredCertificates.map((certificate) => (
          <Card key={certificate.id} className="hover:shadow-lg transition-shadow">
            <CardHeader>
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <CardTitle className="text-lg mb-2">{certificate.titre}</CardTitle>
                  <p className="text-sm text-muted-foreground mb-2">{certificate.formation}</p>
                  <p className="text-sm font-medium text-primary">{certificate.organisme}</p>
                </div>
                {getStatusBadge(certificate.statut)}
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Informations principales */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-muted-foreground">Date d'obtention</p>
                  <p className="font-medium">
                    {new Date(certificate.dateObtention).toLocaleDateString('fr-FR')}
                  </p>
                </div>
                <div>
                  <p className="text-muted-foreground">Score obtenu</p>
                  <p className="font-medium text-green-600">{certificate.score}%</p>
                </div>
              </div>

              {certificate.dateExpiration && (
                <div className="text-sm">
                  <p className="text-muted-foreground">Date d'expiration</p>
                  <p className="font-medium">
                    {new Date(certificate.dateExpiration).toLocaleDateString('fr-FR')}
                  </p>
                </div>
              )}

              <div className="text-sm">
                <p className="text-muted-foreground mb-1">Crédits professionnels</p>
                <Badge variant="outline">{certificate.creditsProfessionnels} points</Badge>
              </div>

              {/* Compétences */}
              <div>
                <p className="text-sm text-muted-foreground mb-2">Compétences validées</p>
                <div className="flex flex-wrap gap-1">
                  {certificate.competences.map((competence, index) => (
                    <Badge key={index} variant="secondary" className="text-xs">
                      {competence}
                    </Badge>
                  ))}
                </div>
              </div>

              {/* Numéro de série */}
              <div className="text-xs text-muted-foreground border-t pt-3">
                N° de série: {certificate.numeroSerie}
              </div>

              {/* Actions */}
              <div className="flex gap-2 pt-2">
                <Button 
                  size="sm" 
                  onClick={() => handleDownload(certificate.id)}
                  className="flex-1"
                >
                  <Download className="h-4 w-4 mr-2" />
                  Télécharger
                </Button>
                <Button 
                  variant="outline" 
                  size="sm"
                  onClick={() => handleShare(certificate.id)}
                >
                  <Share2 className="h-4 w-4 mr-2" />
                  Partager
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {filteredCertificates.length === 0 && (
        <div className="text-center py-12">
          <Award className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-lg font-medium mb-2">Aucun certificat trouvé</h3>
          <p className="text-muted-foreground">
            {searchTerm || filterStatus !== 'all' 
              ? "Aucun certificat ne correspond à vos critères de recherche."
              : "Vous n'avez pas encore obtenu de certificat. Terminez vos formations pour en obtenir."
            }
          </p>
        </div>
      )}
    </div>
  );
};