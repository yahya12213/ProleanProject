export interface FormationFamille {
  id: string;
  nom: string;
  livrables: FormationLivrable[];
}
export interface Student {
  id: string;
  nom: string;
  prenom: string;
  cin?: string;
  email?: string;
  telephone?: string;
  whatsapp?: string;
  date_naissance?: string;
  lieu_naissance?: string;
  adresse?: string;
  photo_url?: string;
}

export interface Inscription {
  id: string;
  numero_bon?: string | null;
  avance?: number;
  statut_compte?: string;
  statut_inscription?: string;
  classe_id?: string;
  etudiant_id: string;
  formation_id?: string;
  formations?: {
    id?: string;
    titre: string;
    prix: number;
  };
  etudiants: Student;
  paiements?: Array<{
    id: string;
    montant: number;
  }>;
  student_id_unique?: string;
}

export interface Classe {
  id: string;
  nom_classe: string;
  nombre_places: number;
  centres?: {
    nom: string;
    villes?: {
      nom_ville: string;
    };
  };
  date_debut: string;
  date_fin: string;
  formation_id?: string;
  corps_formation_id?: string;
  formations?: {
    id?: string;
    titre: string;
    prix: number;
  };
}

export interface FormationLivrable {
  id: string;
  nom: string;
  nom_modele: string;
  description: string;
}
