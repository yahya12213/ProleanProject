# Documentation du Système de Génération de Documents

## Vue d'ensemble du système

Le système de génération de documents permet de créer automatiquement des documents PDF personnalisés pour les étudiants en formation. Il est composé de plusieurs couches interconnectées.

## Architecture du système

### Flux de données principal
```
ÉTUDIANT (statut="valide") 
→ INSCRIPTION (statut_compte="valide") 
→ FORMATION (via inscription.formation_id)
→ CORPS DE FORMATION (via classes.corps_formation_id)
→ FAMILLES DE DOCUMENTS (via corps_formation_familles)
→ MODÈLES DE DOCUMENTS (via formation_modeles)
→ GÉNÉRATION PDF
→ COMBINAISON PDF FINALE
```

### Composants principaux

#### 1. Base de données - Tables essentielles

**etudiants**
- Informations personnelles des étudiants
- Champs critiques: `nom`, `prenom`, `email`, `cin`, `statut`

**inscriptions** 
- Lien étudiant ↔ formation
- Champs critiques: `etudiant_id`, `formation_id`, `classe_id`, `statut_compte`, `statut_inscription`

**formations**
- Définition des formations disponibles
- Champs critiques: `id`, `titre`, `corps_formation_id`

**corps_formation_familles**
- Familles de documents par corps de formation
- Champs critiques: `corps_formation_id`, `famille_nom`

**modeles_documents**
- Templates des documents PDF
- Champs critiques: `id`, `nom_modele`, `famille`, `image_recto_url`, `image_verso_url`

**formation_modeles**
- Association formation ↔ modèles de documents
- Champs critiques: `formation_id`, `modele_id`, `famille_context_id`

#### 2. Fonctions de base de données

**validate_student_for_document_generation(p_etudiant_id)**
```sql
-- Valide l'éligibilité d'un étudiant pour la génération de documents
-- Retourne: is_eligible, formation_id, formation_titre, corps_formation_nom, statut_compte
```

**get_formation_modeles_by_famille(p_formation_id, p_famille_nom)**
```sql
-- Récupère les modèles de documents pour une formation et famille données
-- Gère automatiquement la déduplication et les jointures complexes
-- Retourne: modeles_documents avec toutes les informations nécessaires
```

#### 3. Edge Functions

**generate-pdf**
- Génère un PDF individuel à partir d'un modèle et des données étudiant
- Paramètres: `etudiant_id`, `modele_id`
- Retourne: `success`, `fileName`, `filePath`

**generate-family-documents** 
- Génère tous les documents d'une famille pour un étudiant
- Utilise `get_formation_modeles_by_famille` pour optimiser les requêtes
- Combine automatiquement les PDFs générés
- Paramètres: `etudiant_id`, `famille`, `modele_ids` (optionnel)

**generate-family-documents-batch**
- Version batch pour générer des documents pour plusieurs étudiants
- Utilise la même logique optimisée que la version simple
- Paramètres: `etudiant_ids[]`, `famille`, `modele_ids` (optionnel)

#### 4. Interface utilisateur

**DocumentGenerationHub**
- Interface principale avec onglets
- Système amélioré + Tests + Ancien système

**GenerationDocumentsImproved**
- Interface utilisateur moderne
- Sélection étudiant → validation → choix famille → génération

**TestDocumentGeneration**
- Tests automatisés complets
- Validation de toutes les couches du système

## Logique de validation

### Étapes de validation d'un étudiant

1. **Existence de l'étudiant** dans la table `etudiants`
2. **Inscription active** avec `statut_compte = 'valide'`
3. **Formation associée** via `inscription.formation_id`
4. **Corps de formation** déterminé via la classe ou formation
5. **Modèles disponibles** pour la famille demandée

### Conditions d'éligibilité

```sql
-- Un étudiant est éligible si :
- statut_compte = 'valide'
- inscription.formation_id IS NOT NULL
- formation EXISTS et is_active = true
- Au moins un modèle actif existe pour la famille demandée
```

## Gestion des erreurs

### Erreurs courantes et solutions

**"Aucune inscription trouvée"**
- Vérifier que l'étudiant a une inscription dans la table `inscriptions`
- Vérifier que `statut_inscription` n'est pas 'annulee'

**"Statut compte non valide"**
- L'étudiant doit avoir `statut_compte = 'valide'`
- Mettre à jour le statut si nécessaire

**"Aucun modèle trouvé pour la famille"**
- Vérifier que des modèles existent dans `modeles_documents` avec `famille = 'xxx'`
- Vérifier les associations dans `formation_modeles`
- Vérifier que `is_active = true` sur tous les éléments

**"Erreur de génération PDF"**
- Vérifier que les images des modèles sont accessibles
- Vérifier les permissions du stockage local
- Contrôler les logs des API Express

### Debugging

**Logs des API Express**
```
API Express > Logs > [nom-fonction]
```

**Requête de debug pour un étudiant**
```sql
SELECT 
    e.nom, e.prenom, e.id as etudiant_id,
    i.statut_compte, i.statut_inscription,
    f.titre as formation_titre, f.id as formation_id,
    cf.nom as corps_formation_nom
FROM inscriptions i
JOIN etudiants e ON e.id = i.etudiant_id
LEFT JOIN formations f ON f.id = i.formation_id
LEFT JOIN corps_formation cf ON cf.id = f.corps_formation_id
WHERE e.id = 'ETUDIANT_ID_ICI';
```

## Configuration et déploiement

### Variables d'environnement requises
```
DATABASE_URL=postgresql://[user]:[password]@[host]:[port]/[database]
```

### Permissions RLS

Les API Express utilisent des clés sécurisées pour bypasser RLS.
Pour l'interface utilisateur, s'assurer que l'utilisateur connecté a les permissions appropriées.

### Stockage local

**Dossier: `generated-documents`**
- Politique de lecture publique pour les documents générés
- Structure: `[type]/[date]/[filename]`
- Exemple: `badges/2024-01-15/badge_etudiant_123_20240115.pdf`

## Tests et validation

### Tests unitaires disponibles

1. **Test de validation étudiant**
   - Fonction: `validate_student_for_document_generation`
   - Vérifie l'éligibilité complète

2. **Test de récupération modèles**
   - Fonction: `get_formation_modeles_by_famille`
   - Vérifie les associations et la déduplication

3. **Test de génération simple**
   - API Express: `generate-family-documents`
   - Test complet étudiant → documents

4. **Test de génération batch**
   - API Express: `generate-family-documents-batch`
   - Test multi-étudiants

### Comment lancer les tests

1. Aller dans **Administration > Gestion Classes > Génération de Documents**
2. Onglet **"Tests Complets"**
3. Sélectionner un étudiant éligible
4. Cliquer sur **"Lancer tous les tests"**

## Maintenance et évolution

### Ajout d'une nouvelle famille de documents

1. **Créer les modèles** dans `modeles_documents`
   ```sql
   INSERT INTO modeles_documents (nom_modele, famille, image_recto_url, ...)
   VALUES ('Nouveau modèle', 'nouvelle_famille', 'url_image', ...);
   ```

2. **Associer à un corps de formation**
   ```sql
   INSERT INTO corps_formation_familles (corps_formation_id, famille_nom)
   VALUES ('corps_id', 'nouvelle_famille');
   ```

3. **Lier aux formations**
   ```sql
   INSERT INTO formation_modeles (formation_id, modele_id, famille_context_id)
   VALUES ('formation_id', 'modele_id', 'famille_context_id');
   ```

### Modification des modèles existants

- Les modèles peuvent être mis à jour sans redéploiement
- Changer `is_active = false` pour désactiver temporairement
- Les nouvelles images prennent effet immédiatement

### Surveillance du système

**Métriques à surveiller :**
- Taux de réussite des générations de documents
- Temps de réponse des API Express
- Erreurs dans les logs
- Espace de stockage utilisé

**Points de contrôle réguliers :**
- Vérifier l'intégrité des associations formation ↔ modèles
- Contrôler les doublons potentiels dans `formation_modeles`
- Valider que tous les modèles actifs ont des images accessibles

## Historique des versions

### Version 1.0 (Système amélioré - Date actuelle)
- ✅ Fonction `validate_student_for_document_generation`
- ✅ Fonction `get_formation_modeles_by_famille` 
- ✅ Edge function `generate-family-documents` optimisée
- ✅ Edge function `generate-family-documents-batch` corrigée
- ✅ Interface utilisateur complète avec tests
- ✅ Documentation système complète

### Corrections apportées
- **Problème :** Fonction batch utilisait ancienne logique de requêtes
- **Solution :** Migration vers `get_formation_modeles_by_famille`
- **Problème :** Références incorrectes dans les edge functions  
- **Solution :** Harmonisation des structures de données
- **Problème :** Doublons dans les modèles badge CAF
- **Solution :** Déduplication automatique dans les fonctions DB

---

**Note importante :** Cette documentation doit être mise à jour à chaque modification majeure du système. Elle sert de référence pour la maintenance et la restauration en cas de problème.