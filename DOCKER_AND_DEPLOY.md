
# Guide de Déploiement sur VPS avec Docker & Docker Compose

Ce document explique comment déployer l'application sur un serveur privé virtuel (VPS) en utilisant Docker pour la conteneurisation. Cela garantit un environnement d'exécution stable et reproductible.

## Prérequis sur le VPS

1.  **Docker** installé (`sudo apt-get install docker-ce`)
2.  **Docker Compose** installé (`sudo apt-get install docker-compose`)
3.  Un **serveur de base de données** PostgreSQL ou MySQL (peut aussi être lancé via Docker).

## Fichiers de Configuration Clés

-   `backend/.env`: Contient les variables d'environnement pour le backend, notamment la chaîne de connexion à la base de données (`DATABASE_URL`) et le secret JWT.
-   `docker-compose.yml`: (À créer) Orchestre le lancement des services (backend, frontend, base de données).
-   `Dockerfile`: (À créer dans `/backend`) Décrit comment construire l'image Docker pour le service backend.

## Étapes pour la Migration et le Déploiement

### 1. Centraliser la Logique dans le Backend

C'est l'étape la plus critique. L'application actuelle dépend fortement de Supabase pour l'authentification et l'accès direct aux données depuis le frontend. **Cette approche n'est pas sécurisée sur un VPS sans l'écosystème Supabase.**

-   **Refonte de l'Authentification** : Le backend doit gérer l'inscription (`/register`), la connexion (`/login`) et la validation des utilisateurs. Il doit générer un **JSON Web Token (JWT)** lors de la connexion.

-   **Création d'une API REST** : Toute la logique de lecture/écriture de la base de données qui était dans le frontend (dans les composants React, via le client Supabase) doit être déplacée vers le backend.
    -   *Exemple :* Au lieu d'appeler `supabase.from('produits').select()` dans un composant, le frontend devra faire un appel `fetch('/api/produits')` à votre backend. Le backend, lui, utilisera Prisma pour accéder à la base de données : `prisma.produits.findMany()`.

-   **Migration des Fonctions Cloud** : La logique des dossiers `supabase/functions/*` doit être recréée comme des routes API dans le backend.

### 2. Créer les Fichiers Docker

**Fichier `backend/Dockerfile` (Exemple)**

```Dockerfile
# Étape 1: Build
FROM node:18-alpine AS builder
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY . .
RUN npx prisma generate
RUN npm run build

# Étape 2: Production
FROM node:18-alpine
WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app/dist ./dist
COPY --from=builder /usr/src/app/package.json ./
# Copiez le schéma Prisma pour l'exécution des migrations en production
COPY --from=builder /usr/src/app/prisma/schema.prisma ./prisma/

EXPOSE 3000
CMD [ "node", "dist/index.js" ]
```

**Fichier `docker-compose.yml` (Exemple à la racine)**

```yaml
version: '3.8'
services:
  backend:
    build: ./backend
    container_name: mon-app-backend
    restart: always
    ports:
      - "3000:3000"
    env_file:
      - ./backend/.env
    depends_on:
      - db

  # Optionnel : Lancez votre base de données avec Docker
  db:
    image: postgres:14-alpine
    container_name: mon-app-db
    restart: always
    environment:
      POSTGRES_USER: votre_user # Doit correspondre au .env
      POSTGRES_PASSWORD: votre_mot_de_passe # Doit correspondre au .env
      POSTGRES_DB: votre_base_de_donnees # Doit correspondre au .env
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    ports:
      - "5432:5432"

volumes:
  postgres_data:
```

### 3. Lancer l'Application sur le VPS

1.  Placez vos fichiers sur le VPS (via Git, SCP, etc.).
2.  Remplissez le fichier `backend/.env` avec vos vrais identifiants.
3.  Depuis la racine du projet, lancez la commande :
    ```bash
    docker-compose up -d --build
    ```
4.  Le backend est maintenant accessible sur le port 3000.
5.  Pour le frontend, il doit être buildé en statique et servi par un serveur web comme **Nginx** qui redirigera les appels `/api/*` vers le backend.

