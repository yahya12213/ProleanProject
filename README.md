
# Prolean

---

## Prérequis

- Node.js >= 18
- PostgreSQL >= 14

## Exemple de fichier d'environnement (backend/.env)

```env
DATABASE_URL=postgresql://USER:PASS@127.0.0.1:5432/DBNAME?schema=public
PORT=3002
JWT_SECRET=change_me_in_prod
```

## Démarrage local

```bash
cd prolean-main/backend
npx prisma generate
npx prisma migrate dev --name init # si première fois
cd ..
npm run startsite # lance front (5173) + back (3002)
```

## Endpoints clés

- Authentification :
	- POST /api/auth/register
	- POST /api/auth/login
- Formations : GET /api/formations
- FAQs : GET /api/faqs
- Paie :
	- POST /api/calculate-payroll
	- POST /api/payroll-test-engine
	- POST /api/payroll-calculate
- Admin :
	- POST /api/create-user-admin
- Documents :
	- POST /api/generate-family-documents
- Projets & Actions :
	- (mock) /projects, /actions, /projects/:id/actions

## Tests

```sh
cd backend
npm test
```

## Sécurité production

- Helmet activé
- Rate limiting
- CORS restreint
- Secrets obligatoires

## Infos complémentaires

Front : [http://localhost:5173](http://localhost:5173)
Back : [http://localhost:3002](http://localhost:3002)

## Project info

### URL du projet

[Projet Lovable](https://lovable.dev/projects/854d285c-7cd8-4b4e-9f20-2b0a01246ec0)

## How can I edit this code?

There are several ways of editing your application.

### Utiliser Lovable

Rendez-vous sur le [projet Lovable](https://lovable.dev/projects/854d285c-7cd8-4b4e-9f20-2b0a01246ec0) et commencez à prompt.
Les modifications faites via Lovable sont automatiquement commitées dans ce repo.

### Utiliser votre IDE préféré

git clone <YOUR_GIT_URL>
cd <YOUR_PROJECT_NAME>
npm i
npm run dev
Clonez le repo et poussez vos changements. Ils seront aussi visibles dans Lovable.
Le seul prérequis est d'avoir Node.js & npm installés ([installer avec nvm](https://github.com/nvm-sh/nvm#installing-and-updating)).

#### Étapes :

```bash
# 1. Cloner le repo
git clone <YOUR_GIT_URL>
# 2. Aller dans le dossier du projet
cd <YOUR_PROJECT_NAME>
# 3. Installer les dépendances
npm i
# 4. Démarrer le serveur de dev
npm run dev
```

### Modifier un fichier sur GitHub

1. Naviguez vers le fichier souhaité.
2. Cliquez sur le bouton "Edit" (icône crayon).
3. Faites vos modifications et validez.

### Utiliser GitHub Codespaces

1. Allez sur la page principale du repo.
2. Cliquez sur le bouton "Code" (vert).
3. Sélectionnez l'onglet "Codespaces".
4. Cliquez sur "New codespace" pour lancer l'environnement.
5. Modifiez les fichiers et poussez vos changements.

## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS

## How can I deploy this project?

Simply open [Lovable](https://lovable.dev/projects/854d285c-7cd8-4b4e-9f20-2b0a01246ec0) and click on Share -> Publish.

## Can I connect a custom domain to my Lovable project?

Yes, you can!

To connect a domain, navigate to Project > Settings > Domains and click Connect Domain.

Read more here: [Setting up a custom domain](https://docs.lovable.dev/tips-tricks/custom-domain#step-by-step-guide)
