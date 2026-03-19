import express from 'express';
const router = express.Router();

// Mock: GET /projects
router.get('/projects', (req, res) => {
  res.json([
    {
      id: "1",
      nom: "Projet mock",
      description: "Description du projet mock",
      chef_projet_id: "42",
      date_debut: "2025-09-01",
      date_fin_prevue: "2025-12-01",
      progression_percent: 0,
      statut: "planifie",
      priorite: "normale",
      chef_projet_name: "Jean Dupont",
      actions_count: 1,
      completed_actions_count: 0
    }
  ]);
});

// Mock: POST /projects
router.post('/projects', (req, res) => {
  res.status(201).json({
    id: "2",
    nom: req.body.nom || "Projet créé",
    description: req.body.description || "Description du projet créé",
    chef_projet_id: req.body.chef_projet_id || "42",
    date_debut: req.body.date_debut || "2025-09-19",
    date_fin_prevue: req.body.date_fin_prevue || "2025-12-01",
    progression_percent: 0,
    statut: req.body.statut || "planifie",
    priorite: req.body.priorite || "normale",
    chef_projet_name: req.body.chef_projet_name || "Jean Dupont",
    actions_count: 0,
    completed_actions_count: 0
  });
});

// Mock: GET /projects/:projectId/actions
router.get('/projects/:projectId/actions', (req, res) => {
  res.json([
    {
      id: "1",
      titre: "Action mock",
      description: "Description de l'action mock",
      assigned_to_profile_id: "42",
      assigned_by_profile_id: "43",
      assigned_at: "2025-09-19",
      due_date: "2025-09-30",
      statut: "todo",
      commentaire: "",
      assigned_to_name: "Jean Dupont",
      assigned_by_name: "Marie Martin"
    }
  ]);
});

// Mock: POST /projects/:projectId/actions
router.post('/projects/:projectId/actions', (req, res) => {
  res.status(201).json({
    id: "2",
    titre: req.body.titre || "Nouvelle action",
    description: req.body.description || "Description de la nouvelle action",
    assigned_to_profile_id: req.body.assigned_to_profile_id || "42",
    assigned_by_profile_id: req.body.assigned_by_profile_id || "43",
    assigned_at: "2025-09-19",
    due_date: req.body.due_date || "2025-09-30",
    statut: req.body.statut || "todo",
    commentaire: req.body.commentaire || "",
    assigned_to_name: req.body.assigned_to_name || "Jean Dupont",
    assigned_by_name: req.body.assigned_by_name || "Marie Martin"
  });
});

// Mock: DELETE /projects/:projectId/actions/:actionId
router.delete('/projects/:projectId/actions/:actionId', (req, res) => {
  res.json({ success: true });
});

// Mock: POST /actions
router.post('/actions', (req, res) => {
  res.status(201).json({
    id: "3",
    titre: req.body.titre || "Nouvelle action",
    description: req.body.description || "Description de la nouvelle action",
    assigned_to_profile_id: req.body.assigned_to_profile_id || "42",
    assigned_by_profile_id: req.body.assigned_by_profile_id || "43",
    assigned_at: "2025-09-19",
    due_date: req.body.due_date || "2025-09-30",
    statut: req.body.statut || "todo",
    commentaire: req.body.commentaire || "",
    assigned_to_name: req.body.assigned_to_name || "Jean Dupont",
    assigned_by_name: req.body.assigned_by_name || "Marie Martin"
  });
});

// Mock: PATCH /actions/:actionId/status
router.patch('/actions/:actionId/status', (req, res) => {
  res.json({ id: req.params.actionId, statut: req.body.statut });
});

// Mock: PATCH /actions/:actionId/comment
router.patch('/actions/:actionId/comment', (req, res) => {
  res.json({ id: req.params.actionId, commentaire: req.body.commentaire });
});

// Mock: DELETE /actions/:actionId
router.delete('/actions/:actionId', (req, res) => {
  res.json({ success: true });
});

export default router;