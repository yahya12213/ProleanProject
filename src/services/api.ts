// Délier une action d'un projet
export const unlinkActionFromProject = async (projectId, actionId) => {
  const response = await apiClient.delete(`/projects/${projectId}/actions/${actionId}`);
  return response.data;
};
// Lier une action à un projet
export const linkActionToProject = async (projectId, actionId) => {
  const response = await apiClient.post(`/projects/${projectId}/actions`, { actionId });
  return response.data;
};
// Créer un projet
export const createProject = async (projectData) => {
  const response = await apiClient.post('/projects', projectData);
  return response.data;
};
// Actions liées à un projet
export const getProjectActions = async (projectId) => {
  const response = await apiClient.get(`/projects/${projectId}/actions`);
  return response.data;
};
// Créer une action
export const createAction = async (actionData) => {
  const response = await apiClient.post('/actions', actionData);
  return response.data;
};

// Mettre à jour le statut d'une action
export const updateActionStatus = async (actionId, statut) => {
  const response = await apiClient.patch(`/actions/${actionId}/status`, { statut });
  return response.data;
};

// Mettre à jour le commentaire d'une action
export const updateActionComment = async (actionId, commentaire) => {
  const response = await apiClient.patch(`/actions/${actionId}/comment`, { commentaire });
  return response.data;
};

// Supprimer une action
export const deleteAction = async (actionId) => {
  const response = await apiClient.delete(`/actions/${actionId}`);
  return response.data;
};
// Projets
export const getProjects = async () => {
  const response = await apiClient.get('/projects');
  return response.data;
};

import axios from 'axios';

// Prend l'URL depuis l'env, fallback local si absent
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3002/api';

/**
 * Instance Axios pour les appels à l'API.
 */
const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Intercepteur pour ajouter le token JWT aux requêtes.
 */
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('authToken');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// --- Fonctions du Service API ---

// Auth
export const login = (email, password) => apiClient.post('/auth/login', { email, password });
export const register = (email, password) => apiClient.post('/auth/register', { email, password });

// Data
export const getFormations = () => apiClient.get('/formations');
export const getFaqs = () => apiClient.get('/faqs');

// Actions
export const getActions = async () => {
  const response = await apiClient.get('/actions');
  return response.data;
};

// Profils
export const getProfiles = async () => {
  const response = await apiClient.get('/profiles');
  return response.data;
};

export default {
  login,
  register,
  getFormations,
  getFaqs,
  getActions,
  getProfiles,
  getProjects,
  createProject,
  createAction,
  updateActionStatus,
  updateActionComment,
  deleteAction,
  getProjectActions,
  linkActionToProject,
  unlinkActionFromProject,
};
