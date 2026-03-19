// Délier une action d'un projet
export const unlinkActionFromProject = async (projectId: string, actionId: string) => {
  try {
    const response = await api.unlinkActionFromProject(projectId, actionId);
    return response;
  } catch (error) {
    console.error("Erreur lors de la déliaison action-projet:", error);
    throw error;
  }
};
// Lier une action à un projet
export const linkActionToProject = async (projectId: string, actionId: string) => {
  try {
    const response = await api.linkActionToProject(projectId, actionId);
    return response;
  } catch (error) {
    console.error("Erreur lors de la liaison action-projet:", error);
    throw error;
  }
};
// Créer un projet
export const createProject = async (projectData: Project): Promise<Project> => {
  try {
    const response = await api.createProject(projectData);
    return response;
  } catch (error) {
    console.error("Erreur lors de la création du projet:", error);
    throw error;
  }
};
// ...existing code...
import api from '@/services/api';

export type ActionStatus = "todo" | "en_cours" | "termine";
export type ProjectStatus = "planifie" | "en_cours" | "en_pause" | "termine" | "annule";
export type Priority = "normale" | "haute" | "urgente";

export interface Action {
  id: string;
  titre: string;
  description?: string;
  assigned_to_profile_id: string;
  assigned_by_profile_id: string;
  assigned_at: string;
  due_date?: string;
  statut: ActionStatus;
  commentaire?: string;
  assigned_to_name?: string;
  assigned_by_name?: string;
}

export interface Project {
  id: string;
  nom: string;
  description?: string;
  chef_projet_id: string;
  date_debut: string;
  date_fin_prevue: string;
  date_fin_reelle?: string;
  budget?: number;
  cout_reel?: number;
  progression_percent: number;
  statut: ProjectStatus;
  priorite: Priority;
  chef_projet_name?: string;
  actions_count?: number;
  completed_actions_count?: number;
}

export interface ProjectAction {
  id: string;
  projet_id: string;
  action_id: string;
  created_at: string;
}

// Couleurs pour les statuts d'action
export const getActionStatusColor = (statut: ActionStatus) => {
  switch (statut) {
    case "todo":
      return "bg-muted text-muted-foreground border-border";
    case "en_cours":
      return "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800";
    case "termine":
      return "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800";
    default:
      return "bg-muted text-muted-foreground border-border";
  }
};

// Couleurs pour les lignes du tableau selon statut et date d'échéance
export const getRowColor = (action: Action) => {
  const today = new Date();
  const dueDate = action.due_date ? new Date(action.due_date) : null;
  const daysDiff = dueDate ? Math.ceil((dueDate.getTime() - today.getTime()) / (1000 * 60 * 60 * 24)) : null;

  // Rouge : Actions en retard
  if (dueDate && daysDiff < 0) {
    return "bg-red-50 hover:bg-red-100 border-l-4 border-l-red-500 dark:bg-red-950/20 dark:hover:bg-red-950/30";
  }
  
  // Orange : Actions dues dans les 3 prochains jours
  if (dueDate && daysDiff >= 0 && daysDiff <= 3) {
    return "bg-orange-50 hover:bg-orange-100 border-l-4 border-l-orange-500 dark:bg-orange-950/20 dark:hover:bg-orange-950/30";
  }

  // Selon statut
  switch (action.statut) {
    case "termine":
      return "bg-emerald-50 hover:bg-emerald-100 border-l-4 border-l-emerald-500 dark:bg-emerald-950/20 dark:hover:bg-emerald-950/30";
    case "en_cours":
      return "bg-amber-50 hover:bg-amber-100 border-l-4 border-l-amber-500 dark:bg-amber-950/20 dark:hover:bg-amber-950/30";
    case "todo":
    default:
      return "bg-background hover:bg-muted/50 border-l-4 border-l-muted transition-colors";
  }
};

// Vérifier si une action est en retard
export const isActionOverdue = (action: Action): boolean => {
  if (!action.due_date) return false;
  const today = new Date();
  const dueDate = new Date(action.due_date);
  return dueDate < today;
};

// Vérifier si une action est due bientôt (dans les 3 prochains jours)
export const isActionDueSoon = (action: Action): boolean => {
  if (!action.due_date) return false;
  const today = new Date();
  const dueDate = new Date(action.due_date);
  const daysDiff = Math.ceil((dueDate.getTime() - today.getTime()) / (1000 * 60 * 60 * 24));
  return daysDiff >= 0 && daysDiff <= 3;
};

// Labels pour les statuts d'action
export const getActionStatusLabel = (statut: ActionStatus) => {
  switch (statut) {
    case "todo":
      return "À faire";
    case "en_cours":
      return "En cours";
    case "termine":
      return "Terminé";
    default:
      return statut;
  }
};

// Options pour les selects
export const ACTION_STATUS_OPTIONS = [
  { value: "todo", label: "À faire" },
  { value: "en_cours", label: "En cours" },
  { value: "termine", label: "Terminé" },
];

// Calculer le pourcentage d'avancement d'un projet
export const calculateProjectProgress = (totalActions: number, completedActions: number): number => {
  if (totalActions === 0) return 0;
  return Math.round((completedActions / totalActions) * 100);
};

// Couleurs pour la barre de progression
export const getProgressColor = (percentage: number) => {
  if (percentage >= 80) return "bg-green-500";
  if (percentage >= 50) return "bg-yellow-500";
  if (percentage >= 25) return "bg-orange-500";
  return "bg-red-500";
};

// Formater les dates
export const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString("fr-FR");
};

export const fetchActions = async (): Promise<Action[]> => {
  try {
    const actions = await api.getActions();
    return actions;
  } catch (error) {
    console.error("Erreur lors de la récupération des actions:", error);
    return [];
  }
};

export const fetchProjects = async (): Promise<Project[]> => {
  try {
    const projects = await api.getProjects();
    return projects;
  } catch (error) {
    console.error("Erreur lors de la récupération des projets:", error);
    return [];
  }
};

// Récupérer les actions d'un projet
export const fetchProjectActions = async (projectId: string): Promise<Action[]> => {
  try {
    const actions = await api.getProjectActions(projectId);
    return actions;
  } catch (error) {
    console.error("Erreur lors de la récupération des actions du projet:", error);
    return [];
  }
};

// Mettre à jour le statut d'une action
export const updateActionStatus = async (actionId: string, statut: ActionStatus) => {
  try {
    await api.updateActionStatus(actionId, statut);
  } catch (error) {
    console.error("Erreur lors de la mise à jour du statut:", error);
    throw error;
  }
};

export const createAction = async (actionData: Action): Promise<Action> => {
  try {
    const response = await api.createAction(actionData);
    return response;
  } catch (error) {
    console.error("Erreur lors de la création de l'action:", error);
    throw error;
  }
};

// Créer un nouveau projet
export interface Project {
  nom: string;
  description?: string;
  chef_projet_id: string;
  date_debut: string;
  date_fin_prevue: string;
  budget?: number;
  priorite: "normale" | "haute" | "urgente";
  statut: "planifie" | "en_cours" | "en_pause" | "termine" | "annule";
  progression_percent: number;
}

// export const createProject = async (projectData: Project): Promise<Project> => {
//   try {
//     const response = await api.createProject(projectData);
//     return response;
//   } catch (error) {
//     console.error("Erreur lors de la création du projet:", error);
//     throw error;
//   }
// };

// Lier/délier une action à un projet
// export const linkActionToProject = async (projectId: string, actionId: string) => {
//   try {
//     await api.linkActionToProject(projectId, actionId);
//   } catch (error) {
//     console.error("Erreur lors de la liaison action-projet:", error);
//     throw error;
//   }
// };

// export const unlinkActionFromProject = async (projectId: string, actionId: string) => {
//   try {
//     await api.unlinkActionFromProject(projectId, actionId);
//   } catch (error) {
//     console.error("Erreur lors de la déliaison action-projet:", error);
//     throw error;
//   }
// };

export interface Profile {
  id: string;
  nom: string;
  email: string;
  // Ajoutez d'autres champs selon le modèle de profil
}

export const fetchProfiles = async (): Promise<Profile[]> => {
  try {
    const profiles = await api.getProfiles();
    return profiles;
  } catch (error) {
    console.error("Erreur lors de la récupération des profils:", error);
    return [];
  }
};

// Calculer les statistiques des actions
export const calculateActionStats = (actions: Action[]) => {
  const total = actions.length;
  const completed = actions.filter(a => a.statut === "termine").length;
  const inProgress = actions.filter(a => a.statut === "en_cours").length;
  const todo = actions.filter(a => a.statut === "todo").length;
  const overdue = actions.filter(isActionOverdue).length;
  const dueSoon = actions.filter(isActionDueSoon).length;

  const progressPercent = total > 0 ? Math.round((completed / total) * 100) : 0;

  // Top pilotes avec le plus d'actions à terminer
  const pilotStats = actions.reduce((acc, action) => {
    if (action.statut !== "termine" && action.assigned_to_name && action.assigned_to_name !== "Non assigné") {
      acc[action.assigned_to_name] = (acc[action.assigned_to_name] || 0) + 1;
    }
    return acc;
  }, {} as Record<string, number>);

  const topPilots = Object.entries(pilotStats)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 3)
    .map(([name, count]) => ({ name, count }));

  return {
    total,
    completed,
    inProgress,
    todo,
    overdue,
    dueSoon,
    progressPercent,
    topPilots
  };
};

// Mettre à jour le commentaire d'une action
export const updateActionComment = async (actionId: string, commentaire: string) => {
  try {
    await api.updateActionComment(actionId, commentaire);
  } catch (error) {
    console.error("Erreur lors de la mise à jour du commentaire:", error);
    throw error;
  }
  // Supabase supprimé, toute la logique doit passer par l'API Express locale
};

// Supprimer une action
export const deleteAction = async (actionId: string) => {
  try {
    await api.deleteAction(actionId);
  } catch (error) {
    console.error("Erreur lors de la suppression de l'action:", error);
    throw error;
  }
}

// Vérifier si l'utilisateur peut modifier une action
export const canUserEditAction = (action: Action, currentUserProfileId: string): boolean => {
  // L'utilisateur peut modifier s'il est le pilote assigné ou l'assigneur
  return action.assigned_to_profile_id === currentUserProfileId || 
         action.assigned_by_profile_id === currentUserProfileId;
};