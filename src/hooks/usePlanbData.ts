/**
 * Hook personnalisé pour la gestion des données PLAN B
 * Centralise la logique d'accès aux données avec cache et validation
 */

import { useState, useEffect, useCallback, useMemo } from 'react';
// ...existing code...
import { useToast } from '@/hooks/use-toast';
import { 
  getPlanbClassesWithDetails,
  getPlanbInscriptionsForClasse,
  getPlanbPaiementsForInscription,
  getPlanbClasseStats
} from '@/lib/planb-functions';

// ===============================================
// TYPES
// ===============================================

interface UsePlanbDataOptions {
  autoRefresh?: boolean;
  refreshInterval?: number;
  enableCache?: boolean;
}

interface DataState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  lastUpdated: Date | null;
}

// ===============================================
// HOOK PRINCIPAL
// ===============================================

export function usePlanbData<T>(
  fetchFunction: () => Promise<{ data: T | null; error: any }>,
  dependencies: any[] = [],
  options: UsePlanbDataOptions = {}
) {
  const { autoRefresh = false, refreshInterval = 30000, enableCache = true } = options;
  const { toast } = useToast();

  const [state, setState] = useState<DataState<T>>({
    data: null,
    loading: true,
    error: null,
    lastUpdated: null
  });

  const fetchData = useCallback(async (showLoadingState = true) => {
    if (showLoadingState) {
      setState(prev => ({ ...prev, loading: true, error: null }));
    }

    try {
      const result = await fetchFunction();
      
      if (result.error) {
        throw new Error(result.error.message || 'Erreur lors du chargement des données');
      }

      setState({
        data: result.data,
        loading: false,
        error: null,
        lastUpdated: new Date()
      });

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Erreur inconnue';
      
      setState(prev => ({
        ...prev,
        loading: false,
        error: errorMessage
      }));

      toast({
        title: "Erreur de chargement",
        description: errorMessage,
        variant: "destructive"
      });
    }
  }, [fetchFunction, toast]);

  const refresh = useCallback(() => {
    fetchData(false);
  }, [fetchData]);

  // Chargement initial
  useEffect(() => {
    fetchData();
  }, dependencies);

  // Auto-refresh
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      refresh();
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [autoRefresh, refreshInterval, refresh]);

  const memoizedReturn = useMemo(() => ({
    ...state,
    refresh,
    isStale: state.lastUpdated ? Date.now() - state.lastUpdated.getTime() > refreshInterval : true
  }), [state, refresh, refreshInterval]);

  return memoizedReturn;
}

// ===============================================
// HOOKS SPÉCIALISÉS
// ===============================================

/**
 * Hook pour les classes avec détails
 */
export function usePlanbClasses(options?: UsePlanbDataOptions) {
  return usePlanbData(
    getPlanbClassesWithDetails,
    [],
    options
  );
}

/**
 * Hook pour les inscriptions d'une classe
 */
export function usePlanbInscriptions(classeId: string, options?: UsePlanbDataOptions) {
  return usePlanbData(
    () => getPlanbInscriptionsForClasse(classeId),
    [classeId],
    options
  );
}

/**
 * Hook pour les paiements d'une inscription
 */
export function usePlanbPaiements(inscriptionId: string, options?: UsePlanbDataOptions) {
  return usePlanbData(
    () => getPlanbPaiementsForInscription(inscriptionId),
    [inscriptionId],
    options
  );
}

/**
 * Hook pour les statistiques d'une classe
 */
export function usePlanbClasseStats(classeId: string, options?: UsePlanbDataOptions) {
  return usePlanbData(
    () => getPlanbClasseStats(classeId),
    [classeId],
    options
  );
}

// ===============================================
// HOOK POUR MUTATIONS
// ===============================================

interface UsePlanbMutationOptions<T> {
  onSuccess?: (data: T) => void;
  onError?: (error: Error) => void;
  showToast?: boolean;
}

export function usePlanbMutation<T, Args extends any[]>(
  mutationFunction: (...args: Args) => Promise<{ data: T | null; error: any }>,
  options: UsePlanbMutationOptions<T> = {}
) {
  const { onSuccess, onError, showToast = true } = options;
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const mutate = useCallback(async (...args: Args) => {
    setLoading(true);
    setError(null);

    try {
      const result = await mutationFunction(...args);
      
      if (result.error) {
        throw new Error(result.error.message || 'Erreur lors de la mutation');
      }

      if (showToast) {
        toast({
          title: "Succès",
          description: "Opération réalisée avec succès",
          variant: "default"
        });
      }

      onSuccess?.(result.data as T);
      return result.data;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Erreur inconnue';
      setError(errorMessage);

      if (showToast) {
        toast({
          title: "Erreur",
          description: errorMessage,
          variant: "destructive"
        });
      }

      onError?.(error as Error);
      throw error;

    } finally {
      setLoading(false);
    }
  }, [mutationFunction, onSuccess, onError, showToast, toast]);

  return {
    mutate,
    loading,
    error,
    reset: useCallback(() => {
      setError(null);
    }, [])
  };
}

// ===============================================
// HOOK POUR RECHERCHE ET FILTRAGE
// ===============================================

export function usePlanbSearch<T>(
  data: T[],
  searchFields: (keyof T)[],
  filters: Record<string, any> = {}
) {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeFilters, setActiveFilters] = useState(filters);

  const filteredData = useMemo(() => {
    if (!data) return [];

    let result = data;

    // Filtrage par terme de recherche
    if (searchTerm.trim()) {
      const lowerSearchTerm = searchTerm.toLowerCase();
      result = result.filter(item =>
        searchFields.some(field => {
          const value = item[field];
          return value && String(value).toLowerCase().includes(lowerSearchTerm);
        })
      );
    }

    // Application des filtres
    Object.entries(activeFilters).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '' && value !== 'tous') {
        result = result.filter(item => {
          const itemValue = (item as any)[key];
          return itemValue === value;
        });
      }
    });

    return result;
  }, [data, searchTerm, searchFields, activeFilters]);

  const updateFilter = useCallback((key: string, value: any) => {
    setActiveFilters(prev => ({
      ...prev,
      [key]: value
    }));
  }, []);

  const clearFilters = useCallback(() => {
    setSearchTerm('');
    setActiveFilters({});
  }, []);

  return {
    searchTerm,
    setSearchTerm,
    filteredData,
    activeFilters,
    updateFilter,
    clearFilters,
    totalCount: data?.length || 0,
    filteredCount: filteredData.length
  };
}

// ===============================================
// HOOK POUR PAGINATION
// ===============================================

export function usePlanbPagination<T>(data: T[], itemsPerPage = 10) {
  const [currentPage, setCurrentPage] = useState(1);

  const totalPages = Math.ceil(data.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedData = data.slice(startIndex, endIndex);

  const goToPage = useCallback((page: number) => {
    const validPage = Math.max(1, Math.min(page, totalPages));
    setCurrentPage(validPage);
  }, [totalPages]);

  const nextPage = useCallback(() => {
    goToPage(currentPage + 1);
  }, [currentPage, goToPage]);

  const prevPage = useCallback(() => {
    goToPage(currentPage - 1);
  }, [currentPage, goToPage]);

  // Reset à la page 1 quand les données changent
  useEffect(() => {
    setCurrentPage(1);
  }, [data.length]);

  return {
    currentPage,
    totalPages,
    paginatedData,
    goToPage,
    nextPage,
    prevPage,
    hasNextPage: currentPage < totalPages,
    hasPrevPage: currentPage > 1,
    startIndex: startIndex + 1,
    endIndex: Math.min(endIndex, data.length),
    totalItems: data.length
  };
}