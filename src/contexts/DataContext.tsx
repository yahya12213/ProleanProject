
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import api from '@/services/api'; // Assurez-vous que le chemin est correct

// --- Types de Données ---
interface Formation {
  id: number;
  slug: string;
  title: string;
  description: string;
  imageUrl?: string;
}

interface Faq {
  id: number;
  question: string;
  answer: string;
}

// --- Contexte ---
export interface DataContextType {
  formations: Formation[];
  faqs: Faq[];
  isLoading: boolean;
  error: string | null;
}

const DataContext = createContext<DataContextType | undefined>(undefined);

// --- Provider ---
interface DataProviderProps {
  children: ReactNode;
}

export const DataProvider: React.FC<DataProviderProps> = ({ children }) => {
  const [formations, setFormations] = useState<Formation[]>([]);
  const [faqs, setFaqs] = useState<Faq[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      setIsLoading(true);
      try {
        const [formationsRes, faqsRes] = await Promise.all([
          api.getFormations(),
          api.getFaqs(),
        ]);
        setFormations(formationsRes.data);
        setFaqs(faqsRes.data);
        setError(null);
      } catch (err) {
        console.error("Erreur lors du chargement des données de l'application:", err);
        setError("Impossible de charger les ressources nécessaires.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  const value = { formations, faqs, isLoading, error };

  return <DataContext.Provider value={value}>{children}</DataContext.Provider>;
};

// --- Hook Personnalisé ---
export const useData = (): DataContextType => {
  const context = useContext(DataContext);
  if (context === undefined) {
    throw new Error('useData doit être utilisé à l\'intérieur d\'un DataProvider');
  }
  return context;
};
