
import React from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { LanguageProvider } from "@/contexts/LanguageContext";
import { CurrencyProvider } from "@/contexts/CurrencyContext";
import { DataProvider } from "@/contexts/DataContext"; // Importation
import { NavigationProvider } from "@/contexts/NavigationContext";
import Index from "./pages/Index";
import Dashboard from "./pages/Dashboard";
import Administration from "./pages/Administration";
import HubGestion from "./pages/HubGestion";
import MonEspace from "./pages/MonEspace";
import ValidationDemandes from "./pages/ValidationDemandes";
import Auth from "./pages/Auth";
import NotFound from "./pages/NotFound";
import ProtectedRoute from "./components/ProtectedRoute";
import EmployeeRecord from "./components/admin/EmployeeRecord";
import InscriptionsManagement from "./components/admin/training/InscriptionsManagement";
import ClassesManagement from "./pages/ClassesManagement";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(): { hasError: boolean } {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Error Boundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-background text-foreground flex items-center justify-center">
          <div className="text-center">
            <h1 className="text-2xl font-bold mb-4">Something went wrong</h1>
            <button 
              onClick={() => this.setState({ hasError: false })}
              className="px-4 py-2 bg-primary text-primary-foreground rounded"
            >
              Try again
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

const App: React.FC = () => {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <LanguageProvider>
          <CurrencyProvider>
            <DataProvider> {/* Ajout du DataProvider */}
              <TooltipProvider>
                <React.Suspense fallback={
                  <div className="min-h-screen bg-background text-foreground flex items-center justify-center">
                    <div className="text-center">
                      <h1 className="text-2xl font-bold">PROLEAN Formation</h1>
                      <p className="mt-4">Chargement...</p>
                    </div>
                  </div>
                }>
                  <Toaster />
                  <Sonner />
                  <BrowserRouter>
                    <NavigationProvider>
                      <Routes>
                        <Route path="/" element={<Index />} />
                        <Route path="/auth" element={<Auth />} />
                        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
                        <Route path="/administration" element={<ProtectedRoute><Administration /></ProtectedRoute>} />
                        <Route path="/administration/employee/:id" element={<ProtectedRoute><EmployeeRecord /></ProtectedRoute>} />
                        <Route path="/administration/formations/classes" element={<ProtectedRoute><ClassesManagement /></ProtectedRoute>} />
                        <Route path="/administration/classe/:id/inscriptions" element={<ProtectedRoute><InscriptionsManagement /></ProtectedRoute>} />
                        <Route path="/hub-gestion" element={<ProtectedRoute><HubGestion /></ProtectedRoute>} />
                        <Route path="/mon-espace" element={<ProtectedRoute><MonEspace /></ProtectedRoute>} />
                        <Route path="/validation-demandes" element={<ProtectedRoute><ValidationDemandes /></ProtectedRoute>} />
                        <Route path="*" element={<NotFound />} />
                      </Routes>
                    </NavigationProvider>
                  </BrowserRouter>
                </React.Suspense>
              </TooltipProvider>
            </DataProvider>
          </CurrencyProvider>
        </LanguageProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
};

export default App;
