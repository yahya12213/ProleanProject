import React from 'react';
import { Card } from "@/components/ui/card";
import { useNavigation } from "@/contexts/NavigationContext";
import { RefactoredDemandeValidation } from "@/components/admin/RefactoredDemandeValidation";
import MainNavigation from "@/components/MainNavigation";
import { CheckCircle } from "lucide-react";

const ValidationDemandes = () => {
  const { setBreadcrumbs } = useNavigation();

  React.useEffect(() => {
    setBreadcrumbs([
      { label: "Accueil", path: "/" },
      { label: "Validation des demandes", path: "/validation-demandes" }
    ]);
  }, [setBreadcrumbs]);

  return (
    <div className="min-h-screen bg-background">
      <nav className="bg-card border-b border-border sticky top-0 z-50">
        <div className="container mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <h1 className="text-xl font-semibold text-foreground">PROLEAN Formation</h1>
              <MainNavigation />
            </div>
          </div>
        </div>
      </nav>

      <div className="container mx-auto p-6">
        <Card className="w-full">
          <div className="p-6">
            <div className="flex items-center gap-3 mb-6">
              <CheckCircle className="h-8 w-8 text-primary" />
              <div>
                <h1 className="text-2xl font-bold text-foreground">Validation des demandes</h1>
                <p className="text-muted-foreground">Gérer et valider les demandes RH</p>
              </div>
            </div>
            
            <RefactoredDemandeValidation />
          </div>
        </Card>
      </div>
    </div>
  );
};

export default ValidationDemandes;