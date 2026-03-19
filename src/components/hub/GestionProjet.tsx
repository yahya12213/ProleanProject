import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PlanActionTable } from "./PlanActionTable";
import { ProjetKanban } from "./ProjetKanban";

export function GestionProjet() {
  const [activeTab, setActiveTab] = useState("plan-action");

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-2xl font-bold text-foreground">Gestion des Projets</h3>
          <p className="text-sm text-muted-foreground">
            Gérez vos actions et projets de manière intégrée
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-2 max-w-md">
          <TabsTrigger value="plan-action">Plan d'Action</TabsTrigger>
          <TabsTrigger value="projets">Projets (Kanban)</TabsTrigger>
        </TabsList>

        <TabsContent value="plan-action" className="space-y-6">
          <PlanActionTable />
        </TabsContent>

        <TabsContent value="projets" className="space-y-6">
          <ProjetKanban />
        </TabsContent>
      </Tabs>
    </div>
  );
}