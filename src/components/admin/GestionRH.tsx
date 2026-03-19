import React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CheckCircle, Clock, Calculator } from "lucide-react";
import ValidationWorkflow from './ValidationWorkflow';
import ScheduleManagement from './ScheduleManagement';
import PayrollManagement from './PayrollManagement';

const GestionRH = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <CheckCircle className="h-6 w-6 text-cyan-600" />
        <h2 className="text-xl font-semibold">Gestion RH</h2>
      </div>
      
      <Tabs defaultValue="validation" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="validation" className="flex items-center gap-2">
            <CheckCircle className="h-4 w-4" />
            Boucles de validation
          </TabsTrigger>
          <TabsTrigger value="horaires" className="flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Gestion des horaires
          </TabsTrigger>
          <TabsTrigger value="payroll" className="flex items-center gap-2">
            <Calculator className="h-4 w-4" />
            Gestion de paie
          </TabsTrigger>
        </TabsList>

        <TabsContent value="validation" className="mt-6">
          <ValidationWorkflow />
        </TabsContent>

        <TabsContent value="horaires" className="mt-6">
          <ScheduleManagement />
        </TabsContent>

        <TabsContent value="payroll" className="mt-6">
          <PayrollManagement />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default GestionRH;