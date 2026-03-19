import React, { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Calculator, Settings, FileText, Calendar, Zap, Bug } from "lucide-react";
import PayrollPeriods from './payroll/PayrollPeriods';
import PayrollCalculation from './payroll/PayrollCalculation';
import PayrollConfiguration from './payroll/PayrollConfiguration';
import PayrollResults from './payroll/PayrollResults';
import PayrollAutomation from './payroll/PayrollAutomation';
import { PayrollTestDashboard } from './payroll/PayrollTestDashboard';

const PayrollManagement = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <Calculator className="h-6 w-6 text-emerald-600" />
        <h3 className="text-lg font-semibold">Gestion de Paie - Maroc</h3>
      </div>
      
      <Tabs defaultValue="periods" className="w-full">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="periods" className="flex items-center gap-2">
            <Calendar className="h-4 w-4" />
            Périodes
          </TabsTrigger>
          <TabsTrigger value="calculation" className="flex items-center gap-2">
            <Calculator className="h-4 w-4" />
            Calculs
          </TabsTrigger>
          <TabsTrigger value="results" className="flex items-center gap-2">
            <FileText className="h-4 w-4" />
            Bulletins
          </TabsTrigger>
          <TabsTrigger value="tests" className="flex items-center gap-2">
            <Bug className="h-4 w-4" />
            Tests & Logs
          </TabsTrigger>
          <TabsTrigger value="automation" className="flex items-center gap-2">
            <Zap className="h-4 w-4" />
            Automatisation
          </TabsTrigger>
          <TabsTrigger value="config" className="flex items-center gap-2">
            <Settings className="h-4 w-4" />
            Configuration
          </TabsTrigger>
        </TabsList>

        <TabsContent value="periods" className="mt-6">
          <PayrollPeriods />
        </TabsContent>

        <TabsContent value="calculation" className="mt-6">
          <PayrollCalculation />
        </TabsContent>

        <TabsContent value="results" className="mt-6">
          <PayrollResults />
        </TabsContent>

        <TabsContent value="tests" className="mt-6">
          <PayrollTestDashboard />
        </TabsContent>

        <TabsContent value="automation" className="mt-6">
          <PayrollAutomation />
        </TabsContent>

        <TabsContent value="config" className="mt-6">
          <PayrollConfiguration />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default PayrollManagement;