import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { 
  Play, 
  PlayCircle,
  CheckCircle, 
  XCircle, 
  AlertCircle, 
  Clock,
  Loader2
} from "lucide-react";

interface TestResult {
  id: string;
  test_id: string;
  test_run_id: string;
  status: string;
  actual_result: any;
  execution_time_ms: number;
  error_message: string | null;
  differences: any;
  created_at: string;
}

interface AutomatedTest {
  id: string;
  test_name: string;
  test_category: string;
  test_type: string;
  test_data: any;
  expected_result: any;
  is_active: boolean;
}

interface TestSummary {
  test_run_id: string;
  total_tests: number;
  passed: number;
  failed: number;
  errors: number;
  total_execution_time: number;
}

interface LogEntry {
  id: string;
  operation_type: string;
  status: string;
  execution_time_ms: number;
  error_details: any;
  warnings: any;
  created_at: string;
}

export function PayrollTestDashboard() {
  const [tests, setTests] = useState<AutomatedTest[]>([]);
  const [results, setResults] = useState<TestResult[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [selectedTests, setSelectedTests] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    loadData();
    // Auto-launch tests on component mount
    setTimeout(() => {
      runAllTests();
    }, 2000);
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Load tests, results, and logs in parallel
      const [testsResponse, resultsResponse, logsResponse] = await Promise.all([
        supabase.from('payroll_automated_tests').select('*').eq('is_active', true).order('created_at'),
        supabase.from('payroll_test_results').select('*').order('created_at', { ascending: false }).limit(50),
        supabase.from('payroll_calculation_logs').select('*').order('created_at', { ascending: false }).limit(100)
      ]);

      if (testsResponse.error) throw testsResponse.error;
      if (resultsResponse.error) throw resultsResponse.error;
      if (logsResponse.error) throw logsResponse.error;

      setTests(testsResponse.data || []);
      setResults(resultsResponse.data || []);
      setLogs(logsResponse.data || []);
    } catch (error) {
      console.error('Error loading test data:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données de test",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const runTests = async (testIds?: string[]) => {
    try {
      setIsRunning(true);
      
      // If specific test IDs provided, filter tests
      const testsToRun = testIds ? tests.filter(t => testIds.includes(t.id)) : tests;
      
      if (testsToRun.length === 0) {
        toast({
          title: "Aucun test sélectionné",
          description: "Veuillez sélectionner au moins un test à exécuter",
          variant: "destructive",
        });
        return;
      }

      toast({
        title: "Exécution des tests",
        description: `Lancement de ${testsToRun.length} test(s) automatisé(s)...`,
      });

      // Call the payroll test engine
      const { data, error } = await supabase.functions.invoke('payroll-test-engine', {
        body: { action: 'run_tests' }
      });

      if (error) {
        console.error('Test execution error:', error);
        throw error;
      }

      console.log('Test execution response:', data);
      
      const totalTests = data?.totalTests || 0;
      const passed = data?.passed || 0;
      const failed = data?.failed || 0;
      const errors = data?.errors || 0;
      
      toast({
        title: "Tests terminés",
        description: `${passed} réussis, ${failed} échoués, ${errors} erreurs sur ${totalTests} tests`,
        variant: failed > 0 || errors > 0 ? "destructive" : "default",
      });

      // Reload data to show new results
      await loadData();
      
    } catch (error) {
      console.error('Error running tests:', error);
      toast({
        title: "Erreur",
        description: "Échec de l'exécution des tests",
        variant: "destructive",
      });
    } finally {
      setIsRunning(false);
    }
  };

  const runAllTests = () => {
    runTests();
  };

  const runSelectedTests = () => {
    if (selectedTests.length === 0) {
      toast({
        title: "Aucun test sélectionné",
        description: "Veuillez sélectionner au moins un test",
        variant: "destructive",
      });
      return;
    }
    runTests(selectedTests);
  };

  const toggleTestSelection = (testId: string) => {
    setSelectedTests(prev => 
      prev.includes(testId) 
        ? prev.filter(id => id !== testId)
        : [...prev, testId]
    );
  };

  const selectAllTests = () => {
    setSelectedTests(tests.map(t => t.id));
  };

  const clearSelection = () => {
    setSelectedTests([]);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'passed': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'error': return <AlertCircle className="h-4 w-4 text-orange-500" />;
      default: return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const variants: Record<string, "default" | "destructive" | "secondary" | "outline"> = {
      passed: 'default',
      failed: 'destructive',
      error: 'secondary',
      success: 'default',
      warning: 'secondary',
    };
    return <Badge variant={variants[status] || 'outline'}>{status}</Badge>;
  };

  const calculateSuccessRate = () => {
    if (results.length === 0) return 0;
    const passed = results.filter(r => r.status === 'passed').length;
    return Math.round((passed / results.length) * 100);
  };

  const getLastExecutionTime = () => {
    if (results.length === 0) return 'Jamais';
    const lastResult = results[0];
    return new Date(lastResult.created_at).toLocaleString('fr-FR');
  };

  const getActiveErrors = () => {
    return results.filter(r => r.status === 'failed' || r.status === 'error').length;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
          <p>Chargement des tests...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-semibold">Tests Automatisés de Paie</h2>
        <div className="flex gap-2">
          <Button 
            onClick={runSelectedTests} 
            disabled={isRunning || selectedTests.length === 0}
            variant="outline"
          >
            {isRunning ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}
            Lancer Sélection ({selectedTests.length})
          </Button>
          <Button onClick={runAllTests} disabled={isRunning}>
            {isRunning ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <PlayCircle className="h-4 w-4 mr-2" />}
            Lancer Tous les Tests
          </Button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Tests</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{tests.length}</div>
            <p className="text-xs text-muted-foreground">Tests actifs configurés</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Taux de Réussite</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{calculateSuccessRate()}%</div>
            <p className="text-xs text-muted-foreground">Sur les dernières exécutions</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Dernière Exécution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-sm font-medium">{getLastExecutionTime()}</div>
            <p className="text-xs text-muted-foreground">Horodatage automatique</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Erreurs Actives</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{getActiveErrors()}</div>
            <p className="text-xs text-muted-foreground">Tests en échec</p>
          </CardContent>
        </Card>
      </div>

      {/* Test Interface */}
      <Tabs defaultValue="tests" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="tests">Tests Disponibles</TabsTrigger>
          <TabsTrigger value="results">Résultats</TabsTrigger>
          <TabsTrigger value="logs">Logs de Calcul</TabsTrigger>
          <TabsTrigger value="corrections">Corrections Auto</TabsTrigger>
        </TabsList>

        <TabsContent value="tests" className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={selectAllTests}>
                Tout sélectionner
              </Button>
              <Button variant="outline" size="sm" onClick={clearSelection}>
                Tout désélectionner
              </Button>
            </div>
            <Badge variant="outline">{selectedTests.length} sélectionné(s)</Badge>
          </div>

          <div className="grid gap-4">
            {tests.map((test) => (
              <Card key={test.id} className={selectedTests.includes(test.id) ? 'ring-2 ring-primary' : ''}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Checkbox
                        checked={selectedTests.includes(test.id)}
                        onCheckedChange={() => toggleTestSelection(test.id)}
                      />
                      <div>
                        <CardTitle className="text-sm">{test.test_name}</CardTitle>
                        <div className="flex gap-2 mt-1">
                          <Badge variant="secondary">{test.test_category}</Badge>
                          <Badge variant="outline">{test.test_type}</Badge>
                        </div>
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => runTests([test.id])}
                      disabled={isRunning}
                    >
                      <Play className="h-3 w-3" />
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="text-xs text-muted-foreground">
                    <div><strong>Données:</strong> {JSON.stringify(test.test_data, null, 2).substring(0, 100)}...</div>
                    <div><strong>Attendu:</strong> {JSON.stringify(test.expected_result, null, 2)}</div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="results" className="space-y-4">
          <div className="space-y-2">
            {results.map((result) => (
              <Card key={result.id}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(result.status)}
                      <span className="font-medium">Test {result.test_id?.substring(0, 8)}</span>
                      {getStatusBadge(result.status)}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {result.execution_time_ms}ms
                    </div>
                  </div>
                </CardHeader>
                {(result.differences || result.error_message) && (
                  <CardContent className="pt-0">
                    {result.error_message && (
                      <div className="bg-red-50 border border-red-200 rounded p-3 mb-3">
                        <p className="text-sm text-red-800">{result.error_message}</p>
                      </div>
                    )}
                    {result.differences && (
                      <div className="bg-orange-50 border border-orange-200 rounded p-3">
                        <p className="text-sm font-medium text-orange-800 mb-2">Différences détectées:</p>
                        <pre className="text-xs text-orange-700 overflow-auto">
                          {JSON.stringify(result.differences, null, 2)}
                        </pre>
                      </div>
                    )}
                  </CardContent>
                )}
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="logs" className="space-y-4">
          <div className="space-y-2">
            {logs.map((log) => (
              <Card key={log.id}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">{log.operation_type}</Badge>
                      {getStatusBadge(log.status)}
                    </div>
                    <span className="text-sm text-muted-foreground">
                      {new Date(log.created_at).toLocaleString('fr-FR')}
                    </span>
                  </div>
                </CardHeader>
                {(log.warnings || log.error_details) && (
                  <CardContent className="pt-0">
                    {log.error_details && (
                      <div className="bg-red-50 border border-red-200 rounded p-3 mb-3">
                        <pre className="text-xs text-red-800 overflow-auto">
                          {JSON.stringify(log.error_details, null, 2)}
                        </pre>
                      </div>
                    )}
                    {log.warnings && (
                      <div className="bg-yellow-50 border border-yellow-200 rounded p-3">
                        <pre className="text-xs text-yellow-800 overflow-auto">
                          {JSON.stringify(log.warnings, null, 2)}
                        </pre>
                      </div>
                    )}
                  </CardContent>
                )}
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="corrections" className="space-y-4">
          <div className="text-center py-12">
            <AlertCircle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-medium mb-2">Corrections Automatiques</h3>
            <p className="text-muted-foreground">
              Les fonctionnalités de correction automatique seront implémentées ici.
              Elles permettront de détecter et corriger automatiquement les erreurs de calcul.
            </p>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}