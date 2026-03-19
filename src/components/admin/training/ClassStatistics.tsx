import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { supabase } from '@/integrations/supabase/client';
import { calculatePaymentStatistics, groupInscriptionsByFormation, formatAmount } from '@/lib/payment-utils';

interface ClassStatisticsProps {
  classeId: string;
}

interface PaymentStats {
  name: string;
  value: number;
  color: string;
}

interface FormationStats {
  formation: string;
  inscriptions: number;
  prix: number;
  totalRevenu: number;
}

interface MonthlyStats {
  month: string;
  inscriptions: number;
}

export function ClassStatistics({ classeId }: ClassStatisticsProps) {
  const [paymentStats, setPaymentStats] = useState<PaymentStats[]>([]);
  const [formationStats, setFormationStats] = useState<FormationStats[]>([]);
  const [monthlyStats, setMonthlyStats] = useState<MonthlyStats[]>([]);
  const [totalRevenuePotentiel, setTotalRevenuePotentiel] = useState(0);
  const [totalPaid, setTotalPaid] = useState(0);
  const [totalRemaining, setTotalRemaining] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStatistics();
  }, [classeId]);

  const loadStatistics = async () => {
    try {
      setLoading(true);

      // Charger les inscriptions avec toutes les données nécessaires
      const { data: inscriptions } = await supabase
        .from('inscriptions')
        .select(`
          *,
          formations:formation_id(titre, prix)
        `)
        .eq('classe_id', classeId);

      // Charger les paiements séparément pour chaque inscription
      const inscriptionsWithPaiements = await Promise.all(
        (inscriptions || []).map(async (inscription) => {
          const { data: paiements } = await supabase
            .from('paiements')
            .select('montant')
            .eq('inscription_id', inscription.id);
          
          return {
            ...inscription,
            paiements: paiements || []
          };
        })
      );

      if (inscriptionsWithPaiements.length > 0) {
        // Calculer les statistiques de paiement avec les utilitaires partagés
        const globalStats = calculatePaymentStatistics(inscriptionsWithPaiements);

        setPaymentStats([
          { name: 'Payé', value: globalStats.paymentCounts.paid, color: '#10b981' },
          { name: 'Partiellement payé', value: globalStats.paymentCounts.partial, color: '#f59e0b' },
          { name: 'Impayé', value: globalStats.paymentCounts.unpaid, color: '#ef4444' },
        ]);

        // Mettre à jour les totaux
        setTotalRevenuePotentiel(globalStats.totalRevenuePotentiel);
        setTotalPaid(globalStats.totalPaid);
        setTotalRemaining(globalStats.totalRemaining);

        // Calculer les statistiques mensuelles (6 derniers mois)
        const monthlyData: { [key: string]: number } = {};
        const currentDate = new Date();
        
        for (let i = 5; i >= 0; i--) {
          const date = new Date(currentDate.getFullYear(), currentDate.getMonth() - i, 1);
          const monthKey = date.toLocaleDateString('fr-FR', { month: 'short', year: 'numeric' });
          monthlyData[monthKey] = 0;
        }

        inscriptionsWithPaiements.forEach(inscription => {
          const date = new Date(inscription.date_inscription);
          const monthKey = date.toLocaleDateString('fr-FR', { month: 'short', year: 'numeric' });
          if (monthlyData.hasOwnProperty(monthKey)) {
            monthlyData[monthKey]++;
          }
        });

        setMonthlyStats(
          Object.entries(monthlyData).map(([month, inscriptions]) => ({
            month,
            inscriptions,
          }))
        );

        // Grouper par formation avec les données réelles
        const formationsGrouped = groupInscriptionsByFormation(inscriptionsWithPaiements);
        setFormationStats(formationsGrouped.map(fg => ({
          formation: `${fg.inscriptions} × ${fg.titre} (${fg.prix} DH)`,
          inscriptions: fg.inscriptions,
          prix: fg.prix,
          totalRevenu: fg.totalRevenu
        })));
      }
    } catch (error) {
      console.error('Error loading statistics:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {[...Array(4)].map((_, i) => (
          <Card key={i} className="animate-pulse">
            <CardHeader className="pb-2">
              <div className="h-4 bg-muted rounded w-3/4"></div>
            </CardHeader>
            <CardContent>
              <div className="h-24 bg-muted rounded"></div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* Payment Statistics */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Paiements</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-24">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={paymentStats}
                  cx="50%"
                  cy="50%"
                  innerRadius={20}
                  outerRadius={40}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {paymentStats.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 space-y-1">
            {paymentStats.map((stat, index) => (
              <div key={index} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1">
                  <div 
                    className="w-2 h-2 rounded-full" 
                    style={{ backgroundColor: stat.color }}
                  ></div>
                  <span>{stat.name}</span>
                </div>
                <span className="font-medium">{stat.value}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Revenue Statistics */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Payé</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-green-600">
            {formatAmount(totalPaid)}
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            Total collecté
          </p>
        </CardContent>
      </Card>

      {/* Monthly Inscriptions */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Inscriptions mensuelles</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-24">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={monthlyStats}>
                <Line 
                  type="monotone" 
                  dataKey="inscriptions" 
                  stroke="hsl(var(--primary))" 
                  strokeWidth={2}
                  dot={{ r: 3 }}
                />
                <Tooltip />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Remaining Amount */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Reste à payer</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-orange-600">
            {formatAmount(totalRemaining)}
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            Sur {formatAmount(totalRevenuePotentiel)} attendu
          </p>
          <div className="space-y-1 mt-3">
            {formationStats.map((stat, index) => (
              <div key={index} className="text-xs">
                <span className="font-medium">{stat.formation}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export default ClassStatistics;