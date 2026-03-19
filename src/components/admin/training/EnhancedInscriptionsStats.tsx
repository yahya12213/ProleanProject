import React from 'react';
import { StatsCard } from '@/components/ui/enhanced-card';
import { Users, DollarSign, CheckCircle2, AlertTriangle } from 'lucide-react';
import { formatAmount } from '@/lib/payment-utils';

interface InscriptionsStatsProps {
  stats: {
    total: number;
    valides: number;
    en_attente: number;
    totalPaid: number;
    totalRemaining: number;
    totalRevenuePotentiel: number;
    taux_validation?: number;
    croissance?: number;
  };
  className?: string;
}

const EnhancedInscriptionsStats: React.FC<InscriptionsStatsProps> = ({ 
  stats, 
  className 
}) => {
  const tauxValidation = stats.total > 0 ? (stats.valides / stats.total) * 100 : 0;
  const tauxRecouvrement = stats.totalRevenuePotentiel > 0 ? (stats.totalPaid / stats.totalRevenuePotentiel) * 100 : 0;

  return (
    <div className={`grid gap-4 md:grid-cols-2 lg:grid-cols-4 ${className}`}>
      <StatsCard
        title="Total Inscriptions"
        value={stats.total}
        change={tauxValidation > 0 ? `${tauxValidation.toFixed(1)}% validés` : undefined}
        trend={tauxValidation >= 80 ? "up" : tauxValidation >= 60 ? "neutral" : "down"}
        icon={<Users className="h-6 w-6" />}
      />
      
      <StatsCard
        title="Payé" 
        value={formatAmount(stats.totalPaid)}
        change={`${tauxRecouvrement.toFixed(1)}% collecté`}
        trend={tauxRecouvrement >= 80 ? "up" : tauxRecouvrement >= 50 ? "neutral" : "down"}
        icon={<CheckCircle2 className="h-6 w-6" />}
      />
      
      <StatsCard
        title="Reste à payer"
        value={formatAmount(stats.totalRemaining)}
        change={stats.totalRemaining > 0 ? "En attente" : "Complet"}
        trend={stats.totalRemaining === 0 ? "up" : "neutral"}
        icon={<AlertTriangle className="h-6 w-6" />}
      />
      
      <StatsCard
        title="Revenus Potentiels"
        value={formatAmount(stats.totalRevenuePotentiel)}
        change="Total attendu"
        trend="neutral"
        icon={<DollarSign className="h-6 w-6" />}
      />
    </div>
  );
};

export default EnhancedInscriptionsStats;