/**
 * Utilitaires partagés pour les calculs de paiement
 * Ces fonctions garantissent la cohérence entre tous les composants
 */

export interface PaymentCalculation {
  formationPrice: number;
  totalPaid: number;
  remaining: number;
  percentage: number;
}

export interface InscriptionWithFormation {
  formations?: {
    prix: number;
    titre: string;
  };
  avance?: number;
  paiements?: Array<{
    montant: number;
  }>;
}

/**
 * Calcule les informations de paiement pour une inscription
 */
export function calculatePaymentInfo(inscription: InscriptionWithFormation): PaymentCalculation {
  const formationPrice = inscription.formations?.prix || 0;
  const avance = inscription.avance || 0;
  const paymentsTotal = (inscription.paiements || []).reduce((sum, p) => sum + Number(p.montant), 0);
  const totalPaid = avance + paymentsTotal;
  const remaining = Math.max(0, formationPrice - totalPaid);
  const percentage = formationPrice > 0 ? (totalPaid / formationPrice) * 100 : 0;

  return {
    formationPrice,
    totalPaid,
    remaining,
    percentage
  };
}

/**
 * Détermine le statut de paiement d'une inscription
 */
export function getPaymentStatus(paymentInfo: PaymentCalculation): 'paid' | 'partial' | 'unpaid' {
  if (paymentInfo.totalPaid === 0) return 'unpaid';
  if (paymentInfo.remaining <= 0) return 'paid';
  return 'partial';
}

/**
 * Calcule les statistiques globales de paiement pour une liste d'inscriptions
 */
export function calculatePaymentStatistics(inscriptions: InscriptionWithFormation[]) {
  const stats = inscriptions.map(inscription => {
    const paymentInfo = calculatePaymentInfo(inscription);
    return {
      ...paymentInfo,
      status: getPaymentStatus(paymentInfo)
    };
  });

  const totalRevenuePotentiel = stats.reduce((sum, s) => sum + s.formationPrice, 0);
  const totalPaid = stats.reduce((sum, s) => sum + s.totalPaid, 0);
  const totalRemaining = stats.reduce((sum, s) => sum + s.remaining, 0);

  const paymentCounts = {
    paid: stats.filter(s => s.status === 'paid').length,
    partial: stats.filter(s => s.status === 'partial').length,
    unpaid: stats.filter(s => s.status === 'unpaid').length
  };

  return {
    totalRevenuePotentiel,
    totalPaid,
    totalRemaining,
    paymentCounts,
    totalInscriptions: inscriptions.length
  };
}

/**
 * Groupe les inscriptions par formation et calcule les statistiques
 */
export function groupInscriptionsByFormation(inscriptions: InscriptionWithFormation[]) {
  const groupedByFormation = inscriptions.reduce((acc, inscription) => {
    const formationTitre = inscription.formations?.titre || 'Formation inconnue';
    const formationPrice = inscription.formations?.prix || 0;
    
    if (!acc[formationTitre]) {
      acc[formationTitre] = {
        titre: formationTitre,
        prix: formationPrice,
        inscriptions: 0,
        totalRevenu: 0
      };
    }
    
    acc[formationTitre].inscriptions++;
    acc[formationTitre].totalRevenu += formationPrice;
    
    return acc;
  }, {} as Record<string, { titre: string; prix: number; inscriptions: number; totalRevenu: number }>);

  return Object.values(groupedByFormation);
}

/**
 * Formate un montant en DH
 */
export function formatAmount(amount: number): string {
  return `${amount.toLocaleString()} DH`;
}

/**
 * Retourne la couleur CSS appropriée pour un montant restant
 */
export function getRemainingAmountColor(remaining: number, formationPrice: number): string {
  if (remaining <= 0) return 'text-green-600';
  if (remaining < formationPrice / 2) return 'text-orange-600';
  return 'text-red-600';
}