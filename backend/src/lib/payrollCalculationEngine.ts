/**
 * Unified Payroll Calculation Engine
 * Shared by calculate-payroll and payroll-test-engine functions
 * Ensures consistent calculations across all payroll operations
 */
// Moroccan Tax Brackets 2025 (exact values)
export const IGR_BRACKETS = [
  { min: 0, max: 2500, rate: 0, deduction: 0 },
  { min: 2500, max: 4166.67, rate: 0.10, deduction: 250 },
  { min: 4166.67, max: 5000, rate: 0.20, deduction: 666.67 },
  { min: 5000, max: 6666.67, rate: 0.30, deduction: 1166.67 },
  { min: 6666.67, max: 15000, rate: 0.34, deduction: 1433.33 },
  { min: 15000, max: Infinity, rate: 0.38, deduction: 2033.33 }
];
// CNSS Branches (2025 rates)
export const CNSS_BRANCHES = [
  { code: 'AIF', name: 'Assurance Invalidité-Famille', rate: 0.0067, payer: 'SALARIE', base: 'GROSS_PLAFONNEE' },
  { code: 'PENSION', name: 'Pension Vieillesse', rate: 0.0396, payer: 'SALARIE', base: 'GROSS_PLAFONNEE' },
  { code: 'AIF_PATR', name: 'AIF Patronal', rate: 0.0681, payer: 'EMPLOYEUR', base: 'GROSS_PLAFONNEE' },
  { code: 'PENSION_PATR', name: 'Pension Patronal', rate: 0.0792, payer: 'EMPLOYEUR', base: 'GROSS_PLAFONNEE' },
  { code: 'FORMATION', name: 'Formation Prof.', rate: 0.016, payer: 'EMPLOYEUR', base: 'GROSS' }
];
// AMO Configuration
export const AMO_CONFIG = {
  employee_rate: 0.0226,
  employer_rate: 0.0226,
  solidarity_rate: 0.005
};
// Constants
export const CNSS_CEILING = 6000; // MAD
export const FAMILY_ALLOWANCE_PER_CHILD = 41.67; // MAD
export const MONTHLY_HOURS_THRESHOLD = 191; // Hours

// Typing for CNSS details
interface CNSSDetail {
  code: string;
  name: string;
  base: number;
  rate: number;
  amount: number;
  payer: string;
}

export function calculateCNSS(grossPay: number) {
  let employee = 0;
  let employer = 0;
  const details: CNSSDetail[] = [];
  const cnssBase = Math.min(grossPay, CNSS_CEILING);
  CNSS_BRANCHES.forEach((branch) => {
    const base = branch.base === 'GROSS_PLAFONNEE' ? cnssBase : grossPay;
    const amount = base * branch.rate;
    if (branch.payer === 'SALARIE') {
      employee += amount;
    } else {
      employer += amount;
    }
    details.push({
      code: branch.code,
      name: branch.name,
      base,
      rate: branch.rate,
      amount: Math.round(amount * 100) / 100,
      payer: branch.payer
    });
  });
  return {
    employee: Math.round(employee * 100) / 100,
    employer: Math.round(employer * 100) / 100,
    details
  };
}

export function calculateAMO(grossPay: number) {
  const employee = grossPay * AMO_CONFIG.employee_rate;
  const employer = grossPay * AMO_CONFIG.employer_rate;
  const solidarity = grossPay * AMO_CONFIG.solidarity_rate;
  return {
    employee: Math.round(employee * 100) / 100,
    employer: Math.round(employer * 100) / 100,
    solidarity: Math.round(solidarity * 100) / 100
  };
}

export function calculateIGR(grossImposable: number, dependentsCount: number, cnssDeductible: number) {
  const effectiveDependents = Math.min(dependentsCount || 0, 6);
  const familyDeduction = effectiveDependents * FAMILY_ALLOWANCE_PER_CHILD;
  const netImposableBase = Math.max(0, grossImposable - familyDeduction - cnssDeductible);
  const roundedBase = Math.ceil(netImposableBase / 10) * 10;
  const bracket = IGR_BRACKETS.find((b) => roundedBase >= b.min && roundedBase < b.max);
  if (!bracket) {
    return {
      igr: 0,
      netImposableBase,
      details: {
        bracket: null,
        roundedBase,
        familyDeduction,
        cnssDeduction: cnssDeductible
      }
    };
  }
  const igrCalculated = roundedBase * bracket.rate - bracket.deduction;
  const igr = Math.max(0, Math.ceil(igrCalculated));
  return {
    igr,
    netImposableBase,
    details: {
      bracket,
      roundedBase,
      familyDeduction,
      cnssDeduction: cnssDeductible,
      effectiveDependents,
      igrCalculated
    }
  };
}

export function calculateLeaveAccrual(employee: { hire_date?: string; date_naissance?: string }, effectiveHours: number, periodEndDate: Date) {
  if (!employee?.hire_date) {
    return {
      days: 0,
      details: {
        reason: "Date d'embauche manquante"
      }
    };
  }
  const hireDate = new Date(employee.hire_date);
  const birthDate = employee.date_naissance ? new Date(employee.date_naissance) : null;
  const isMinor = birthDate ? getAge(birthDate, periodEndDate) < 18 : false;
  const seniorityMonths = getMonthsDifference(hireDate, periodEndDate);
  if (seniorityMonths < 6) {
    return {
      days: 0,
      details: {
        reason: 'Ancienneté insuffisante (< 6 mois)',
        seniorityMonths
      }
    };
  }
  const effectiveMonths = Math.floor(effectiveHours / MONTHLY_HOURS_THRESHOLD);
  const baseRate = isMinor ? 2.0 : 1.5;
  const baseDays = effectiveMonths * baseRate;
  const seniorityYears = Math.floor(seniorityMonths / 12);
  const bonusYears = Math.floor(seniorityYears / 5);
  const maxAnnualBonus = isMinor ? 6 : 12;
  const annualBonus = Math.min(bonusYears * 1.5, maxAnnualBonus);
  const monthlyBonus = annualBonus * (effectiveMonths / 12);
  const totalDays = baseDays + monthlyBonus;
  return {
    days: Math.round(totalDays * 100) / 100,
    details: {
      effectiveHours,
      effectiveMonths,
      isMinor,
      seniorityMonths,
      seniorityYears,
      baseRate,
      baseDays,
      monthlyBonus,
      annualBonus,
      bonusYears
    }
  };
}

export function evaluateFormula(formula: string, variables: Record<string, number | string>): number {
  if (!formula) return 0;
  let expression = formula;
  Object.entries(variables).forEach(([key, value]) => {
    expression = expression.replace(new RegExp(`\\b${key}\\b`, 'g'), value.toString());
  });
  try {
    const result = Function(`"use strict"; return (${expression})`)();
    return Number(result) || 0;
  } catch (error) {
    console.warn(`Formula evaluation error: ${formula}`, error);
    return 0;
  }
}

export function executeCalculation(testType: string, testData: Record<string, unknown>) {
  try {
    switch (testType) {
      case 'cnss': {
        return { ...calculateCNSS(testData.grossPay as number) };
      }
      case 'amo': {
        return { ...calculateAMO(testData.grossPay as number) };
      }
      case 'igr': {
        const igrResult = calculateIGR(
          testData.grossImposable as number,
          testData.dependentsCount as number,
          testData.cnssDeductible as number
        );
        return { igrAmount: igrResult.igr, details: igrResult.details };
      }
      case 'leave': {
        const leaveResult = calculateLeaveAccrual(
          testData.employee as { hire_date?: string; date_naissance?: string },
          testData.effectiveHours as number,
          new Date(testData.periodEndDate as string)
        );
        return { leaveAccrualDays: leaveResult.days, details: leaveResult.details };
      }
      case 'formula': {
        const formulaResult = evaluateFormula(
          testData.formula as string,
          testData.variables as Record<string, number | string>
        );
        return { formulaResult, details: { formula: testData.formula, variables: testData.variables } };
      }
      default:
        throw new Error(`Unknown test type: ${testType}`);
    }
  } catch (error: unknown) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    console.error(`Calculation error for ${testType}:`, errorMsg);
    return { details: { error: errorMsg } };
  }
}

function getAge(birthDate: Date, referenceDate: Date) {
  const age = referenceDate.getFullYear() - birthDate.getFullYear();
  const monthDiff = referenceDate.getMonth() - birthDate.getMonth();
  if (monthDiff < 0 || (monthDiff === 0 && referenceDate.getDate() < birthDate.getDate())) return age - 1;
  return age;
}
function getMonthsDifference(startDate: Date, endDate: Date) {
  const months = (endDate.getFullYear() - startDate.getFullYear()) * 12;
  return months + (endDate.getMonth() - startDate.getMonth());
}
