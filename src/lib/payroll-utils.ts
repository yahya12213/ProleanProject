// Payroll calculation utilities for Moroccan labor law

export interface PayrollConfig {
  cnss_ceiling: number;
  family_allowance_per_child: number;
  max_dependents: number;
  monthly_hours_threshold: number;
  default_window_day: number;
}

export interface IGRBracket {
  min: number;
  max: number;
  rate: number;
  deduction: number;
}

export interface CNSSBranch {
  code: string;
  name: string;
  rate: number;
  payer: 'SALARIE' | 'EMPLOYEUR';
  base: 'GROSS_PLAFONNEE' | 'GROSS';
}

export interface AMOConfig {
  employee_rate: number;
  employer_rate: number;
  solidarity_rate: number;
}

export interface PayrollLine {
  code: string;
  name: string;
  type: 'gain' | 'retenue';
  formula?: string;
  base_amount: number;
  percentage: number;
  soumis_cnss: boolean;
  soumis_amo: boolean;
  imposable_igr: boolean;
}

export interface TimeEntry {
  date: string;
  hours: number;
  code: string;
  type: 'normal' | 'overtime_25' | 'overtime_50' | 'overtime_100' | 'absence';
}

export interface Employee {
  id: string;
  nom: string;
  prenom: string;
  salaire_horaire: number;
  dependents_count: number;
  hire_date: string;
  date_naissance: string;
}

// Calculate period window dates (default 19th to 19th)
export function calculatePeriodWindow(
  year: number,
  month: number,
  windowDay: number = 19
): { start: Date; end: Date } {
  // Start from previous month's window day
  const start = new Date(year, month - 2, windowDay);
  // End at current month's window day (exclusive)
  const end = new Date(year, month - 1, windowDay);
  
  return { start, end };
}

// Calculate reference hours for the period
export function calculateReferenceHours(periodDays: number): number {
  // Standard calculation: period days / 30.44 average days per month * standard monthly hours
  const standardMonthlyHours = 191; // Legal working hours in Morocco
  return (periodDays / 30.44) * standardMonthlyHours;
}

// Aggregate timesheet data
export function aggregateTimesheet(
  entries: TimeEntry[],
  assimilatedCodes: string[] = [],
  nonAssimilatedCodes: string[] = []
) {
  const result = {
    normal_hours: 0,
    overtime_25: 0,
    overtime_50: 0,
    overtime_100: 0,
    absence_hours: 0,
    effective_hours: 0, // For leave calculation (191h rule)
    total_worked: 0
  };

  entries.forEach(entry => {
    switch (entry.type) {
      case 'normal':
        result.normal_hours += entry.hours;
        result.total_worked += entry.hours;
        break;
      case 'overtime_25':
        result.overtime_25 += entry.hours;
        result.total_worked += entry.hours;
        break;
      case 'overtime_50':
        result.overtime_50 += entry.hours;
        result.total_worked += entry.hours;
        break;
      case 'overtime_100':
        result.overtime_100 += entry.hours;
        result.total_worked += entry.hours;
        break;
      case 'absence':
        result.absence_hours += entry.hours;
        break;
    }

    // Count towards effective hours if work or assimilated absence
    if (entry.type !== 'absence' || assimilatedCodes.includes(entry.code)) {
      result.effective_hours += entry.hours;
    }
  });

  return result;
}

// Evaluate payroll formulas
export function evaluateFormula(
  formula: string,
  variables: Record<string, number>
): number {
  // Simple formula evaluator for payroll calculations
  let expression = formula;
  
  // Replace variables
  Object.entries(variables).forEach(([key, value]) => {
    expression = expression.replace(new RegExp(key, 'g'), value.toString());
  });

  try {
    // Basic arithmetic evaluation (secure for known formulas)
    return Function(`"use strict"; return (${expression})`)();
  } catch (error) {
    console.warn(`Formula evaluation error: ${formula}`, error);
    return 0;
  }
}

// Calculate CNSS contributions
export function calculateCNSS(
  grossPay: number,
  cnssBranches: CNSSBranch[],
  cnssPlafond: number
): { employee: number; employer: number; details: any[] } {
  let employee = 0;
  let employer = 0;
  const details: any[] = [];

  // CNSS subject base (capped)
  const cnssBase = Math.min(grossPay, cnssPlafond);

  cnssBranches.forEach(branch => {
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
      amount,
      payer: branch.payer
    });
  });

  return { employee, employer, details };
}

// Calculate AMO contributions
export function calculateAMO(
  grossPay: number,
  amoConfig: AMOConfig
): { employee: number; employer: number; solidarity: number } {
  const employee = grossPay * amoConfig.employee_rate;
  const employer = grossPay * amoConfig.employer_rate;
  const solidarity = grossPay * amoConfig.solidarity_rate;

  return { employee, employer, solidarity };
}

// Calculate IGR (Income Tax)
export function calculateIGR(
  grossImposable: number,
  dependentsCount: number,
  cnssDeductible: number,
  igrBrackets: IGRBracket[],
  familyAllowancePerChild: number = 41.67
): { igr: number; netImposableBase: number; details: any } {
  // Family deductions (max 6 dependents)
  const effectiveDependents = Math.min(dependentsCount, 6);
  const familyDeduction = effectiveDependents * familyAllowancePerChild;

  // Net imposable base
  const netImposableBase = Math.max(0, grossImposable - familyDeduction - cnssDeductible);

  // Round up to nearest 10 MAD (Moroccan tax rule)
  const roundedBase = Math.ceil(netImposableBase / 10) * 10;

  // Find applicable bracket
  const bracket = igrBrackets.find(b => roundedBase >= b.min && roundedBase < b.max);
  
  if (!bracket) {
    return { igr: 0, netImposableBase, details: { bracket: null, roundedBase } };
  }

  // Calculate IGR and round up to nearest MAD
  const igr = Math.ceil(roundedBase * bracket.rate - bracket.deduction);

  return {
    igr: Math.max(0, igr),
    netImposableBase,
    details: {
      bracket,
      roundedBase,
      familyDeduction,
      cnssDeduction: cnssDeductible,
      effectiveDependents
    }
  };
}

// Calculate leave accrual (Moroccan 191h rule)
export function calculateLeaveAccrual(
  employee: Employee,
  effectiveHours: number,
  periodEndDate: Date
): { days: number; details: any } {
  const birthDate = new Date(employee.date_naissance);
  const hireDate = new Date(employee.hire_date);
  
  // Check age (different rules for minors)
  const isMinor = getAge(birthDate, periodEndDate) < 18;
  
  // Check seniority (must have 6 months to earn leave)
  const seniorityMonths = getMonthsDifference(hireDate, periodEndDate);
  
  if (seniorityMonths < 6) {
    return { days: 0, details: { reason: 'Ancienneté insuffisante (< 6 mois)' } };
  }

  // Calculate effective months (191h = 1 month)
  const effectiveMonths = Math.floor(effectiveHours / 191);
  
  // Base leave rate
  const baseRate = isMinor ? 2.0 : 1.5; // days per month
  const baseDays = effectiveMonths * baseRate;

  // Seniority bonus (+1.5 days per 5 years, max 30 days/year)
  const seniorityYears = Math.floor(seniorityMonths / 12);
  const bonusYears = Math.floor(seniorityYears / 5);
  const annualBonus = Math.min(bonusYears * 1.5, 30 - 18); // 18 = base annual days for adults
  const monthlyBonus = annualBonus * (effectiveMonths / 12);

  const totalDays = baseDays + monthlyBonus;

  return {
    days: Math.round(totalDays * 100) / 100, // Round to 2 decimals
    details: {
      effectiveHours,
      effectiveMonths,
      isMinor,
      seniorityMonths,
      seniorityYears,
      baseRate,
      baseDays,
      monthlyBonus,
      annualBonus
    }
  };
}

// Calculate net pay (rounded up to nearest MAD)
export function calculateNetPay(
  grossPay: number,
  totalDeductions: number
): number {
  const net = grossPay - totalDeductions;
  return Math.ceil(net); // Always round up
}

// Get last working day of month
export function getLastWorkingDay(year: number, month: number, holidays: Date[] = []): Date {
  const lastDay = new Date(year, month + 1, 0);
  
  // Go backwards to find last working day
  while (isWeekendOrHoliday(lastDay, holidays)) {
    lastDay.setDate(lastDay.getDate() - 1);
  }
  
  return lastDay;
}

// Helper functions
function getAge(birthDate: Date, referenceDate: Date): number {
  const age = referenceDate.getFullYear() - birthDate.getFullYear();
  const monthDiff = referenceDate.getMonth() - birthDate.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && referenceDate.getDate() < birthDate.getDate())) {
    return age - 1;
  }
  
  return age;
}

function getMonthsDifference(startDate: Date, endDate: Date): number {
  const months = (endDate.getFullYear() - startDate.getFullYear()) * 12;
  return months + (endDate.getMonth() - startDate.getMonth());
}

function isWeekendOrHoliday(date: Date, holidays: Date[] = []): boolean {
  // Check if weekend (Saturday = 6, Sunday = 0)
  if (date.getDay() === 0 || date.getDay() === 6) return true;
  
  // Check if holiday
  return holidays.some(holiday => 
    holiday.getTime() === date.getTime()
  );
}