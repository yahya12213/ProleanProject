import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.3'
import { prisma } from '../../../backend/prisma/client';
import { config as dotenvConfig } from 'dotenv';
dotenvConfig();

// Extend interfaces with missing properties
interface PayrollConfig {
  cnss_branches?: Array<{ nom: string; taux_employe: number; taux_employeur: number }>;
  igr_brackets?: Array<{ min: number; max: number; taux: number }>;
  family_allowance_per_child?: number;
  absence_codes?: string[];
  cnss_plafond?: number;
  payroll_settings?: {
    monthly_hours_threshold?: number;
  };
  amo_config?: {
    employee_rate: number;
    employer_rate: number;
  };
}

interface Employee {
  id: string;
  user_id: string;
  nom?: string;
  prenom?: string;
  payrollEnabled?: boolean;
  salaire_horaire?: number;
  salaire_base?: number;
  dependents_count?: number;
  date_naissance?: string;
  // Add other relevant fields
}

// Define additional types for employees, segments, and other objects
interface Segment {
  segmentId: string;
}

interface TimeEntry {
  timestamp_pointage: string;
  // Add other relevant fields
}

interface PayrollLine {
  ordreAffichage?: number;
  formula?: string;
  percentage?: number;
  base_amount?: number;
  type?: string;
  code?: string;
  name?: string;
}

interface Period {
  startDate: string;
  endDate: string;
  id?: string;
  window_config?: Record<string, unknown>;
}

interface Timesheet {
  normal_hours: number;
  overtime_25: number;
  overtime_50: number;
  overtime_100: number;
  total_worked: number;
  effective_hours?: number;
  absence_hours?: number;
}

// Replace Deno.env.get with process.env
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// Replace untyped config object with typed PayrollConfig
const config: PayrollConfig = {};
const configItems: Array<{ key: string; value: string | number }> = await prisma.payrollConfig.findMany();
configItems.forEach(item => {
  if (item.key in config) {
    const key = item.key as keyof PayrollConfig;
    config[key] = item.value as PayrollConfig[keyof PayrollConfig];
  }
});

// Define corsHeaders
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// Ensure default values are set
config.cnss_branches = config.cnss_branches || [
  { nom: 'Prestations familiales', taux_employe: 0, taux_employeur: 6.4 },
  { nom: 'Prestations sociales courtes', taux_employe: 0.33, taux_employeur: 0.67 },
  { nom: 'Prestations sociales longues', taux_employe: 0.33, taux_employeur: 0.67 },
  { nom: 'AMO', taux_employe: 2, taux_employeur: 3.17 },
  { nom: 'Taxe de formation professionnelle', taux_employe: 0, taux_employeur: 1.6 }
];
config.cnss_plafond = config.cnss_plafond || 6000;
config.igr_brackets = config.igr_brackets || [
  { min: 0, max: 2500, taux: 0 },
  { min: 2500, max: 4166.67, taux: 10 },
  { min: 4166.67, max: 5000, taux: 20 },
  { min: 5000, max: 6666.67, taux: 30 },
  { min: 6666.67, max: 15000, taux: 34 },
  { min: 15000, max: Infinity, taux: 38 }
];
config.family_allowance_per_child = config.family_allowance_per_child || 300;

// Force redeploy v1.2 - Fix function deployment

serve(async (req: Request) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabase = createClient(
      SUPABASE_URL,
      SUPABASE_SERVICE_ROLE_KEY
    );

    const { periodId, segmentId, scope, requestingUserId } = await req.json();
    
    console.log(`Starting payroll calculation for period ${periodId}, scope: ${scope}, segmentId: ${segmentId}, requestingUser: ${requestingUserId}`);
    
    // Get the requesting user and their permissions
    const { data: requestingUser } = await supabase
      .from('profiles')
      .select('id, nom, prenom')
      .eq('user_id', requestingUserId)
      .single();

    if (!requestingUser) {
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Get period details
    const { data: period, error: periodError } = await supabase
      .from('payroll_periods')
      .select('*')
      .eq('id', periodId)
      .single();

    if (periodError || !period) {
      return new Response(JSON.stringify({ error: 'Period not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Set default configuration if needed
    // if (!config.cnss_branches) {
    //   config.cnss_branches = [
    //     { nom: 'Prestations familiales', taux_employe: 0, taux_employeur: 6.4 },
    //     { nom: 'Prestations sociales courtes', taux_employe: 0.33, taux_employeur: 0.67 },
    //     { nom: 'Prestations sociales longues', taux_employe: 0.33, taux_employeur: 0.67 },
    //     { nom: 'AMO', taux_employe: 2, taux_employeur: 3.17 },
    //     { nom: 'Taxe de formation professionnelle', taux_employe: 0, taux_employeur: 1.6 }
    //   ];
    // }
    
    // if (!config.cnss_plafond) config.cnss_plafond = 6000;
    // if (!config.igr_brackets) {
    //   config.igr_brackets = [
    //     { min: 0, max: 2500, taux: 0 },
    //     { min: 2500, max: 4166.67, taux: 10 },
    //     { min: 4166.67, max: 5000, taux: 20 },
    //     { min: 5000, max: 6666.67, taux: 30 },
    //     { min: 6666.67, max: 15000, taux: 34 },
    //     { min: 15000, max: Infinity, taux: 38 }
    //   ];
    // }
    // if (!config.family_allowance_per_child) config.family_allowance_per_child = 300;

    // Get payroll lines
    const lines = await prisma.payrollLines.findMany({
      where: { isActive: true },
      orderBy: { ordreAffichage: 'asc' }
    });

    // Determine employees to process based on scope
    let employees: Employee[] = [];
    
    if (scope === 'segment' && segmentId) {
      employees = await prisma.employees.findMany({
        where: { segmentId: segmentId, payrollEnabled: true }
      });
    } else if (scope === 'employees' && segmentId) {
      // For "employees" scope, get from specific segment
      employees = await prisma.employees.findMany({
        where: { segmentId: segmentId, payrollEnabled: true }
      });
    } else if (scope === 'all') {
      // Get user's primary segment for access control
      const userPrimarySegment = await getUserPrimarySegment(supabase, requestingUserId);
      console.log('User primary segment:', userPrimarySegment);
      
      if (userPrimarySegment) {
        // Get all segments the user has access to
        const userSegments = await prisma.centreAssignments.findMany({
          where: { userId: requestingUserId, isActive: true },
          select: { centres: { select: { segmentId: true } } }
        });
        const accessibleSegments = userSegments.map((s: { centres: Segment }) => s.centres.segmentId);
        console.log(`User has access to ${accessibleSegments.length} segments:`, accessibleSegments);
        
        // Get employees from all accessible segments
        employees = await prisma.employees.findMany({
          where: { segmentId: { in: accessibleSegments }, payrollEnabled: true }
        });
      }
      
      // Fallback: get all employees directly (for admin scope) - CORRECTION: Condition SQL plus robuste
      if (employees.length === 0) {
        const { data: allEmployees, error: allError } = await supabase
          .from('profiles')
          .select('id, nom, prenom, user_id, salaire_base, salaire_horaire, dependents_count, date_embauche, date_naissance, payroll_enabled')
          .eq('payroll_enabled', true)
          .not('user_id', 'is', null);
        
        if (allError) {
          console.error('Error getting admin employees:', allError);
          employees = [];
        } else {
          console.log(`Processing all employees: ${allEmployees?.length || 0} total employees found`);
          employees = allEmployees || [];
        }
      }
    } else {
      return new Response(JSON.stringify({ error: 'Invalid scope or missing segmentId' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    console.log(`About to process ${employees.length} employees for calculation`);

    // Process each employee
    const results = [];
    for (const employee of employees) {
      try {
        console.log(`Processing employee: ${employee.nom} ${employee.prenom} (ID: ${employee.id})`);
        const result = await calculateEmployeePayroll(employee, period, config, lines || []);
        results.push(result);
        console.log(`Successfully calculated payroll for ${employee.nom} ${employee.prenom}`);
      } catch (error) {
        console.error(`Error calculating payroll for employee ${employee.id}:`, error);
        // Continue processing other employees
      }
    }

    // Save results to database
    if (results.length > 0) {
      await prisma.payrollResults.createMany({ data: results });
    }

    // Update period status
    await prisma.payrollPeriods.update({
      where: { id: periodId },
      data: { status: 'calculated' }
    });

    console.log(`Payroll calculation completed. Processed: ${results.length} employees`);

    return new Response(JSON.stringify({ 
      success: true, 
      employeesProcessed: results.length,
      message: `Payroll calculated successfully for ${results.length} employees`
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Error in payroll calculation:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

async function calculateEmployeePayroll(
  employee: Employee,
  period: Period,
  config: PayrollConfig,
  lines: PayrollLine[]
): Promise<void> {
  console.log(`Calculating payroll for: ${employee.nom} ${employee.prenom}`);
  
  // Fetch timesheet data for the period
  const timeEntries: TimeEntry[] = await prisma.pointages.findMany({
    where: {
      profileId: employee.id,
      timestampPointage: {
        gte: period.startDate,
        lte: period.endDate
      }
    }
  });

  console.log(`Found ${timeEntries.length} time entries for employee ${employee.nom} ${employee.prenom}`);

  // Aggregate timesheet
  const timesheet = aggregateTimesheet(timeEntries, config.absence_codes);
  console.log(`Timesheet aggregated - Normal: ${timesheet.normal_hours}h, Overtime: ${timesheet.overtime_25 + timesheet.overtime_50 + timesheet.overtime_100}h, Total worked: ${timesheet.total_worked}h`);

  // Fetch employee-specific payroll settings
  console.log(`Fetching payroll settings for employee: ${employee.nom} ${employee.prenom} (ID: ${employee.id})`);
  
  const settings = await prisma.payrollSettings.findMany({
    where: { employeeId: employee.id }
  });

  const settingsError = null; // Replace with actual error handling logic

  if (settingsError) {
    console.error('Error fetching payroll settings:', settingsError);
    // Use default settings if fetch fails
    const defaultSettings = {
      cnss_enabled: true,
      amo_enabled: true,
      igr_enabled: true,
      mutuelle_enabled: false,
      autres_retenues: {}
    };
    console.log('Using default payroll settings due to error');
    
    return await calculateWithSettings(employee, defaultSettings, timesheet, period, config, lines);
  }

  // If no settings found, create default settings
  if (!settings) {
    console.log('No payroll settings found, creating default settings');
    const defaultSettings = {
      cnss_enabled: true,
      amo_enabled: true,
      igr_enabled: true,
      mutuelle_enabled: false,
      autres_retenues: {}
    };
    
    return await calculateWithSettings(employee, defaultSettings, timesheet, period, config, lines);
  }

  console.log(`Found payroll settings: CNSS=${settings.cnss_enabled}, AMO=${settings.amo_enabled}, IGR=${settings.igr_enabled}, Mutuelle=${settings.mutuelle_enabled}`);
  
  return await calculateWithSettings(employee, settings, timesheet, period, config, lines);
}

// Update PayrollSettings type to include autres_retenues
interface PayrollSettings {
  cnss_enabled: boolean;
  amo_enabled: boolean;
  igr_enabled: boolean;
  mutuelle_enabled: boolean;
  autres_retenues: Record<string, number>;
}

async function calculateWithSettings(
  employee: Employee,
  settings: PayrollSettings,
  timesheet: Timesheet,
  period: Period,
  config: PayrollConfig,
  lines: PayrollLine[]
): Promise<void> {
  const startDate = new Date(period.start_date);
  const endDate = new Date(period.end_date);
  const periodDays = Math.floor((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24));
  const referenceHours = (periodDays / 30.44) * (config.payroll_settings?.monthly_hours_threshold || 191);

  // Setup calculation variables - UNIQUEMENT sur salaire horaire
  if (!employee.salaire_horaire || employee.salaire_horaire <= 0) {
    throw new Error(`Salaire horaire manquant pour l'employé ${employee.nom} ${employee.prenom}`);
  }
  
  const salaryRate = employee.salaire_horaire;
  
  // Calculer le salaire brut = salaire horaire × heures travaillées
  const grossPay = salaryRate * timesheet.effective_hours;
  console.log(`Gross pay calculation: ${salaryRate} MAD/h × ${timesheet.effective_hours}h = ${grossPay} MAD`);
  
  const variables = {
    TAUX_HORAIRE: salaryRate,
    HEURES_REF: referenceHours,
    HEURES_TRAVAILLEES: timesheet.effective_hours,
    HS_25: timesheet.overtime_25,
    HS_50: timesheet.overtime_50,
    HS_100: timesheet.overtime_100,
    BASE: grossPay // Base = salaire horaire × heures travaillées
  };

  // Calculate line amounts
  const lineResults = [];
  let totalDeductions = 0;

  for (const line of lines) {
    let amount = 0;
    
    if (line.formula) {
      amount = evaluateFormula(line.formula, variables);
    } else if (line.percentage > 0) {
      amount = grossPay * (line.percentage / 100);
    } else {
      amount = line.base_amount || 0;
    }

    if (line.type === 'retenue') {
      totalDeductions += amount;
    }
    // Les gains sont déjà calculés dans grossPay = salaire_horaire × heures

    lineResults.push({
      code: line.code,
      name: line.name,
      type: line.type,
      amount: Math.round(amount * 100) / 100
    });
  }

  // PHASE 3: Calculate standard deductions ONLY if enabled
  console.log(`Calculating deductions - CNSS: ${settings.cnss_enabled}, AMO: ${settings.amo_enabled}, IGR: ${settings.igr_enabled}`);
  
  const cnssResult: DeductionResult = calculateCNSS(grossPay, config.cnss_branches || [], config.cnss_plafond || 0);
  const amoResult: DeductionResult = calculateAMO(grossPay, config.amo_config || { employee_rate: 0, employer_rate: 0 });
  const igrResult: { igr: number; netImposableBase: number; details: Record<string, number> } = calculateIGR(
    grossImposable,
    employee.dependents_count || 0,
    cnssResult.employee,
    config.igr_brackets || [],
    config.family_allowance_per_child || 0
  );

  console.log(`Deduction results - CNSS employee: ${cnssResult.employee}, AMO employee: ${amoResult.employee}, IGR: ${igrResult.igr}`);
  
  // Calculate other deductions from settings
  let autresRetenues = 0;
  if (settings.autres_retenues && typeof settings.autres_retenues === 'object') {
    Object.entries(settings.autres_retenues).forEach(([key, value]) => {
      if (typeof value === 'number') {
        autresRetenues += value;
      }
    });
  }

  // Calculate leave accrual
  const leaveAccrual = calculateLeaveAccrual(
    employee,
    timesheet.effective_hours,
    endDate,
    config.payroll_settings?.monthly_hours_threshold || 191
  );

  // Calculate final net pay (rounded up)
  const totalPayrollDeductions = cnssResult.employee + amoResult.employee + igrResult.igr + autresRetenues;
  const netPay = Math.ceil(grossPay - totalDeductions - totalPayrollDeductions);

  console.log(`Final calculation for ${employee.nom} ${employee.prenom}: Gross=${grossPay}, Total deductions=${totalPayrollDeductions}, Net=${netPay}`);

  return {
    period_id: period.id,
    profile_id: employee.id,
    gross_pay: Math.round(grossPay * 100) / 100,
    net_pay: netPay,
    cnss_employee: Math.round(cnssResult.employee * 100) / 100,
    cnss_employer: Math.round(cnssResult.employer * 100) / 100,
    amo_employee: Math.round(amoResult.employee * 100) / 100,
    amo_employer: Math.round(amoResult.employer * 100) / 100,
    igr_amount: Math.round(igrResult.igr * 100) / 100,
    leave_accrual_days: Math.round(leaveAccrual.days * 100) / 100,
    worked_hours: timesheet.total_worked,
    overtime_hours: timesheet.overtime_25 + timesheet.overtime_50 + timesheet.overtime_100,
    absence_hours: timesheet.absence_hours,
    lines_detail: lineResults,
    calculation_snapshot: {
      period_window: period.window_config,
      config_used: config,
      variables_used: variables,
      reference_hours: referenceHours
    }
  };
}

function aggregateTimesheet(entries: Array<{ timestamp_pointage: string }>, absenceCodes: string[]): Timesheet {
  const result = {
    normal_hours: 0,
    overtime_25: 0,
    overtime_50: 0,
    overtime_100: 0,
    absence_hours: 0,
    effective_hours: 0,
    total_worked: 0
  };

  // Group entries by date and calculate worked hours from entry/exit pairs
  const dailyEntries = new Map();
  
  entries.forEach(entry => {
    const date = entry.timestamp_pointage.split('T')[0]; // Extract date from timestamp
    
    if (!dailyEntries.has(date)) {
      dailyEntries.set(date, []);
    }
    dailyEntries.get(date).push(entry);
  });

  // Process each day
  dailyEntries.forEach((dayEntries, date) => {
    // Sort by timestamp
    dayEntries.sort((a: { timestamp_pointage: string }, b: { timestamp_pointage: string }) =>
      new Date(a.timestamp_pointage).getTime() - new Date(b.timestamp_pointage).getTime()
    );
    
    let entryTime = null;
    let exitTime = null;
    
    // Find first entry and last exit of the day
    for (const entry of dayEntries) {
      if (entry.type_pointage === 'entree' && !entryTime) {
        entryTime = new Date(entry.timestamp_pointage);
      } else if (entry.type_pointage === 'sortie') {
        exitTime = new Date(entry.timestamp_pointage);
      }
    }
    
    // Calculate hours worked if we have both entry and exit
    if (entryTime && exitTime && exitTime > entryTime) {
      const hoursWorked = (exitTime.getTime() - entryTime.getTime()) / (1000 * 60 * 60);
      
      // Standard working day is 8 hours, overtime starts after that
      const standardHours = Math.min(hoursWorked, 8);
      const overtimeHours = Math.max(0, hoursWorked - 8);
      
      result.normal_hours += standardHours;
      result.total_worked += hoursWorked;
      result.effective_hours += hoursWorked;
      
      // Simple overtime classification (first 2 hours at 25%, rest at 50%)
      if (overtimeHours > 0) {
        const overtime25 = Math.min(overtimeHours, 2);
        const overtime50 = Math.max(0, overtimeHours - 2);
        
        result.overtime_25 += overtime25;
        result.overtime_50 += overtime50;
      }
      
      console.log(`Date ${date}: Entry ${entryTime.toISOString()}, Exit ${exitTime.toISOString()}, Hours: ${hoursWorked.toFixed(2)}`);
    } else {
      console.warn(`Incomplete day ${date}: Entry ${entryTime ? entryTime.toISOString() : 'missing'}, Exit ${exitTime ? exitTime.toISOString() : 'missing'}`);
    }
  });

  return result;
}

function evaluateFormula(formula: string, variables: Record<string, number>): number {
  try {
    let expression = formula;
    Object.entries(variables).forEach(([key, value]) => {
      const regex = new RegExp(`\\b${key}\\b`, 'g');
      expression = expression.replace(regex, value.toString());
    });
    
    // Simple arithmetic evaluation (be careful in production!)
    const result = Function(`"use strict"; return (${expression})`)();
    return isNaN(result) ? 0 : result;
  } catch (error) {
    console.error('Formula evaluation error:', error);
    return 0;
  }
}

function calculateCNSS(grossPay: number, cnssBranches: Array<{ nom: string; taux_employe: number; taux_employeur: number }>, cnssPlafond: number): number {
  const cappedSalary = Math.min(grossPay, cnssPlafond);
  let employeeTotal = 0;
  let employerTotal = 0;
  const details = [];

  for (const branch of cnssBranches) {
    const employeeContrib = cappedSalary * (branch.taux_employe / 100);
    const employerContrib = cappedSalary * (branch.taux_employeur / 100);
    
    employeeTotal += employeeContrib;
    employerTotal += employerContrib;
    
    details.push({
      branche: branch.nom,
      assiette: cappedSalary,
      taux_employe: branch.taux_employe,
      taux_employeur: branch.taux_employeur,
      cotisation_employe: employeeContrib,
      cotisation_employeur: employerContrib
    });
  }

  return {
    employee: employeeTotal,
    employer: employerTotal,
    details
  };
}

function calculateAMO(grossPay: number, amoConfig: { employee_rate: number; employer_rate: number }): number {
  return {
    employee: grossPay * (amoConfig.taux_employe / 100),
    employer: grossPay * (amoConfig.taux_employeur / 100),
    solidarity: grossPay * (amoConfig.taux_solidarite / 100)
  };
}

function calculateIGR(
  grossImposable: number,
  dependentsCount: number,
  cnssEmployee: number,
  brackets: Array<{ min: number; max: number; taux: number }>,
  familyAllowancePerChild: number
): number {
  const effectiveDependents = Math.min(dependentsCount, 6);
  const familyDeduction = effectiveDependents * familyAllowancePerChild;
  
  const netImposableBase = Math.max(0, grossImposable - familyDeduction - cnssEmployee);
  const roundedBase = Math.ceil(netImposableBase / 10) * 10;
  
  const bracket = brackets.find(b => roundedBase >= b.min && roundedBase < b.max);
  
  if (!bracket) return { igr: 0 };
  
  const igr = Math.ceil(roundedBase * bracket.rate - bracket.deduction);
  return { igr: Math.max(0, igr) };
}

function calculateLeaveAccrual(employee: Employee, effectiveHours: number, periodEndDate: Date, threshold: number): { days: number } {
  if (!employee.date_embauche) return { days: 0 };
  
  const hireDate = new Date(employee.date_embauche);
  const seniorityMonths = getMonthsDifference(hireDate, periodEndDate);
  
  if (seniorityMonths < 6) return { days: 0 };
  
  const effectiveMonths = Math.floor(effectiveHours / threshold);
  const isMinor = employee.date_naissance ? 
    getAge(new Date(employee.date_naissance), periodEndDate) < 18 : false;
  
  const baseRate = isMinor ? 2.0 : 1.5;
  const baseDays = effectiveMonths * baseRate;
  
  return { days: baseDays };
}

function getMonthsDifference(startDate: Date, endDate: Date): number {
  return (endDate.getFullYear() - startDate.getFullYear()) * 12 + 
         (endDate.getMonth() - startDate.getMonth());
}

function getAge(birthDate: Date, referenceDate: Date): number {
  const age = referenceDate.getFullYear() - birthDate.getFullYear();
  const monthDiff = referenceDate.getMonth() - birthDate.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && referenceDate.getDate() < birthDate.getDate())) {
    return age - 1;
  }
  
  return age;
}

// Helper function to get user's primary segment (first assigned chronologically)
async function getUserPrimarySegment(prisma: typeof import('../../../backend/prisma/client'), userId: string): Promise<string | null> {
  const { data: assignments, error } = await prisma
    .from('centre_assignments')
    .select(`
      centres!inner(segment_id),
      assigned_at
    `)
    .eq('user_id', userId)
    .eq('is_active', true)
    .order('assigned_at', { ascending: true })
    .limit(1);

  if (error) {
    console.error('Error getting user primary segment:', error);
    return null;
  }

  return assignments && assignments.length > 0 ? {
    segment_id: assignments[0].centres.segment_id,
    assigned_at: assignments[0].assigned_at
  } : null;
}

// Helper function to check if user can access a specific segment
async function canAccessSegment(prisma: typeof import('../../../backend/prisma/client'), userId: string, segmentId: string): Promise<boolean> {
  const { data: assignments, error } = await prisma
    .from('centre_assignments')
    .select(`
      centres!inner(segment_id)
    `)
    .eq('user_id', userId)
    .eq('is_active', true)
    .eq('centres.segment_id', segmentId);

  if (error) {
    console.error('Error checking segment access:', error);
    return false;
  }

  return assignments && assignments.length > 0;
}

// Helper function to get employees from a specific segment
async function getEmployeesFromSegment(prisma: typeof import('../../../backend/prisma/client'), segmentId: string): Promise<Employee[]> {
  console.log(`Getting employees from segment: ${segmentId}`);
  
  // First get centres in this segment
  const { data: centres, error: centresError } = await prisma
    .from('centres')
    .select('id')
    .eq('segment_id', segmentId)
    .eq('is_active', true);

  if (centresError) {
    console.error('Error getting centres:', centresError);
    return [];
  }

  console.log(`Found ${centres?.length || 0} centres in segment ${segmentId}`);

  if (!centres || centres.length === 0) {
    console.warn(`No centres found for segment: ${segmentId}`);
    return [];
  }

  const centreIds = centres.map((c: { id: string }) => c.id);
  console.log(`Centre IDs for segment ${segmentId}:`, centreIds);

  // Get user assignments to these centres
  const { data: assignments, error: assignmentsError } = await prisma
    .from('centre_assignments')
    .select('user_id')
    .in('centre_id', centreIds)
    .eq('is_active', true);

  if (assignmentsError) {
    console.error('Error getting assignments:', assignmentsError);
    return [];
  }

  console.log(`Found ${assignments?.length || 0} assignments for segment ${segmentId}`);

  if (!assignments || assignments.length === 0) {
    console.warn(`No assignments found for segment: ${segmentId}`);
    return [];
  }

  const userIds = assignments.map((a: { user_id: string }) => a.user_id);
  console.log(`User IDs assigned to segment ${segmentId}:`, userIds);

  // Get employee profiles - CORRECTION: Filtrer les user_id null avant la requête
  const validUserIds = userIds.filter((id: string | null | undefined) => id !== null && id !== undefined);
  console.log(`Valid user IDs (after null filter):`, validUserIds);
  
  if (validUserIds.length === 0) {
    console.warn(`No valid user IDs found for segment: ${segmentId}`);
    return [];
  }
  
  const { data: employees, error: employeesError } = await supabase
    .from('profiles')
    .select('id, nom, prenom, user_id, salaire_base, salaire_horaire, dependents_count, date_embauche, date_naissance, payroll_enabled')
    .in('user_id', validUserIds)
    .eq('payroll_enabled', true);

  if (employeesError) {
    console.error('Error getting employees:', employeesError);
    return [];
  }

  console.log(`Found ${employees?.length || 0} payroll-enabled employees in segment ${segmentId}`);
  if (employees && employees.length > 0) {
    console.log('Employees found:', employees.map((e: Employee) => ({ nom: e.nom, prenom: e.prenom, user_id: e.user_id })));
  }
  
  return employees || [];
}