// ...existing code...

export interface PayrollTestConfig {
  testRunId: string;
  periodId?: string;
  logLevel: 'error' | 'warning' | 'info' | 'debug';
}

export interface PayrollValidationResult {
  isValid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  metrics: PerformanceMetric[];
}

export interface ValidationError {
  type: string;
  field: string;
  expected: number;
  actual: number;
  difference: number;
  percentage: number;
  severity: 'critical' | 'major' | 'minor';
}

export interface ValidationWarning {
  type: string;
  message: string;
  suggestion?: string;
}

export interface PerformanceMetric {
  name: string;
  value: number;
  unit: string;
  benchmark?: number;
  isWithinThreshold: boolean;
}

/**
 * Logger pour les opérations de paie avec niveaux de détail
 */
export class PayrollLogger {
  private config: PayrollTestConfig;

  constructor(config: PayrollTestConfig) {
    this.config = config;
  }

  async logCalculation(
    periodId: string | null,
    profileId: string | null,
    operationType: string,
    status: 'started' | 'success' | 'warning' | 'error',
    inputData: any,
    outputData?: any,
    errorDetails?: any,
    warnings?: any[],
    executionTimeMs?: number
  ): Promise<string> {
    try {
  // TODO: Remplacer par appel à l'API Express locale
        .from('payroll_calculation_logs')
        .insert({
          period_id: periodId,
          profile_id: profileId,
          operation_type: operationType,
          status,
          execution_time_ms: executionTimeMs,
          input_data: inputData,
          output_data: outputData,
          error_details: errorDetails,
          warnings: warnings || [],
          metadata: {
            test_run_id: this.config.testRunId,
            log_level: this.config.logLevel
          }
        })
        .select('id')
        .single();

      if (error) {
        console.error('Erreur logging:', error);
        throw error;
      }

      return data.id;
    } catch (error) {
      console.error('Erreur critique logging:', error);
      throw error;
    }
  }

  async logPerformanceMetric(
    periodId: string | null,
    metricName: string,
    value: number,
    unit: string,
    benchmark?: number
  ): Promise<void> {
  // TODO: Remplacer par appel à l'API Express locale
      period_id: periodId,
      metric_name: metricName,
      metric_value: value,
      metric_unit: unit,
      benchmark_value: benchmark,
      is_within_threshold: benchmark ? value <= benchmark : null
    });
  }
}

/**
 * Validateur automatique pour les calculs de paie
 */
export class PayrollValidator {
  private logger: PayrollLogger;
  
  constructor(logger: PayrollLogger) {
    this.logger = logger;
  }

  /**
   * Valide un résultat de paie complet
   */
  async validatePayrollResult(payrollResultId: string): Promise<PayrollValidationResult> {
    const startTime = Date.now();
    
    try {
      // Récupérer le résultat de paie
  // TODO: Remplacer par appel à l'API Express locale
        .from('payroll_results')
        .select('*, profiles(*), payroll_periods(*)')
        .eq('id', payrollResultId)
        .single();

      if (error) throw error;

      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];
      const metrics: PerformanceMetric[] = [];

      // Validation CNSS
      const cnssValidation = this.validateCNSS(
        payrollResult.gross_pay,
        payrollResult.cnss_employee,
        payrollResult.cnss_employer
      );
      errors.push(...cnssValidation.errors);
      warnings.push(...cnssValidation.warnings);

      // Validation AMO
      const amoValidation = this.validateAMO(
        payrollResult.gross_pay,
        payrollResult.amo_employee,
        payrollResult.amo_employer
      );
      errors.push(...amoValidation.errors);
      warnings.push(...amoValidation.warnings);

      // Validation IGR
      const igrValidation = this.validateIGR(
        payrollResult.gross_pay,
        payrollResult.igr_amount,
        payrollResult.profiles.dependents_count || 0
      );
      errors.push(...igrValidation.errors);
      warnings.push(...igrValidation.warnings);

      // Validation cohérence générale
      const coherenceValidation = this.validateCoherence(payrollResult);
      errors.push(...coherenceValidation.errors);
      warnings.push(...coherenceValidation.warnings);

      const executionTime = Date.now() - startTime;
      
      // Métriques de performance
      metrics.push({
        name: 'validation_time',
        value: executionTime,
        unit: 'ms',
        benchmark: 500,
        isWithinThreshold: executionTime <= 500
      });

      // Logger le résultat
      await this.logger.logCalculation(
        payrollResult.period_id,
        payrollResult.profile_id,
        'validation',
        errors.length > 0 ? 'error' : warnings.length > 0 ? 'warning' : 'success',
        { payroll_result_id: payrollResultId },
        { errors_count: errors.length, warnings_count: warnings.length },
        errors.length > 0 ? { validation_errors: errors } : null,
        warnings,
        executionTime
      );

      return {
        isValid: errors.length === 0,
        errors,
        warnings,
        metrics
      };

    } catch (error) {
      await this.logger.logCalculation(
        null,
        null,
        'validation',
        'error',
        { payroll_result_id: payrollResultId },
        null,
        { error: error.message },
        [],
        Date.now() - startTime
      );
      
      throw error;
    }
  }

  private validateCNSS(grossPay: number, employeeCnss: number, employerCnss: number) {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    
    const expectedEmployee = Math.round(Math.min(grossPay, 6000) * 0.04 * 100) / 100;
    const expectedEmployer = Math.round(Math.min(grossPay, 6000) * 0.076 * 100) / 100;
    
    if (Math.abs(employeeCnss - expectedEmployee) > 0.01) {
      errors.push({
        type: 'cnss_calculation',
        field: 'cnss_employee',
        expected: expectedEmployee,
        actual: employeeCnss,
        difference: employeeCnss - expectedEmployee,
        percentage: expectedEmployee !== 0 ? ((employeeCnss - expectedEmployee) / expectedEmployee) * 100 : 0,
        severity: Math.abs(employeeCnss - expectedEmployee) > 10 ? 'critical' : 'major'
      });
    }
    
    if (Math.abs(employerCnss - expectedEmployer) > 0.01) {
      errors.push({
        type: 'cnss_calculation',
        field: 'cnss_employer',
        expected: expectedEmployer,
        actual: employerCnss,
        difference: employerCnss - expectedEmployer,
        percentage: expectedEmployer !== 0 ? ((employerCnss - expectedEmployer) / expectedEmployer) * 100 : 0,
        severity: Math.abs(employerCnss - expectedEmployer) > 10 ? 'critical' : 'major'
      });
    }
    
    if (grossPay > 6000) {
      warnings.push({
        type: 'cnss_plafond',
        message: `Salaire au-dessus du plafond CNSS (${grossPay} > 6000)`,
        suggestion: 'Vérifier que le plafond CNSS est correctement appliqué'
      });
    }
    
    return { errors, warnings };
  }

  private validateAMO(grossPay: number, employeeAmo: number, employerAmo: number) {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    
    const expectedEmployee = Math.round(grossPay * 0.02 * 100) / 100;
    const expectedEmployer = Math.round(grossPay * 0.034 * 100) / 100;
    
    if (Math.abs(employeeAmo - expectedEmployee) > 0.01) {
      errors.push({
        type: 'amo_calculation',
        field: 'amo_employee',
        expected: expectedEmployee,
        actual: employeeAmo,
        difference: employeeAmo - expectedEmployee,
        percentage: expectedEmployee !== 0 ? ((employeeAmo - expectedEmployee) / expectedEmployee) * 100 : 0,
        severity: Math.abs(employeeAmo - expectedEmployee) > 5 ? 'major' : 'minor'
      });
    }
    
    if (Math.abs(employerAmo - expectedEmployer) > 0.01) {
      errors.push({
        type: 'amo_calculation',
        field: 'amo_employer',
        expected: expectedEmployer,
        actual: employerAmo,
        difference: employerAmo - expectedEmployer,
        percentage: expectedEmployer !== 0 ? ((employerAmo - expectedEmployer) / expectedEmployer) * 100 : 0,
        severity: Math.abs(employerAmo - expectedEmployer) > 5 ? 'major' : 'minor'
      });
    }
    
    return { errors, warnings };
  }

  private validateIGR(grossPay: number, igr: number, dependentsCount: number) {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    
    const familyAllowance = dependentsCount * 30;
    const netImposable = grossPay - familyAllowance;
    
    let expectedIgr = 0;
    if (netImposable > 5000) {
      expectedIgr = Math.round((netImposable - 5000) * 0.3 * 100) / 100;
    }
    
    if (Math.abs(igr - expectedIgr) > 0.01) {
      errors.push({
        type: 'igr_calculation',
        field: 'igr_amount',
        expected: expectedIgr,
        actual: igr,
        difference: igr - expectedIgr,
        percentage: expectedIgr !== 0 ? ((igr - expectedIgr) / expectedIgr) * 100 : 0,
        severity: Math.abs(igr - expectedIgr) > 20 ? 'critical' : 'major'
      });
    }
    
    if (dependentsCount > 6) {
      warnings.push({
        type: 'igr_dependents',
        message: `Nombre élevé de personnes à charge (${dependentsCount})`,
        suggestion: 'Vérifier la documentation justificative'
      });
    }
    
    return { errors, warnings };
  }

  private validateCoherence(payrollResult: any) {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    
    // Vérifier que le net pay est cohérent
    const expectedNetPay = payrollResult.gross_pay - 
      payrollResult.cnss_employee - 
      payrollResult.amo_employee - 
      payrollResult.igr_amount;
    
    if (Math.abs(payrollResult.net_pay - expectedNetPay) > 0.01) {
      errors.push({
        type: 'coherence',
        field: 'net_pay',
        expected: expectedNetPay,
        actual: payrollResult.net_pay,
        difference: payrollResult.net_pay - expectedNetPay,
        percentage: expectedNetPay !== 0 ? ((payrollResult.net_pay - expectedNetPay) / expectedNetPay) * 100 : 0,
        severity: 'critical'
      });
    }
    
    // Vérifier les heures
    if (payrollResult.worked_hours + payrollResult.absence_hours < 1) {
      warnings.push({
        type: 'hours_coherence',
        message: 'Total des heures très faible',
        suggestion: 'Vérifier la saisie des temps'
      });
    }
    
    return { errors, warnings };
  }
}

/**
 * Système de correction automatique
 */
export class PayrollAutoCorrector {
  private logger: PayrollLogger;
  
  constructor(logger: PayrollLogger) {
    this.logger = logger;
  }

  /**
   * Propose des corrections automatiques pour un résultat de paie
   */
  async proposeCorrections(payrollResultId: string): Promise<any[]> {
    const validator = new PayrollValidator(this.logger);
    const validationResult = await validator.validatePayrollResult(payrollResultId);
    
    const corrections = [];
    
    for (const error of validationResult.errors) {
      if (error.severity === 'critical' || error.severity === 'major') {
        corrections.push({
          error_type: error.type,
          error_description: `Écart de ${error.difference.toFixed(2)} sur ${error.field}`,
          original_values: { [error.field]: error.actual },
          corrected_values: { [error.field]: error.expected },
          correction_method: 'auto',
          confidence_score: this.calculateConfidenceScore(error)
        });
      }
    }
    
    return corrections;
  }

  private calculateConfidenceScore(error: ValidationError): number {
    // Score de confiance basé sur le type d'erreur et l'ampleur
    if (error.type === 'cnss_calculation' && Math.abs(error.percentage) < 5) {
      return 0.95;
    }
    if (error.type === 'amo_calculation' && Math.abs(error.percentage) < 3) {
      return 0.9;
    }
    if (error.type === 'igr_calculation' && Math.abs(error.percentage) < 10) {
      return 0.85;
    }
    
    return 0.7; // Score par défaut
  }
}

/**
 * Moniteur de performance en temps réel
 */
export class PayrollPerformanceMonitor {
  private logger: PayrollLogger;
  private startTime: number;
  private checkpoints: Map<string, number> = new Map();
  
  constructor(logger: PayrollLogger) {
    this.logger = logger;
    this.startTime = Date.now();
  }

  checkpoint(name: string): void {
    this.checkpoints.set(name, Date.now() - this.startTime);
  }

  async finish(periodId: string | null): Promise<void> {
    const totalTime = Date.now() - this.startTime;
    
    // Enregistrer les métriques de performance
    await this.logger.logPerformanceMetric(
      periodId,
      'total_execution_time',
      totalTime,
      'ms',
      10000 // Benchmark: 10 secondes max
    );
    
    for (const [name, time] of this.checkpoints) {
      await this.logger.logPerformanceMetric(
        periodId,
        `checkpoint_${name}`,
        time,
        'ms'
      );
    }
  }
}