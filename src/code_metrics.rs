use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::control_flow::{ControlFlowAnalysis, ControlFlowGraph, InstructionType, BasicBlock};
use crate::function_analysis::SymbolTable;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CodeQualityAnalysis {
    pub function_metrics: Vec<FunctionMetrics>,
    pub overall_metrics: OverallCodeMetrics,
    pub quality_report: QualityReport,
    pub analysis_stats: QualityAnalysisStats,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FunctionMetrics {
    pub function_name: String,
    pub function_address: u64,
    pub cyclomatic_complexity: u32,
    pub cognitive_complexity: u32,
    pub nesting_depth: u32,
    pub function_length: u32,      // Number of instructions
    pub basic_block_count: u32,
    pub parameter_count: u32,       // Estimated from function signature
    pub return_paths: u32,          // Number of return statements
    pub halstead_metrics: HalsteadMetrics,
    pub maintainability_index: f64,
    pub technical_debt_minutes: u32, // Estimated time to fix issues
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HalsteadMetrics {
    pub distinct_operators: u32,     // n1
    pub distinct_operands: u32,      // n2
    pub total_operators: u32,        // N1
    pub total_operands: u32,         // N2
    pub vocabulary: u32,             // n = n1 + n2
    pub length: u32,                 // N = N1 + N2
    pub volume: f64,                 // V = N * log2(n)
    pub difficulty: f64,             // D = (n1/2) * (N2/n2)
    pub effort: f64,                 // E = D * V
    pub time_to_program: f64,        // T = E / 18 (seconds)
    pub delivered_bugs: f64,         // B = V / 3000
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OverallCodeMetrics {
    pub total_functions: usize,
    pub total_instructions: usize,
    pub average_complexity: f64,
    pub average_function_length: f64,
    pub total_code_volume: f64,
    pub total_estimated_bugs: f64,
    pub most_complex_function: Option<String>,
    pub highest_complexity: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QualityReport {
    pub overall_quality_score: f64,    // 0.0 to 100.0
    pub complexity_score: f64,         // 0.0 to 100.0
    pub maintainability_score: f64,    // 0.0 to 100.0
    pub code_health: CodeHealth,
    pub quality_issues: Vec<QualityIssue>,
    pub recommendations: Vec<String>,
    pub technical_debt_hours: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CodeHealth {
    Excellent,  // 90-100
    Good,       // 75-89
    Fair,       // 60-74
    Poor,       // 40-59
    Critical,   // 0-39
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QualityIssue {
    pub issue_type: QualityIssueType,
    pub severity: IssueSeverity,
    pub function_name: String,
    pub description: String,
    pub recommendation: String,
    pub debt_minutes: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum QualityIssueType {
    HighComplexity,
    LongFunction,
    DeepNesting,
    TooManyReturns,
    HighCoupling,
    LowCohesion,
    DuplicatedCode,
    DeadCode,
    MagicNumbers,
    GodFunction,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum IssueSeverity {
    Critical,
    Major,
    Minor,
    Info,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QualityAnalysisStats {
    pub analysis_duration_ms: u64,
    pub functions_analyzed: usize,
    pub instructions_analyzed: usize,
    pub issues_found: usize,
}

pub struct CodeQualityAnalyzer;

impl CodeQualityAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(
        &self,
        cfg_analysis: &ControlFlowAnalysis,
        _symbol_table: &SymbolTable,
    ) -> Result<CodeQualityAnalysis> {
        let start_time = std::time::Instant::now();
        let mut function_metrics = Vec::new();
        let mut total_instructions = 0;

        // Analyze each function
        for cfg in &cfg_analysis.cfgs {
            let metrics = self.analyze_function(cfg)?;
            total_instructions += metrics.function_length as usize;
            function_metrics.push(metrics);
        }

        // Calculate overall metrics
        let overall_metrics = self.calculate_overall_metrics(&function_metrics, total_instructions);
        
        // Generate quality report
        let quality_report = self.generate_quality_report(&function_metrics, &overall_metrics);

        let duration = start_time.elapsed().as_millis() as u64;
        let issues_found = quality_report.quality_issues.len();

        Ok(CodeQualityAnalysis {
            function_metrics,
            overall_metrics,
            quality_report,
            analysis_stats: QualityAnalysisStats {
                analysis_duration_ms: duration,
                functions_analyzed: cfg_analysis.cfgs.len(),
                instructions_analyzed: total_instructions,
                issues_found,
            },
        })
    }

    fn analyze_function(&self, cfg: &ControlFlowGraph) -> Result<FunctionMetrics> {
        // Get basic metrics from CFG
        let cyclomatic_complexity = cfg.complexity.cyclomatic_complexity;
        let cognitive_complexity = cfg.complexity.cognitive_complexity;
        let nesting_depth = cfg.complexity.nesting_depth;
        let basic_block_count = cfg.basic_blocks.len() as u32;
        
        // Count total instructions
        let function_length = cfg.basic_blocks.iter()
            .map(|bb| bb.instruction_count)
            .sum::<usize>() as u32;

        // Count return paths
        let return_paths = cfg.exit_blocks.len() as u32;

        // Calculate Halstead metrics
        let halstead_metrics = self.calculate_halstead_metrics(&cfg.basic_blocks)?;

        // Calculate maintainability index
        let maintainability_index = self.calculate_maintainability_index(
            &halstead_metrics,
            cyclomatic_complexity,
            function_length,
        );

        // Estimate technical debt
        let technical_debt_minutes = self.estimate_technical_debt(
            cyclomatic_complexity,
            cognitive_complexity,
            function_length,
            nesting_depth,
        );

        // Estimate parameter count (simplified - would need more analysis in practice)
        let parameter_count = self.estimate_parameter_count(&cfg.basic_blocks);

        Ok(FunctionMetrics {
            function_name: cfg.function_name.clone(),
            function_address: cfg.function_address,
            cyclomatic_complexity,
            cognitive_complexity,
            nesting_depth,
            function_length,
            basic_block_count,
            parameter_count,
            return_paths,
            halstead_metrics,
            maintainability_index,
            technical_debt_minutes,
        })
    }

    fn calculate_halstead_metrics(&self, basic_blocks: &[BasicBlock]) -> Result<HalsteadMetrics> {
        let mut operators = HashMap::new();
        let mut operands = HashMap::new();
        let mut total_operators = 0;
        let mut total_operands = 0;

        for block in basic_blocks {
            for instruction in &block.instructions {
                // Classify instruction as operator
                match &instruction.instruction_type {
                    InstructionType::Arithmetic | InstructionType::Logic | 
                    InstructionType::Control | InstructionType::Call |
                    InstructionType::Jump | InstructionType::Conditional => {
                        *operators.entry(instruction.mnemonic.clone()).or_insert(0) += 1;
                        total_operators += 1;
                    }
                    _ => {}
                }

                // Extract operands from instruction
                let operand_tokens = self.extract_operand_tokens(&instruction.operands);
                for token in operand_tokens {
                    *operands.entry(token).or_insert(0) += 1;
                    total_operands += 1;
                }
            }
        }

        let distinct_operators = operators.len() as u32;
        let distinct_operands = operands.len() as u32;
        let vocabulary = distinct_operators + distinct_operands;
        let length = total_operators + total_operands;

        let volume = if vocabulary > 0 {
            length as f64 * (vocabulary as f64).log2()
        } else {
            0.0
        };

        let difficulty = if distinct_operands > 0 && operands.values().sum::<u32>() > 0 {
            (distinct_operators as f64 / 2.0) * 
            (total_operands as f64 / distinct_operands as f64)
        } else {
            0.0
        };

        let effort = difficulty * volume;
        let time_to_program = effort / 18.0; // seconds
        let delivered_bugs = volume / 3000.0;

        Ok(HalsteadMetrics {
            distinct_operators,
            distinct_operands,
            total_operators,
            total_operands,
            vocabulary,
            length,
            volume,
            difficulty,
            effort,
            time_to_program,
            delivered_bugs,
        })
    }

    fn extract_operand_tokens(&self, operands: &str) -> Vec<String> {
        // Simple tokenization of operands
        operands.split(|c: char| c == ',' || c == ' ' || c == '[' || c == ']' || c == '+' || c == '-' || c == '*')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    fn calculate_maintainability_index(
        &self,
        halstead: &HalsteadMetrics,
        cyclomatic_complexity: u32,
        lines_of_code: u32,
    ) -> f64 {
        // Microsoft's Maintainability Index formula
        // MI = 171 - 5.2 * ln(V) - 0.23 * CC - 16.2 * ln(LOC)
        let volume = halstead.volume.max(1.0);
        let loc = lines_of_code.max(1) as f64;
        let cc = cyclomatic_complexity as f64;

        let mi = 171.0 
            - 5.2 * volume.ln()
            - 0.23 * cc
            - 16.2 * loc.ln();

        // Normalize to 0-100 scale
        ((mi * 100.0 / 171.0).max(0.0)).min(100.0)
    }

    fn estimate_technical_debt(
        &self,
        cyclomatic_complexity: u32,
        cognitive_complexity: u32,
        function_length: u32,
        nesting_depth: u32,
    ) -> u32 {
        let mut debt_minutes = 0;

        // High complexity penalty
        if cyclomatic_complexity > 10 {
            debt_minutes += (cyclomatic_complexity - 10) * 10;
        }

        // Cognitive complexity penalty
        if cognitive_complexity > 15 {
            debt_minutes += (cognitive_complexity - 15) * 8;
        }

        // Long function penalty
        if function_length > 50 {
            debt_minutes += (function_length - 50) * 2;
        }

        // Deep nesting penalty
        if nesting_depth > 4 {
            debt_minutes += (nesting_depth - 4) * 15;
        }

        debt_minutes
    }

    fn estimate_parameter_count(&self, basic_blocks: &[BasicBlock]) -> u32 {
        // Look for register usage patterns in first basic block
        // This is a simplified heuristic
        if let Some(first_block) = basic_blocks.first() {
            let param_registers = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
            let mut max_param = 0;
            
            for (i, reg) in param_registers.iter().enumerate() {
                for instruction in &first_block.instructions {
                    if instruction.operands.contains(reg) {
                        max_param = i + 1;
                    }
                }
            }
            
            max_param as u32
        } else {
            0
        }
    }

    fn calculate_overall_metrics(
        &self,
        function_metrics: &[FunctionMetrics],
        total_instructions: usize,
    ) -> OverallCodeMetrics {
        let total_functions = function_metrics.len();
        
        let average_complexity = if total_functions > 0 {
            function_metrics.iter()
                .map(|m| m.cyclomatic_complexity as f64)
                .sum::<f64>() / total_functions as f64
        } else {
            0.0
        };

        let average_function_length = if total_functions > 0 {
            function_metrics.iter()
                .map(|m| m.function_length as f64)
                .sum::<f64>() / total_functions as f64
        } else {
            0.0
        };

        let total_code_volume = function_metrics.iter()
            .map(|m| m.halstead_metrics.volume)
            .sum::<f64>();

        let total_estimated_bugs = function_metrics.iter()
            .map(|m| m.halstead_metrics.delivered_bugs)
            .sum::<f64>();

        let (most_complex_function, highest_complexity) = function_metrics.iter()
            .max_by_key(|m| m.cyclomatic_complexity)
            .map(|m| (Some(m.function_name.clone()), m.cyclomatic_complexity))
            .unwrap_or((None, 0));

        OverallCodeMetrics {
            total_functions,
            total_instructions,
            average_complexity,
            average_function_length,
            total_code_volume,
            total_estimated_bugs,
            most_complex_function,
            highest_complexity,
        }
    }

    fn generate_quality_report(
        &self,
        function_metrics: &[FunctionMetrics],
        overall_metrics: &OverallCodeMetrics,
    ) -> QualityReport {
        let mut quality_issues = Vec::new();
        let mut total_debt_minutes = 0;

        // Check each function for quality issues
        for metrics in function_metrics {
            // High complexity
            if metrics.cyclomatic_complexity > 10 {
                quality_issues.push(QualityIssue {
                    issue_type: QualityIssueType::HighComplexity,
                    severity: if metrics.cyclomatic_complexity > 20 {
                        IssueSeverity::Critical
                    } else {
                        IssueSeverity::Major
                    },
                    function_name: metrics.function_name.clone(),
                    description: format!(
                        "Function has high cyclomatic complexity ({})",
                        metrics.cyclomatic_complexity
                    ),
                    recommendation: "Consider breaking this function into smaller, more focused functions".to_string(),
                    debt_minutes: (metrics.cyclomatic_complexity - 10) * 10,
                });
            }

            // Long function
            if metrics.function_length > 50 {
                quality_issues.push(QualityIssue {
                    issue_type: QualityIssueType::LongFunction,
                    severity: if metrics.function_length > 100 {
                        IssueSeverity::Major
                    } else {
                        IssueSeverity::Minor
                    },
                    function_name: metrics.function_name.clone(),
                    description: format!(
                        "Function is too long ({} instructions)",
                        metrics.function_length
                    ),
                    recommendation: "Extract cohesive blocks into separate functions".to_string(),
                    debt_minutes: (metrics.function_length - 50) * 2,
                });
            }

            // Deep nesting
            if metrics.nesting_depth > 4 {
                quality_issues.push(QualityIssue {
                    issue_type: QualityIssueType::DeepNesting,
                    severity: IssueSeverity::Major,
                    function_name: metrics.function_name.clone(),
                    description: format!(
                        "Function has deep nesting (depth: {})",
                        metrics.nesting_depth
                    ),
                    recommendation: "Use early returns or extract nested logic".to_string(),
                    debt_minutes: (metrics.nesting_depth - 4) * 15,
                });
            }

            // Too many returns
            if metrics.return_paths > 5 {
                quality_issues.push(QualityIssue {
                    issue_type: QualityIssueType::TooManyReturns,
                    severity: IssueSeverity::Minor,
                    function_name: metrics.function_name.clone(),
                    description: format!(
                        "Function has too many return paths ({})",
                        metrics.return_paths
                    ),
                    recommendation: "Consolidate return paths for better maintainability".to_string(),
                    debt_minutes: (metrics.return_paths - 5) * 5,
                });
            }

            // God function (doing too much)
            if metrics.cyclomatic_complexity > 20 && metrics.function_length > 100 {
                quality_issues.push(QualityIssue {
                    issue_type: QualityIssueType::GodFunction,
                    severity: IssueSeverity::Critical,
                    function_name: metrics.function_name.clone(),
                    description: "Function is doing too much (high complexity and length)".to_string(),
                    recommendation: "Refactor into multiple smaller functions with single responsibilities".to_string(),
                    debt_minutes: 120,
                });
            }

            total_debt_minutes += metrics.technical_debt_minutes;
        }

        // Calculate quality scores
        let complexity_score = self.calculate_complexity_score(overall_metrics.average_complexity);
        let maintainability_score = if function_metrics.is_empty() {
            100.0
        } else {
            function_metrics.iter()
                .map(|m| m.maintainability_index)
                .sum::<f64>() / function_metrics.len() as f64
        };

        let overall_quality_score = (complexity_score + maintainability_score) / 2.0;

        let code_health = match overall_quality_score {
            score if score >= 90.0 => CodeHealth::Excellent,
            score if score >= 75.0 => CodeHealth::Good,
            score if score >= 60.0 => CodeHealth::Fair,
            score if score >= 40.0 => CodeHealth::Poor,
            _ => CodeHealth::Critical,
        };

        let mut recommendations = Vec::new();
        if overall_metrics.average_complexity > 10.0 {
            recommendations.push("Consider refactoring complex functions to reduce average complexity".to_string());
        }
        if overall_metrics.average_function_length > 50.0 {
            recommendations.push("Functions are generally too long - aim for 20-50 instructions per function".to_string());
        }
        if overall_metrics.total_estimated_bugs > 1.0 {
            recommendations.push(format!(
                "Code volume suggests approximately {:.1} potential bugs - increase testing coverage",
                overall_metrics.total_estimated_bugs
            ));
        }
        if quality_issues.is_empty() {
            recommendations.push("Code quality is good - maintain current standards".to_string());
        }

        let technical_debt_hours = total_debt_minutes as f64 / 60.0;

        QualityReport {
            overall_quality_score,
            complexity_score,
            maintainability_score,
            code_health,
            quality_issues,
            recommendations,
            technical_debt_hours,
        }
    }

    fn calculate_complexity_score(&self, average_complexity: f64) -> f64 {
        // Convert complexity to a 0-100 score (lower complexity = higher score)
        if average_complexity <= 5.0 {
            100.0
        } else if average_complexity <= 10.0 {
            90.0 - (average_complexity - 5.0) * 4.0
        } else if average_complexity <= 20.0 {
            70.0 - (average_complexity - 10.0) * 3.0
        } else if average_complexity <= 30.0 {
            40.0 - (average_complexity - 20.0) * 2.0
        } else {
            20.0_f64.max(20.0 - (average_complexity - 30.0))
        }
    }
}

pub fn analyze_code_quality(
    _path: &Path,
    symbol_table: &SymbolTable,
    cfg_analysis: &ControlFlowAnalysis,
) -> Result<CodeQualityAnalysis> {
    let analyzer = CodeQualityAnalyzer::new();
    analyzer.analyze(cfg_analysis, symbol_table)
}