import type { SecurityFinding, StaticAnalysisResult } from './static-analyzer.js';

export type ReportFormat = 'json' | 'md' | 'sarif';

export interface UnifiedFindingEvidence {
  file: string;
  line?: number;
  code?: string;
  detail: string;
}

export interface UnifiedReportFinding {
  id: string;
  ruleId: string;
  category: SecurityFinding['type'];
  severity: SecurityFinding['severity'];
  cwe: string;
  masvs: string[];
  title: string;
  description: string;
  evidence: UnifiedFindingEvidence;
  repro: string[];
  impact: string;
  fix: string;
}

export interface UnifiedSecurityReport {
  schemaVersion: '1.0.0';
  generatedAt: string;
  targetPath: string;
  summary: StaticAnalysisResult['summary'] & {
    scannedFiles: number;
    scanTimeMs: number;
  };
  findings: UnifiedReportFinding[];
}

function mapCategoryName(type: SecurityFinding['type']): string {
  switch (type) {
    case 'hardcoded_secret':
      return '硬编码敏感信息';
    case 'debug_leak':
      return '调试信息泄露';
    case 'weak_crypto':
      return '弱加密实现';
    case 'permission_issue':
      return '权限风险';
    case 'sensitive_data':
      return '敏感数据恢复链路';
    default:
      return type;
  }
}

function buildRuleId(finding: SecurityFinding): string {
  const base: Record<SecurityFinding['type'], string> = {
    hardcoded_secret: 'MATM.HARDCODED_SECRET',
    debug_leak: 'MATM.DEBUG_LEAK',
    weak_crypto: 'MATM.WEAK_CRYPTO',
    permission_issue: 'MATM.PERMISSION_ISSUE',
    sensitive_data: 'MATM.OFFLINE_SECRET_RECOVERY'
  };
  return base[finding.type];
}

function mapStandards(finding: SecurityFinding): { cwe: string; masvs: string[]; impact: string } {
  switch (finding.type) {
    case 'hardcoded_secret':
      return {
        cwe: 'CWE-798',
        masvs: ['MASVS-CRYPTO-1', 'MASVS-STORAGE-1'],
        impact: '攻击者可直接提取凭据，伪造请求或访问受保护资源。'
      };
    case 'debug_leak':
      return {
        cwe: 'CWE-532',
        masvs: ['MASVS-CODE-2'],
        impact: '日志与调试信息可泄露运行时状态、账号标识或密钥线索。'
      };
    case 'weak_crypto':
      return {
        cwe: 'CWE-327',
        masvs: ['MASVS-CRYPTO-1'],
        impact: '弱算法或不安全模式可被利用，导致数据机密性或完整性受损。'
      };
    case 'sensitive_data':
      return {
        cwe: 'CWE-312',
        masvs: ['MASVS-CRYPTO-1', 'MASVS-RESILIENCE-1'],
        impact: '攻击者可能在离线环境恢复secret并绕过客户端校验。'
      };
    case 'permission_issue':
    default:
      return {
        cwe: 'CWE-250',
        masvs: ['MASVS-PLATFORM-1'],
        impact: '权限控制不足可能扩大攻击面并增加敏感能力暴露风险。'
      };
  }
}

function buildReproSteps(finding: SecurityFinding): string[] {
  const location = `${finding.file}${finding.line ? `:${finding.line}` : ''}`;
  return [
    `定位代码位置: ${location}`,
    `检查证据代码并确认触发模式: ${finding.title}`,
    '在测试构建中复现对应路径并验证可利用性'
  ];
}

export function buildUnifiedSecurityReport(
  targetPath: string,
  analysis: StaticAnalysisResult
): UnifiedSecurityReport {
  const findings: UnifiedReportFinding[] = analysis.findings.map((finding, index) => {
    const standards = mapStandards(finding);
    const location = `${finding.file}${finding.line ? `:${finding.line}` : ''}`;
    return {
      id: `F-${String(index + 1).padStart(4, '0')}`,
      ruleId: buildRuleId(finding),
      category: finding.type,
      severity: finding.severity,
      cwe: standards.cwe,
      masvs: standards.masvs,
      title: finding.title,
      description: finding.description,
      evidence: {
        file: finding.file,
        line: finding.line,
        code: finding.code,
        detail: `${mapCategoryName(finding.type)} @ ${location}`
      },
      repro: buildReproSteps(finding),
      impact: standards.impact,
      fix: finding.recommendation
    };
  });

  return {
    schemaVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    targetPath,
    summary: {
      ...analysis.summary,
      scannedFiles: analysis.scannedFiles,
      scanTimeMs: analysis.scanTime
    },
    findings
  };
}

export function buildMarkdownReport(report: UnifiedSecurityReport): string {
  const lines: string[] = [];
  lines.push('# Mobile App Security Report');
  lines.push('');
  lines.push(`- GeneratedAt: ${report.generatedAt}`);
  lines.push(`- TargetPath: ${report.targetPath}`);
  lines.push(`- Findings: ${report.summary.totalFindings}`);
  lines.push(
    `- Severity: critical=${report.summary.critical}, high=${report.summary.high}, medium=${report.summary.medium}, low=${report.summary.low}, info=${report.summary.info}`
  );
  lines.push('');

  if (report.findings.length === 0) {
    lines.push('## Findings');
    lines.push('');
    lines.push('No security finding.');
    return lines.join('\n');
  }

  lines.push('## Findings');
  lines.push('');
  lines.push('| ID | Severity | CWE | MASVS | Title | Evidence |');
  lines.push('| --- | --- | --- | --- | --- | --- |');
  for (const finding of report.findings) {
    const evidenceLocation = `${finding.evidence.file}${finding.evidence.line ? `:${finding.evidence.line}` : ''}`;
    lines.push(
      `| ${finding.id} | ${finding.severity} | ${finding.cwe} | ${finding.masvs.join(', ')} | ${finding.title} | ${evidenceLocation} |`
    );
  }
  lines.push('');

  for (const finding of report.findings) {
    const evidenceLocation = `${finding.evidence.file}${finding.evidence.line ? `:${finding.evidence.line}` : ''}`;
    lines.push(`### ${finding.id} ${finding.title}`);
    lines.push('');
    lines.push(`- Severity: ${finding.severity}`);
    lines.push(`- Category: ${finding.category}`);
    lines.push(`- CWE: ${finding.cwe}`);
    lines.push(`- MASVS: ${finding.masvs.join(', ')}`);
    lines.push(`- Evidence: ${evidenceLocation}`);
    if (finding.evidence.code) {
      lines.push(`- Code: \`${finding.evidence.code}\``);
    }
    lines.push(`- Description: ${finding.description}`);
    lines.push(`- Repro: ${finding.repro.join(' ; ')}`);
    lines.push(`- Impact: ${finding.impact}`);
    lines.push(`- Fix: ${finding.fix}`);
    lines.push('');
  }

  return lines.join('\n');
}

function mapSeverityToSarifLevel(severity: SecurityFinding['severity']): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') {
    return 'error';
  }
  if (severity === 'medium' || severity === 'low') {
    return 'warning';
  }
  return 'note';
}

export function buildSarifReport(report: UnifiedSecurityReport): Record<string, unknown> {
  const rules = new Map<string, UnifiedReportFinding>();
  for (const finding of report.findings) {
    if (!rules.has(finding.ruleId)) {
      rules.set(finding.ruleId, finding);
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mobile-app-testing-mcp',
            rules: Array.from(rules.values()).map(rule => ({
              id: rule.ruleId,
              name: rule.title,
              shortDescription: { text: rule.title },
              fullDescription: { text: rule.description },
              help: { text: rule.fix },
              properties: {
                cwe: rule.cwe,
                masvs: rule.masvs
              }
            }))
          }
        },
        results: report.findings.map(finding => ({
          ruleId: finding.ruleId,
          level: mapSeverityToSarifLevel(finding.severity),
          message: {
            text: `${finding.title} - ${finding.description}`
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.evidence.file
                },
                region: {
                  startLine: finding.evidence.line || 1
                }
              }
            }
          ],
          properties: {
            id: finding.id,
            severity: finding.severity,
            cwe: finding.cwe,
            masvs: finding.masvs,
            repro: finding.repro,
            impact: finding.impact,
            fix: finding.fix,
            evidence: finding.evidence.detail
          }
        }))
      }
    ]
  };
}
