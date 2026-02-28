// 标准移动安全测试工作流定义
// 聚焦 ADB 自动化、AAPT 分析、JADX 反编译与静态扫描

export interface WorkflowPhase {
  id: string;
  name: string;
  description: string;
  tools: string[];
  dependencies?: string[];
  criticalPath: boolean;
}

export interface ToolExecutionRule {
  toolName: string;
  phase: string;
  order: number;
  dependencies: string[];
  nextSuggestions: string[];
  criticalNotes?: string[];
  errorRecovery?: string[];
}

export class StandardWorkflowEngine {
  private phases: Map<string, WorkflowPhase> = new Map([
    ['phase1_preparation', {
      id: 'phase1_preparation',
      name: '阶段一：设备与目标确认',
      description: '确认设备连接、应用存在与基础运行状态',
      tools: ['adb_list_devices', 'adb_set_device', 'adb_list_packages', 'adb_start_app', 'adb_screenshot'],
      criticalPath: true
    }],

    ['phase2_static_apk', {
      id: 'phase2_static_apk',
      name: '阶段二：APK静态信息分析',
      description: '基于 AAPT 提取包信息、权限与清单结构',
      tools: ['aapt_dump_badging', 'aapt_dump_permissions', 'aapt_dump_xmltree', 'aapt_analyze_apk'],
      dependencies: ['phase1_preparation'],
      criticalPath: true
    }],

    ['phase3_reverse_engineering', {
      id: 'phase3_reverse_engineering',
      name: '阶段三：反编译与源码结构分析',
      description: '使用 JADX 验证、反编译并统计项目结构',
      tools: ['jadx_validate_apk', 'jadx_decompile_apk', 'jadx_get_info'],
      dependencies: ['phase2_static_apk'],
      criticalPath: true
    }],

    ['phase4_security_review', {
      id: 'phase4_security_review',
      name: '阶段四：静态安全审查',
      description: '执行敏感信息、调试泄露、弱加密与综合扫描',
      tools: ['static_scan_secrets', 'static_scan_debug_leaks', 'static_scan_weak_crypto', 'static_comprehensive_analysis'],
      dependencies: ['phase3_reverse_engineering'],
      criticalPath: true
    }],

    ['phase5_evidence', {
      id: 'phase5_evidence',
      name: '阶段五：证据留存与补充取证',
      description: '哈希固化、截图与必要文件拉取',
      tools: ['file_sha256', 'adb_pull_file_advanced', 'adb_screenshot'],
      dependencies: ['phase4_security_review'],
      criticalPath: false
    }]
  ]);

  private executionRules: Map<string, ToolExecutionRule> = new Map([
    ['adb_list_devices', {
      toolName: 'adb_list_devices',
      phase: 'phase1_preparation',
      order: 1,
      dependencies: [],
      nextSuggestions: ['adb_set_device', 'adb_list_packages'],
      criticalNotes: ['确认设备状态为 device', '若无设备，先排查 USB 调试与驱动']
    }],

    ['adb_set_device', {
      toolName: 'adb_set_device',
      phase: 'phase1_preparation',
      order: 2,
      dependencies: ['adb_list_devices'],
      nextSuggestions: ['adb_list_packages'],
      criticalNotes: ['多设备场景必须先指定当前设备']
    }],

    ['adb_list_packages', {
      toolName: 'adb_list_packages',
      phase: 'phase1_preparation',
      order: 3,
      dependencies: ['adb_list_devices'],
      nextSuggestions: ['adb_start_app', 'aapt_dump_badging'],
      criticalNotes: ['确认目标包名，避免后续分析对象错误']
    }],

    ['adb_start_app', {
      toolName: 'adb_start_app',
      phase: 'phase1_preparation',
      order: 4,
      dependencies: ['adb_list_packages'],
      nextSuggestions: ['adb_screenshot', 'adb_shell_command'],
      criticalNotes: ['启动后建议立即截图记录基线界面']
    }],

    ['adb_screenshot', {
      toolName: 'adb_screenshot',
      phase: 'phase1_preparation',
      order: 5,
      dependencies: ['adb_start_app'],
      nextSuggestions: ['aapt_dump_badging', 'adb_shell_command'],
      criticalNotes: ['关键操作前后均建议截图留证']
    }],

    ['aapt_dump_badging', {
      toolName: 'aapt_dump_badging',
      phase: 'phase2_static_apk',
      order: 6,
      dependencies: [],
      nextSuggestions: ['aapt_dump_permissions', 'aapt_dump_xmltree'],
      criticalNotes: ['优先确认包名、版本、SDK 与可调试状态']
    }],

    ['aapt_dump_permissions', {
      toolName: 'aapt_dump_permissions',
      phase: 'phase2_static_apk',
      order: 7,
      dependencies: ['aapt_dump_badging'],
      nextSuggestions: ['aapt_analyze_apk', 'jadx_validate_apk'],
      criticalNotes: ['优先关注高风险权限与权限组合']
    }],

    ['aapt_dump_xmltree', {
      toolName: 'aapt_dump_xmltree',
      phase: 'phase2_static_apk',
      order: 8,
      dependencies: ['aapt_dump_badging'],
      nextSuggestions: ['aapt_analyze_apk'],
      criticalNotes: ['重点检查 exported 组件和 intent-filter']
    }],

    ['aapt_analyze_apk', {
      toolName: 'aapt_analyze_apk',
      phase: 'phase2_static_apk',
      order: 9,
      dependencies: ['aapt_dump_permissions'],
      nextSuggestions: ['jadx_validate_apk', 'jadx_decompile_apk'],
      criticalNotes: ['用于快速形成静态风险初判']
    }],

    ['jadx_validate_apk', {
      toolName: 'jadx_validate_apk',
      phase: 'phase3_reverse_engineering',
      order: 10,
      dependencies: [],
      nextSuggestions: ['jadx_decompile_apk'],
      criticalNotes: ['反编译前建议先验证 APK 有效性']
    }],

    ['jadx_decompile_apk', {
      toolName: 'jadx_decompile_apk',
      phase: 'phase3_reverse_engineering',
      order: 11,
      dependencies: ['jadx_validate_apk'],
      nextSuggestions: ['jadx_get_info', 'static_comprehensive_analysis'],
      criticalNotes: ['反编译输出目录应固定，便于复现与对比'],
      errorRecovery: ['检查 APK 完整性', '调整 threads_count', '确认 JADX 可执行路径']
    }],

    ['jadx_get_info', {
      toolName: 'jadx_get_info',
      phase: 'phase3_reverse_engineering',
      order: 12,
      dependencies: ['jadx_decompile_apk'],
      nextSuggestions: ['static_scan_secrets', 'static_scan_weak_crypto'],
      criticalNotes: ['先看目录结构，再做有目标的静态扫描']
    }],

    ['static_scan_secrets', {
      toolName: 'static_scan_secrets',
      phase: 'phase4_security_review',
      order: 13,
      dependencies: ['jadx_decompile_apk'],
      nextSuggestions: ['static_scan_debug_leaks', 'static_scan_weak_crypto'],
      criticalNotes: ['优先检查 token/key/credential 类命中']
    }],

    ['static_scan_debug_leaks', {
      toolName: 'static_scan_debug_leaks',
      phase: 'phase4_security_review',
      order: 14,
      dependencies: ['jadx_decompile_apk'],
      nextSuggestions: ['static_scan_weak_crypto', 'static_comprehensive_analysis'],
      criticalNotes: ['重点关注日志输出中的敏感字段']
    }],

    ['static_scan_weak_crypto', {
      toolName: 'static_scan_weak_crypto',
      phase: 'phase4_security_review',
      order: 15,
      dependencies: ['jadx_decompile_apk'],
      nextSuggestions: ['static_comprehensive_analysis'],
      criticalNotes: ['重点关注 MD5/DES/ECB/固定 IV 等模式']
    }],

    ['static_comprehensive_analysis', {
      toolName: 'static_comprehensive_analysis',
      phase: 'phase4_security_review',
      order: 16,
      dependencies: ['jadx_decompile_apk'],
      nextSuggestions: ['file_sha256', 'adb_pull_file_advanced'],
      criticalNotes: ['用于输出整体风险视角，建议作为收尾步骤']
    }],

    ['file_sha256', {
      toolName: 'file_sha256',
      phase: 'phase5_evidence',
      order: 17,
      dependencies: [],
      nextSuggestions: ['adb_pull_file_advanced', 'adb_screenshot'],
      criticalNotes: ['对关键样本与输出文件做哈希固化']
    }],

    ['adb_pull_file_advanced', {
      toolName: 'adb_pull_file_advanced',
      phase: 'phase5_evidence',
      order: 18,
      dependencies: ['adb_list_devices'],
      nextSuggestions: ['file_sha256'],
      criticalNotes: ['拉取后建议立即计算 SHA256 记录证据链']
    }]
  ]);

  getCurrentPhase(executedTools: string[]): string {
    if (executedTools.includes('static_comprehensive_analysis') ||
        executedTools.includes('static_scan_weak_crypto') ||
        executedTools.includes('static_scan_secrets')) {
      return 'phase4_security_review';
    }

    if (executedTools.includes('jadx_decompile_apk') || executedTools.includes('jadx_get_info')) {
      return 'phase3_reverse_engineering';
    }

    if (executedTools.includes('aapt_dump_badging') || executedTools.includes('aapt_analyze_apk')) {
      return 'phase2_static_apk';
    }

    return 'phase1_preparation';
  }

  getNextToolSuggestions(executedTools: string[], lastTool?: string): {
    tool: string;
    reason: string;
    phase: string;
    order: number;
    criticalNotes: string[];
  }[] {
    const currentPhase = this.getCurrentPhase(executedTools);
    const suggestions: Array<{ tool: string; reason: string; phase: string; order: number; criticalNotes: string[] }> = [];

    if (lastTool && this.executionRules.has(lastTool)) {
      const rule = this.executionRules.get(lastTool)!;
      for (const nextTool of rule.nextSuggestions) {
        if (executedTools.includes(nextTool)) {
          continue;
        }
        const nextRule = this.executionRules.get(nextTool);
        if (!nextRule) {
          continue;
        }

        const dependenciesMet = nextRule.dependencies.every(dep => executedTools.includes(dep));
        if (!dependenciesMet) {
          continue;
        }

        suggestions.push({
          tool: nextTool,
          reason: `根据标准流程，${lastTool}后建议执行该工具`,
          phase: nextRule.phase,
          order: nextRule.order,
          criticalNotes: nextRule.criticalNotes || []
        });
      }
    }

    if (suggestions.length === 0) {
      const phaseTools = Array.from(this.executionRules.values())
        .filter(rule => rule.phase === currentPhase)
        .filter(rule => !executedTools.includes(rule.toolName))
        .sort((a, b) => a.order - b.order);

      for (const rule of phaseTools) {
        const dependenciesMet = rule.dependencies.every(dep => executedTools.includes(dep));
        if (!dependenciesMet) {
          continue;
        }

        suggestions.push({
          tool: rule.toolName,
          reason: `${this.phases.get(currentPhase)?.name}的下一步标准操作`,
          phase: rule.phase,
          order: rule.order,
          criticalNotes: rule.criticalNotes || []
        });

        if (suggestions.length >= 3) {
          break;
        }
      }
    }

    return suggestions.slice(0, 3);
  }

  getToolExecutionAdvice(toolName: string): {
    phase: string;
    dependencies: string[];
    criticalNotes: string[];
    errorRecovery: string[];
  } | null {
    const rule = this.executionRules.get(toolName);
    if (!rule) {
      return null;
    }

    return {
      phase: this.phases.get(rule.phase)?.name || rule.phase,
      dependencies: rule.dependencies,
      criticalNotes: rule.criticalNotes || [],
      errorRecovery: rule.errorRecovery || []
    };
  }

  validateToolOrder(toolName: string, executedTools: string[]): {
    valid: boolean;
    missingDependencies: string[];
    warnings: string[];
  } {
    const rule = this.executionRules.get(toolName);
    if (!rule) {
      return { valid: true, missingDependencies: [], warnings: [] };
    }

    const missingDependencies = rule.dependencies.filter(dep => !executedTools.includes(dep));
    const warnings: string[] = [];

    if (missingDependencies.length > 0) {
      warnings.push(`缺少前置工具: ${missingDependencies.join(', ')}`);
      warnings.push(`建议先执行: ${missingDependencies[0]}`);
    }

    if (toolName === 'adb_tap' && !executedTools.includes('adb_screenshot')) {
      warnings.push('⚠️ 建议点击前先截屏记录界面状态');
    }

    if (toolName === 'jadx_decompile_apk' && !executedTools.includes('jadx_validate_apk')) {
      warnings.push('⚠️ 建议反编译前先执行 jadx_validate_apk');
    }

    return {
      valid: missingDependencies.length === 0,
      missingDependencies,
      warnings
    };
  }

  getPhaseInfo(phaseId: string): WorkflowPhase | null {
    return this.phases.get(phaseId) || null;
  }

  getAllPhases(): WorkflowPhase[] {
    return Array.from(this.phases.values());
  }
}

export const standardWorkflowEngine = new StandardWorkflowEngine();
