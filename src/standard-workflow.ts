// 标准移动安全测试工作流定义
// 基于用户提供的专业测试流程

export interface WorkflowPhase {
  id: string;
  name: string;
  description: string;
  tools: string[];
  dependencies?: string[];
  criticalPath: boolean; // 是否为关键路径
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
  // 标准测试阶段定义
  private phases: Map<string, WorkflowPhase> = new Map([
    ['phase1_preparation', {
      id: 'phase1_preparation',
      name: '阶段一：环境准备与状态确认',
      description: '建立基础连接，确认测试目标和环境状态',
      tools: ['frida_list_devices', 'adb_screenshot', 'adb_list_packages', 'adb_start_app'],
      criticalPath: true
    }],
    
    ['phase2_connection', {
      id: 'phase2_connection', 
      name: '阶段二：调试连接建立',
      description: '附加到目标进程，建立Frida调试会话',
      tools: ['frida_attach', 'frida_connection_status', 'frida_inject_script', 'frida_realtime_logs'],
      dependencies: ['phase1_preparation'],
      criticalPath: true
    }],
    
    ['phase3_automation_loop', {
      id: 'phase3_automation_loop',
      name: '阶段三：界面分析与自动化操作',
      description: '循环执行：截屏→UI分析→操作→验证',
      tools: ['adb_screenshot', 'adb_shell_command', 'adb_pull_file', 'adb_tap', 'adb_input_text'],
      dependencies: ['phase2_connection'],
      criticalPath: true
    }],
    
    ['phase4_monitoring', {
      id: 'phase4_monitoring',
      name: '阶段四：监控与数据收集',
      description: '收集Hook数据，提取敏感信息',
      tools: ['frida_realtime_logs', 'frida_memory_search', 'adb_pull_file', 'frida_save_logs'],
      dependencies: ['phase3_automation_loop'],
      criticalPath: false
    }],
    
    ['phase5_recovery', {
      id: 'phase5_recovery',
      name: '阶段五：错误恢复与重连',
      description: '处理连接断开和错误恢复',
      tools: ['frida_force_reconnect', 'frida_inject_script', 'adb_screenshot'],
      dependencies: [],
      criticalPath: true
    }]
  ]);

  // 工具执行规则 - 基于标准流程
  private executionRules: Map<string, ToolExecutionRule> = new Map([
    // ===== 阶段一：环境准备 =====
    ['frida_list_devices', {
      toolName: 'frida_list_devices',
      phase: 'phase1_preparation',
      order: 1,
      dependencies: [],
      nextSuggestions: ['adb_screenshot', 'adb_list_devices'],
      criticalNotes: ['确保设备连接正常', '如果没有USB设备，检查ADB连接']
    }],
    
    ['adb_screenshot', {
      toolName: 'adb_screenshot', 
      phase: 'phase1_preparation',
      order: 2,
      dependencies: ['frida_list_devices'],
      nextSuggestions: ['adb_list_packages', 'adb_list_devices'],
      criticalNotes: ['记录当前界面状态', '每次关键操作前后都应截屏']
    }],
    
    ['adb_list_packages', {
      toolName: 'adb_list_packages',
      phase: 'phase1_preparation', 
      order: 3,
      dependencies: ['adb_screenshot'],
      nextSuggestions: ['adb_start_app', 'frida_list_processes'],
      criticalNotes: ['确认目标应用已安装', '记下完整的包名']
    }],
    
    ['adb_start_app', {
      toolName: 'adb_start_app',
      phase: 'phase1_preparation',
      order: 4,
      dependencies: ['adb_list_packages'],
      nextSuggestions: ['frida_list_processes', 'frida_attach'],
      criticalNotes: ['启动目标应用', '等待应用完全加载后再进行下一步']
    }],

    // ===== 阶段二：调试连接 =====
    ['frida_attach', {
      toolName: 'frida_attach',
      phase: 'phase2_connection',
      order: 5,
      dependencies: ['adb_start_app'],
      nextSuggestions: ['frida_connection_status', 'frida_inject_script'],
      criticalNotes: ['必须在脚本注入前执行', '确保目标应用正在运行'],
      errorRecovery: ['检查frida-server是否运行', '确认应用进程存在', '尝试重新启动应用']
    }],
    
    ['frida_connection_status', {
      toolName: 'frida_connection_status',
      phase: 'phase2_connection', 
      order: 6,
      dependencies: ['frida_attach'],
      nextSuggestions: ['frida_inject_script', 'frida_enumerate_classes'],
      criticalNotes: ['验证Frida连接状态', '确认会话稳定']
    }],
    
    ['frida_inject_script', {
      toolName: 'frida_inject_script',
      phase: 'phase2_connection',
      order: 7, 
      dependencies: ['frida_attach', 'frida_connection_status'],
      nextSuggestions: ['frida_realtime_logs', 'adb_screenshot'],
      criticalNotes: ['必须在进程附加后执行', '脚本注入是监控的基础'],
      errorRecovery: ['检查脚本语法', '确认Frida会话有效', '重新附加进程']
    }],
    
    ['frida_realtime_logs', {
      toolName: 'frida_realtime_logs',
      phase: 'phase2_connection',
      order: 8,
      dependencies: ['frida_inject_script'],
      nextSuggestions: ['adb_screenshot', 'adb_shell_command'],
      criticalNotes: ['启动实时日志监听', '为后续操作监控做准备']
    }],

    // ===== 阶段三：自动化操作循环 =====
    // 注意：这个阶段是循环执行的
    ['adb_shell_command', {
      toolName: 'adb_shell_command',
      phase: 'phase3_automation_loop',
      order: 10,
      dependencies: ['adb_screenshot'],
      nextSuggestions: ['adb_pull_file'],
      criticalNotes: ['执行uiautomator dump获取UI布局', '必须在UI操作分析前执行']
    }],
    
    ['adb_pull_file', {
      toolName: 'adb_pull_file', 
      phase: 'phase3_automation_loop',
      order: 11,
      dependencies: ['adb_shell_command'],
      nextSuggestions: ['adb_tap', 'adb_input_text'],
      criticalNotes: ['拉取UI布局文件到本地分析', '为确定操作坐标做准备']
    }],
    
    ['adb_tap', {
      toolName: 'adb_tap',
      phase: 'phase3_automation_loop', 
      order: 13,
      dependencies: ['adb_pull_file'],
      nextSuggestions: ['adb_screenshot'],
      criticalNotes: ['执行点击操作', '操作后必须立即截屏验证结果'],
      errorRecovery: ['重新截屏确认界面状态', '重新获取UI布局', '调整点击坐标']
    }],
    
    ['adb_input_text', {
      toolName: 'adb_input_text',
      phase: 'phase3_automation_loop',
      order: 13,
      dependencies: ['adb_pull_file'], 
      nextSuggestions: ['adb_screenshot'],
      criticalNotes: ['输入文本内容', '输入后必须立即截屏验证'],
      errorRecovery: ['确认输入框已选中', '检查输入法状态', '重新截屏验证']
    }],

    // ===== 阶段四：监控数据收集 =====
    ['frida_realtime_logs', {
      toolName: 'frida_realtime_logs',
      phase: 'phase4_monitoring',
      order: 16,
      dependencies: ['frida_realtime_logs'],
      nextSuggestions: ['frida_memory_search', 'frida_save_logs'],
      criticalNotes: ['检查Hook捕获的数据', '分析敏感信息泄露']
    }],
    
    ['frida_memory_search', {
      toolName: 'frida_memory_search',
      phase: 'phase4_monitoring',
      order: 17, 
      dependencies: ['frida_inject_script'],
      nextSuggestions: ['adb_pull_file', 'frida_save_logs'],
      criticalNotes: ['搜索内存中的敏感数据', '查找密钥、密码等信息']
    }],
    
    ['frida_save_logs', {
      toolName: 'frida_save_logs',
      phase: 'phase4_monitoring',
      order: 19,
      dependencies: ['frida_realtime_logs'],
      nextSuggestions: [],
      criticalNotes: ['保存监控日志到文件', '为后续分析保留证据']
    }],

    // ===== 阶段五：错误恢复 =====  
    ['frida_force_reconnect', {
      toolName: 'frida_force_reconnect',
      phase: 'phase5_recovery',
      order: 20,
      dependencies: [],
      nextSuggestions: ['frida_inject_script', 'adb_screenshot'],
      criticalNotes: ['连接断开时强制重连', '必须重新注入脚本'],
      errorRecovery: ['检查frida-server状态', '重新启动应用', '重新附加进程']
    }]
  ]);

  // 获取当前阶段
  getCurrentPhase(executedTools: string[]): string {
    // 根据已执行的工具判断当前阶段
    if (executedTools.includes('frida_save_logs') || executedTools.includes('frida_memory_search')) {
      return 'phase4_monitoring';
    }
    if (executedTools.includes('adb_tap') || executedTools.includes('adb_input_text')) {
      return 'phase3_automation_loop';  
    }
    if (executedTools.includes('frida_inject_script') || executedTools.includes('frida_realtime_logs')) {
      return 'phase2_connection';
    }
    if (executedTools.includes('adb_screenshot') || executedTools.includes('adb_list_packages')) {
      return 'phase1_preparation';
    }
    
    return 'phase1_preparation'; // 默认从第一阶段开始
  }

  // 获取下一个建议工具（基于标准流程）
  getNextToolSuggestions(executedTools: string[], lastTool?: string): {
    tool: string;
    reason: string;
    phase: string;
    order: number;
    criticalNotes: string[];
  }[] {
    const currentPhase = this.getCurrentPhase(executedTools);
    const suggestions: any[] = [];

    // 特殊处理：如果最后一个工具有特定的下一步建议
    if (lastTool && this.executionRules.has(lastTool)) {
      const rule = this.executionRules.get(lastTool)!;
      for (const nextTool of rule.nextSuggestions) {
        if (!executedTools.includes(nextTool)) {
          const nextRule = this.executionRules.get(nextTool);
          if (nextRule) {
            suggestions.push({
              tool: nextTool,
              reason: `根据标准流程，${lastTool}后应执行此工具`,
              phase: nextRule.phase,
              order: nextRule.order,
              criticalNotes: nextRule.criticalNotes || []
            });
          }
        }
      }
    }

    // 如果没有特定建议，按阶段推荐
    if (suggestions.length === 0) {
      const phaseTools = Array.from(this.executionRules.values())
        .filter(rule => rule.phase === currentPhase)
        .filter(rule => !executedTools.includes(rule.toolName))
        .sort((a, b) => a.order - b.order);

      for (const rule of phaseTools.slice(0, 3)) {
        // 检查依赖是否满足
        const dependenciesMet = rule.dependencies.every(dep => executedTools.includes(dep));
        if (dependenciesMet) {
          suggestions.push({
            tool: rule.toolName,
            reason: `${this.phases.get(currentPhase)?.name}的下一步标准操作`,
            phase: rule.phase,
            order: rule.order,
            criticalNotes: rule.criticalNotes || []
          });
        }
      }
    }

    return suggestions.slice(0, 3); // 最多返回3个建议
  }

  // 获取工具的执行建议
  getToolExecutionAdvice(toolName: string): {
    phase: string;
    dependencies: string[];
    criticalNotes: string[];
    errorRecovery: string[];
  } | null {
    const rule = this.executionRules.get(toolName);
    if (!rule) return null;

    return {
      phase: this.phases.get(rule.phase)?.name || rule.phase,
      dependencies: rule.dependencies,
      criticalNotes: rule.criticalNotes || [],
      errorRecovery: rule.errorRecovery || []
    };
  }

  // 验证工具执行顺序
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

    // 检查关键路径违规
    if (missingDependencies.length > 0) {
      warnings.push(`缺少前置工具: ${missingDependencies.join(', ')}`);
      warnings.push(`建议先执行: ${missingDependencies[0]}`);
    }

    // 特殊规则检查
    if (toolName === 'frida_inject_script' && !executedTools.includes('frida_attach')) {
      warnings.push('⚠️ 必须先附加进程再注入脚本');
    }
    
    if (toolName === 'adb_tap' && !executedTools.includes('adb_screenshot')) {
      warnings.push('⚠️ 建议操作前先截屏记录界面状态');
    }

    return {
      valid: missingDependencies.length === 0,
      missingDependencies,
      warnings
    };
  }

  // 获取阶段信息
  getPhaseInfo(phaseId: string): WorkflowPhase | null {
    return this.phases.get(phaseId) || null;
  }

  // 获取所有阶段
  getAllPhases(): WorkflowPhase[] {
    return Array.from(this.phases.values());
  }
}

export const standardWorkflowEngine = new StandardWorkflowEngine();