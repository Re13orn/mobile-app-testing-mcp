import { globalLogger } from './logger.js';
import { standardWorkflowEngine } from './standard-workflow.js';

export interface WorkflowTemplate {
  id: string;
  name: string;
  description: string;
  category: 'security_audit' | 'penetration_test' | 'data_analysis' | 'ui_automation';
  difficulty: 'beginner' | 'intermediate' | 'expert';
  estimatedTime: string;
  steps: WorkflowStep[];
  prerequisites: string[];
  expectedOutputs: string[];
}

export interface WorkflowStep {
  stepId: string;
  toolName: string;
  description: string;
  parameters?: any;
  prerequisites?: string[];
  expectedResult: string;
  tips: string[];
  warnings?: string[];
  nextStepSuggestions?: string[];
}

export interface TestContext {
  deviceId?: string;
  deviceInfo?: any;
  connectedApps?: string[];
  currentApp?: string;
  lastScreenshot?: string;
  executedTools: string[];
  testResults: any[];
  startTime: number;
}

export interface SmartSuggestion {
  tool: string;
  reason: string;
  priority: 'high' | 'medium' | 'low';
  description: string;
  estimatedTime: string;
}

export class WorkflowManager {
  private context: TestContext = {
    executedTools: [],
    testResults: [],
    startTime: Date.now()
  };

  private templates: Map<string, WorkflowTemplate> = new Map();

  constructor() {
    this.initializeTemplates();
  }

  private initializeTemplates() {
    this.templates.set('comprehensive_security_audit', {
      id: 'comprehensive_security_audit',
      name: '完整应用安全审计',
      description: '面向移动应用的全流程审计：设备确认 → APK静态分析 → 反编译 → 代码安全扫描',
      category: 'security_audit',
      difficulty: 'intermediate',
      estimatedTime: '45-70分钟',
      prerequisites: ['Android设备已连接', '目标应用已安装', 'AAPT/JADX 可用（推荐）'],
      expectedOutputs: ['风险清单', '高危项证据', '修复建议'],
      steps: [
        {
          stepId: 'audit_01',
          toolName: 'adb_list_devices',
          description: '检查设备连接状态',
          expectedResult: '设备列表与状态',
          tips: ['确保状态为 device', '多设备时先记录设备ID'],
          nextStepSuggestions: ['adb_set_device', 'adb_list_packages']
        },
        {
          stepId: 'audit_02',
          toolName: 'adb_list_packages',
          description: '确认目标应用包名',
          expectedResult: '包名列表和目标包确认',
          tips: ['优先确认目标包名与版本对应关系'],
          nextStepSuggestions: ['aapt_dump_badging']
        },
        {
          stepId: 'audit_03',
          toolName: 'aapt_dump_badging',
          description: '提取APK基础元信息',
          expectedResult: '包名/版本/SDK/调试状态',
          tips: ['先看是否 debuggable', '记录 minSdk/targetSdk'],
          nextStepSuggestions: ['aapt_dump_permissions', 'aapt_dump_xmltree']
        },
        {
          stepId: 'audit_04',
          toolName: 'aapt_dump_permissions',
          description: '分析权限申请',
          expectedResult: '权限列表与保护级别',
          tips: ['关注高风险权限组合'],
          nextStepSuggestions: ['jadx_validate_apk']
        },
        {
          stepId: 'audit_05',
          toolName: 'jadx_validate_apk',
          description: '反编译前完整性检查',
          expectedResult: 'APK可反编译确认',
          tips: ['验证失败时先修复样本来源问题'],
          nextStepSuggestions: ['jadx_decompile_apk']
        },
        {
          stepId: 'audit_06',
          toolName: 'jadx_decompile_apk',
          description: '反编译APK获取源码',
          expectedResult: '反编译目录',
          tips: ['固定输出目录便于复现'],
          nextStepSuggestions: ['static_comprehensive_analysis', 'static_scan_secrets']
        },
        {
          stepId: 'audit_07',
          toolName: 'static_comprehensive_analysis',
          description: '执行综合静态安全扫描',
          expectedResult: '聚合风险报告',
          tips: ['结合前面权限信息交叉验证'],
          nextStepSuggestions: ['file_sha256']
        }
      ]
    });

    this.templates.set('login_flow_behavior_test', {
      id: 'login_flow_behavior_test',
      name: '登录流程行为测试（ADB自动化）',
      description: '不依赖动态Hook，通过ADB自动化还原登录关键路径并保留证据',
      category: 'penetration_test',
      difficulty: 'intermediate',
      estimatedTime: '20-35分钟',
      prerequisites: ['目标应用可正常启动', '已获取目标包名'],
      expectedOutputs: ['关键页面截图序列', '操作轨迹记录', '登录流程异常点'],
      steps: [
        {
          stepId: 'login_01',
          toolName: 'adb_start_app',
          description: '启动应用并进入登录页',
          expectedResult: '登录页可见',
          tips: ['必要时指定 activity'],
          nextStepSuggestions: ['adb_screenshot', 'adb_shell_command']
        },
        {
          stepId: 'login_02',
          toolName: 'adb_screenshot',
          description: '记录登录前页面状态',
          expectedResult: '基线截图',
          tips: ['建议每次关键动作后截图'],
          nextStepSuggestions: ['adb_input_text', 'adb_tap']
        },
        {
          stepId: 'login_03',
          toolName: 'adb_input_text',
          description: '输入测试凭据',
          expectedResult: '输入成功',
          tips: ['先聚焦输入框再输入文本']
        },
        {
          stepId: 'login_04',
          toolName: 'adb_tap',
          description: '点击登录按钮触发流程',
          expectedResult: '页面状态变化',
          tips: ['点击后立即截图验证结果'],
          nextStepSuggestions: ['adb_screenshot', 'adb_shell_command']
        }
      ]
    });

    this.templates.set('apk_reverse_analysis', {
      id: 'apk_reverse_analysis',
      name: 'APK逆向分析模板',
      description: '聚焦APK元信息、清单结构、源码统计和安全扫描的组合流程',
      category: 'data_analysis',
      difficulty: 'beginner',
      estimatedTime: '25-40分钟',
      prerequisites: ['APK文件可访问'],
      expectedOutputs: ['组件与权限概览', '源码结构信息', '初步漏洞候选'],
      steps: [
        {
          stepId: 'rev_01',
          toolName: 'aapt_dump_badging',
          description: '获取APK总体信息',
          expectedResult: '版本/SDK/包名信息',
          tips: ['先确认分析对象准确性']
        },
        {
          stepId: 'rev_02',
          toolName: 'aapt_dump_xmltree',
          description: '解析 AndroidManifest.xml',
          expectedResult: '组件清单结构',
          tips: ['重点查看 exported 组件']
        },
        {
          stepId: 'rev_03',
          toolName: 'jadx_decompile_apk',
          description: '反编译获取源码',
          expectedResult: '反编译目录',
          tips: ['后续扫描建议针对目录执行']
        },
        {
          stepId: 'rev_04',
          toolName: 'jadx_get_info',
          description: '获取反编译统计信息',
          expectedResult: '包结构与文件统计',
          tips: ['先理解结构，再定位敏感模块']
        },
        {
          stepId: 'rev_05',
          toolName: 'static_scan_secrets',
          description: '扫描硬编码敏感信息',
          expectedResult: '疑似密钥与凭据命中',
          tips: ['结合权限和代码调用链验证']
        }
      ]
    });

    this.templates.set('ui_automation_baseline', {
      id: 'ui_automation_baseline',
      name: 'UI自动化取证基线',
      description: '通过ADB自动化实现可复现的界面操作与证据采集',
      category: 'ui_automation',
      difficulty: 'beginner',
      estimatedTime: '15-30分钟',
      prerequisites: ['设备连接正常', '应用可启动'],
      expectedOutputs: ['步骤截图序列', '关键文件导出', '操作命令轨迹'],
      steps: [
        {
          stepId: 'ui_01',
          toolName: 'adb_screenshot',
          description: '记录当前界面',
          expectedResult: '截图文件',
          tips: ['作为每轮操作起点']
        },
        {
          stepId: 'ui_02',
          toolName: 'adb_shell_command',
          description: '采集UI或系统状态信息',
          expectedResult: '命令输出',
          tips: ['建议保存输出用于回溯']
        },
        {
          stepId: 'ui_03',
          toolName: 'adb_tap',
          description: '执行交互操作',
          expectedResult: '界面状态变化',
          tips: ['与截图配套使用']
        },
        {
          stepId: 'ui_04',
          toolName: 'adb_pull_file_advanced',
          description: '拉取关键文件到本地',
          expectedResult: '本地证据文件',
          tips: ['拉取后建议执行 file_sha256']
        }
      ]
    });

    console.log(`[WorkflowManager] 已加载 ${this.templates.size} 个工作流模板`);
  }

  getWorkflowTemplates(category?: string): WorkflowTemplate[] {
    const templates = Array.from(this.templates.values());
    return category ? templates.filter(t => t.category === category) : templates;
  }

  getWorkflowTemplate(templateId: string): WorkflowTemplate | null {
    return this.templates.get(templateId) || null;
  }

  updateContext(updates: Partial<TestContext>): void {
    this.context = { ...this.context, ...updates };

    globalLogger.addLog({
      type: 'info',
      sessionId: 'workflow',
      data: {
        action: 'context_updated',
        updates,
        context: this.context
      }
    });
  }

  recordToolExecution(toolName: string, result: any): void {
    this.context.executedTools.push(toolName);
    this.context.testResults.push({
      tool: toolName,
      timestamp: Date.now(),
      result
    });

    if (toolName === 'adb_list_devices' && result.success) {
      this.context.deviceInfo = result;
    }
    if (toolName === 'adb_screenshot' && result.success) {
      this.context.lastScreenshot = result.localPath;
    }
    if (toolName === 'adb_start_app' && result.success) {
      this.context.currentApp = result.packageName;
    }
  }

  getSmartSuggestions(): SmartSuggestion[] {
    const suggestions: SmartSuggestion[] = [];
    const executed = this.context.executedTools;
    const lastTool = executed[executed.length - 1];

    this.addCaseBasedSuggestions(suggestions, executed, lastTool);

    const standardSuggestions = standardWorkflowEngine.getNextToolSuggestions(executed, lastTool);
    for (const suggestion of standardSuggestions) {
      suggestions.push({
        tool: suggestion.tool,
        reason: suggestion.reason,
        priority: 'high',
        description: suggestion.criticalNotes.length > 0
          ? suggestion.criticalNotes[0]
          : `${suggestion.phase}的标准操作`,
        estimatedTime: this.estimateToolTime(suggestion.tool)
      });
    }

    if (suggestions.length === 0) {
      if (executed.length === 0) {
        suggestions.push({
          tool: 'adb_list_devices',
          reason: '【阶段起点】先确认设备连接，避免后续步骤无效',
          priority: 'high',
          description: '建立测试环境的第一步',
          estimatedTime: '3秒'
        });
      }

      if (executed.length > 0 && !executed.includes('adb_screenshot')) {
        suggestions.push({
          tool: 'adb_screenshot',
          reason: '【关键留证】先保存当前状态，再进行后续操作',
          priority: 'high',
          description: '为操作结果提供可对照证据',
          estimatedTime: '2秒'
        });
      }

      if (executed.length > 3) {
        suggestions.push({
          tool: 'workflow_analyze_context',
          reason: '分析当前测试阶段和完成度',
          priority: 'medium',
          description: '用于调整下一步策略',
          estimatedTime: '2秒'
        });
      }
    }

    if (suggestions.length < 3) {
      suggestions.push({
        tool: 'workflow_get_templates',
        reason: '查看可复用模板与标准流程',
        priority: 'low',
        description: '按模板推进可降低遗漏概率',
        estimatedTime: '2秒'
      });
    }

    const deduped = new Map<string, SmartSuggestion>();
    for (const suggestion of suggestions) {
      if (!deduped.has(suggestion.tool)) {
        deduped.set(suggestion.tool, suggestion);
      }
    }

    return Array.from(deduped.values()).slice(0, 3);
  }

  private addCaseBasedSuggestions(suggestions: SmartSuggestion[], executed: string[], lastTool: string): void {
    if (executed.includes('adb_list_packages') && !executed.some(tool => tool.startsWith('aapt_'))) {
      suggestions.push({
        tool: 'aapt_dump_badging',
        reason: '【静态分析】先提取APK基础元信息',
        priority: 'high',
        description: '版本、SDK、调试状态是后续分析输入',
        estimatedTime: '5秒'
      });
    }

    if (executed.includes('aapt_dump_badging') && !executed.includes('aapt_dump_permissions')) {
      suggestions.push({
        tool: 'aapt_dump_permissions',
        reason: '【权限审查】检查权限暴露面',
        priority: 'high',
        description: '识别高风险权限及组合',
        estimatedTime: '3秒'
      });
    }

    if (executed.includes('aapt_dump_permissions') && !executed.includes('aapt_analyze_apk')) {
      suggestions.push({
        tool: 'aapt_analyze_apk',
        reason: '【综合视图】形成APK级别静态评估',
        priority: 'medium',
        description: '汇总 badging/permissions/xml 结果',
        estimatedTime: '10秒'
      });
    }

    if (executed.includes('aapt_dump_badging') && !executed.includes('jadx_validate_apk')) {
      suggestions.push({
        tool: 'jadx_validate_apk',
        reason: '【反编译预检】先验证APK可用性',
        priority: 'medium',
        description: '避免后续反编译流程中断',
        estimatedTime: '3秒'
      });
    }

    if (executed.includes('jadx_validate_apk') && !executed.includes('jadx_decompile_apk')) {
      suggestions.push({
        tool: 'jadx_decompile_apk',
        reason: '【源码分析】进入反编译阶段',
        priority: 'high',
        description: '生成可审计源码目录',
        estimatedTime: '30-120秒'
      });
    }

    if (executed.includes('jadx_decompile_apk') && !executed.includes('static_scan_secrets')) {
      suggestions.push({
        tool: 'static_scan_secrets',
        reason: '【敏感信息】优先扫描硬编码凭据',
        priority: 'high',
        description: '定位 token/key/secret 风险点',
        estimatedTime: '15秒'
      });
    }

    if (executed.includes('static_scan_secrets') && !executed.includes('static_comprehensive_analysis')) {
      suggestions.push({
        tool: 'static_comprehensive_analysis',
        reason: '【综合评估】输出整体风险画像',
        priority: 'medium',
        description: '统一查看关键风险类别与建议',
        estimatedTime: '20秒'
      });
    }

    if (lastTool === 'adb_start_app' && !executed.includes('adb_screenshot')) {
      suggestions.push({
        tool: 'adb_screenshot',
        reason: '【状态确认】启动后应先截图记录页面状态',
        priority: 'high',
        description: '避免后续定位偏差',
        estimatedTime: '2秒'
      });
    }

    if (executed.includes('adb_pull_file_advanced') && !executed.includes('file_sha256')) {
      suggestions.push({
        tool: 'file_sha256',
        reason: '【证据固化】对拉取文件进行哈希留证',
        priority: 'medium',
        description: '确保文件完整性可验证',
        estimatedTime: '3秒'
      });
    }
  }

  private estimateToolTime(toolName: string): string {
    const timeMap: { [key: string]: string } = {
      'adb_list_devices': '3秒',
      'adb_screenshot': '2秒',
      'adb_list_packages': '5秒',
      'adb_start_app': '10秒',
      'aapt_dump_badging': '5秒',
      'aapt_dump_permissions': '3秒',
      'aapt_analyze_apk': '10秒',
      'jadx_validate_apk': '3秒',
      'jadx_decompile_apk': '30-120秒',
      'jadx_get_info': '5秒',
      'static_scan_secrets': '15秒',
      'static_scan_debug_leaks': '10秒',
      'static_scan_weak_crypto': '10秒',
      'static_comprehensive_analysis': '20秒',
      'file_sha256': '3秒'
    };

    return timeMap[toolName] || '5秒';
  }

  analyzeCurrentContext(): any {
    const executedCount = this.context.executedTools.length;
    const runtime = Math.round((Date.now() - this.context.startTime) / 1000);

    let currentPhase = 'initialization';
    if (this.context.executedTools.some(tool => tool.startsWith('static_'))) {
      currentPhase = 'security_review';
    } else if (this.context.executedTools.some(tool => tool.startsWith('jadx_'))) {
      currentPhase = 'reverse_engineering';
    } else if (this.context.executedTools.some(tool => tool.startsWith('aapt_'))) {
      currentPhase = 'static_apk_analysis';
    } else if (this.context.executedTools.includes('adb_start_app') || this.context.executedTools.includes('adb_tap')) {
      currentPhase = 'app_interaction';
    } else if (this.context.executedTools.includes('adb_list_devices')) {
      currentPhase = 'environment_setup';
    }

    const baselineTools = ['adb_list_devices', 'adb_list_packages', 'aapt_dump_badging', 'jadx_validate_apk'];
    const completedBaseline = baselineTools.filter(tool => this.context.executedTools.includes(tool)).length;
    const completionPercentage = Math.round((completedBaseline / baselineTools.length) * 100);

    return {
      session_summary: {
        executed_tools_count: executedCount,
        runtime_seconds: runtime,
        current_phase: currentPhase,
        completion_percentage: completionPercentage
      },
      device_status: {
        connected: !!this.context.deviceInfo,
        device_id: this.context.deviceId,
        current_app: this.context.currentApp
      },
      recent_activities: this.context.executedTools.slice(-5),
      available_data: {
        screenshots: !!this.context.lastScreenshot,
        device_info: !!this.context.deviceInfo,
        test_results_count: this.context.testResults.length
      }
    };
  }

  getToolCollaborationHelp(toolName: string): any {
    const standardAdvice = standardWorkflowEngine.getToolExecutionAdvice(toolName);

    if (standardAdvice) {
      const validation = standardWorkflowEngine.validateToolOrder(toolName, this.context.executedTools);

      return {
        standard_workflow_phase: standardAdvice.phase,
        dependencies: standardAdvice.dependencies,
        critical_notes: standardAdvice.criticalNotes,
        error_recovery: standardAdvice.errorRecovery,
        validation_status: {
          valid: validation.valid,
          missing_dependencies: validation.missingDependencies,
          warnings: validation.warnings
        },
        workflow_tips: [
          '此工具属于标准流程中的可复用步骤',
          '建议先满足前置依赖再执行',
          '关键步骤建议配合截图和哈希留证'
        ]
      };
    }

    const collaborations: Record<string, any> = {
      'adb_tap': {
        recommended_before: ['adb_screenshot', 'adb_shell_command'],
        recommended_after: ['adb_screenshot'],
        tips: [
          '点击前先截图记录状态',
          '必要时先用 shell 命令获取更多上下文',
          '点击后立即截图验证结果'
        ],
        warnings: ['坐标依赖分辨率，建议在同设备复现']
      },
      'adb_input_text': {
        recommended_before: ['adb_tap'],
        recommended_after: ['adb_screenshot'],
        tips: ['先聚焦输入框再输入文本', '输入后立即截图确认回显'],
        warnings: ['特殊字符可能需要转义']
      },
      'aapt_dump_badging': {
        recommended_before: ['adb_list_packages'],
        recommended_after: ['aapt_dump_permissions', 'aapt_dump_xmltree'],
        tips: ['优先确认包名、版本、SDK与调试状态']
      },
      'jadx_decompile_apk': {
        recommended_before: ['jadx_validate_apk'],
        recommended_after: ['jadx_get_info', 'static_scan_secrets'],
        tips: ['输出目录建议固定，便于版本比较'],
        warnings: ['大型APK反编译时间较长']
      },
      'static_comprehensive_analysis': {
        recommended_before: ['jadx_decompile_apk'],
        recommended_after: ['file_sha256'],
        tips: ['综合扫描后建议立刻整理风险优先级']
      }
    };

    const toolAdvice = collaborations[toolName];
    if (toolAdvice) {
      return {
        ...toolAdvice,
        current_execution_status: this.context.executedTools.includes(toolName) ? '✅ 已执行' : '⏳ 未执行',
        missing_prerequisites: toolAdvice.recommended_before?.filter((tool: string) => !this.context.executedTools.includes(tool)) || []
      };
    }

    return {
      message: `📚 ${toolName} 协作建议`,
      general_tips: [
        '优先建立：设备确认 → APK信息分析 → 反编译 → 静态扫描',
        '关键步骤建议截图留证并记录命令参数',
        '对关键文件执行 SHA256 以保证可复核'
      ],
      suggested_next_action: 'workflow_get_smart_suggestions() - 获取基于当前状态的下一步建议'
    };
  }

  resetSession(): void {
    this.context = {
      executedTools: [],
      testResults: [],
      startTime: Date.now()
    };

    console.log('[WorkflowManager] 测试会话已重置');
  }
}

export const globalWorkflowManager = new WorkflowManager();
