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
  fridaSession?: string;
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
    // 完整应用安全审计流程
    this.templates.set('comprehensive_security_audit', {
      id: 'comprehensive_security_audit',
      name: '完整应用安全审计',
      description: '对移动应用进行全面的安全性检测，包括静态和动态分析',
      category: 'security_audit',
      difficulty: 'intermediate',
      estimatedTime: '45-60分钟',
      prerequisites: ['Android设备已连接', 'Frida服务器已启动', '目标应用已安装'],
      expectedOutputs: ['安全风险评估报告', '漏洞详情列表', '修复建议'],
      steps: [
        {
          stepId: 'step_01',
          toolName: 'adb_list_devices',
          description: '获取设备基本信息，确认测试环境',
          expectedResult: '设备信息和系统版本',
          tips: ['确认设备已正确连接', '检查ADB调试权限'],
        },
        {
          stepId: 'step_02', 
          toolName: 'adb_screenshot',
          description: '截取设备当前屏幕，记录初始状态',
          expectedResult: '设备屏幕截图',
          tips: ['建议在每个关键步骤都截图记录'],
        },
        {
          stepId: 'step_03',
          toolName: 'adb_list_packages', 
          description: '列出所有已安装应用，选择测试目标',
          expectedResult: '应用列表及包名信息',
          tips: ['重点关注非系统应用', '查看应用版本信息'],
        },
        {
          stepId: 'step_04',
          toolName: 'frida_list_processes',
          description: '查看当前运行的进程，了解系统状态',
          expectedResult: '进程列表和资源使用情况',
          tips: ['关注目标应用是否在运行', '检查可疑进程'],
        },
        {
          stepId: 'step_05',
          toolName: 'adb_start_app',
          description: '启动目标应用，开始动态分析',
          parameters: { package_name: '{目标应用包名}' },
          expectedResult: '应用启动成功',
          tips: ['观察应用启动时的行为', '注意权限请求'],
          nextStepSuggestions: ['frida_attach', 'adb_screenshot']
        },
        {
          stepId: 'step_06',
          toolName: 'frida_attach',
          description: '附加Frida到目标进程，准备Hook',
          expectedResult: 'Frida成功附加到目标进程',
          tips: ['确保应用正在运行', '检查Frida服务器状态'],
          nextStepSuggestions: ['frida_enumerate_classes', 'frida_enumerate_methods']
        },
        {
          stepId: 'step_07',
          toolName: 'frida_enumerate_classes',
          description: '枚举应用中的类，了解代码结构',
          expectedResult: '应用类列表和结构信息',
          tips: ['关注自定义类和关键业务类', '查找加密、认证相关类'],
        }
      ]
    });

    // 登录绕过测试流程
    this.templates.set('login_bypass_test', {
      id: 'login_bypass_test',
      name: '身份认证绕过测试',
      description: '测试应用的身份认证机制是否存在绕过漏洞',
      category: 'penetration_test',
      difficulty: 'expert',
      estimatedTime: '30-45分钟',
      prerequisites: ['目标应用已安装', '了解应用登录流程', 'Frida Hook经验'],
      expectedOutputs: ['认证绕过结果', 'Hook代码示例', '安全建议'],
      steps: [
        {
          stepId: 'login_01',
          toolName: 'adb_screenshot',
          description: '记录应用初始登录界面',
          expectedResult: '登录页面截图',
          tips: ['记录UI元素位置', '观察登录表单结构'],
        },
        {
          stepId: 'login_02',
          toolName: 'adb_start_app',
          description: '启动目标应用',
          expectedResult: '应用正常启动',
          tips: ['确保应用处于登录页面'],
        },
        {
          stepId: 'login_03',
          toolName: 'frida_attach',
          description: '附加到应用进程',
          expectedResult: 'Frida成功附加',
          tips: ['准备Hook认证相关方法'],
        },
        {
          stepId: 'login_04',
          toolName: 'frida_batch_hook',
          description: 'Hook认证相关方法',
          parameters: { 
            class_name: '{认证类名}',
            method_name: '{认证方法名}',
            hook_type: 'modify'
          },
          expectedResult: 'Hook成功，可拦截认证流程',
          tips: ['常见认证方法：login, authenticate, checkUser', '返回值通常是boolean类型'],
          warnings: ['仅在测试环境使用', '注意Hook的影响范围']
        },
        {
          stepId: 'login_05',
          toolName: 'adb_input_text',
          description: '输入测试账号密码',
          expectedResult: '成功输入测试数据',
          tips: ['使用无效凭据测试绕过效果'],
        },
        {
          stepId: 'login_06',
          toolName: 'adb_tap',
          description: '点击登录按钮',
          expectedResult: '触发登录流程',
          tips: ['观察Hook是否生效'],
        },
        {
          stepId: 'login_07',
          toolName: 'adb_screenshot',
          description: '截图验证绕过结果',
          expectedResult: '登录结果截图',
          tips: ['比较绕过前后的界面变化'],
        }
      ]
    });

    // 敏感数据检测流程
    this.templates.set('sensitive_data_detection', {
      id: 'sensitive_data_detection',
      name: '敏感数据泄露检测',
      description: '检测应用是否存在敏感数据泄露风险',
      category: 'data_analysis',
      difficulty: 'beginner',
      estimatedTime: '20-30分钟',
      prerequisites: ['设备已连接', '目标应用已安装'],
      expectedOutputs: ['敏感数据清单', '泄露风险评估', '数据保护建议'],
      steps: [
        {
          stepId: 'data_01',
          toolName: 'adb_start_app',
          description: '启动应用，触发数据生成',
          expectedResult: '应用正常运行',
          tips: ['执行各种操作生成数据'],
        },
        {
          stepId: 'data_02',
          toolName: 'adb_shell_command',
          description: '列出应用数据目录中的文件',
          expectedResult: '应用文件列表',
          tips: ['关注databases、shared_prefs等目录'],
        },
        {
          stepId: 'data_03',
          toolName: 'adb_pull_file_advanced',
          description: '提取应用数据文件',
          expectedResult: '成功提取数据文件',
          tips: ['批量提取多个重要文件', '注意文件权限'],
        },
        {
          stepId: 'data_04',
          toolName: 'frida_memory_search',
          description: '内存中搜索敏感字符串',
          parameters: { 
            pattern: 'password|token|key|secret',
            type: 'string'
          },
          expectedResult: '内存中的敏感数据位置',
          tips: ['搜索常见敏感词汇', '注意加密密钥'],
          warnings: ['内存数据可能包含误报']
        }
      ]
    });

    console.log(`[WorkflowManager] 已加载 ${this.templates.size} 个工作流模板`);
  }

  // 获取所有工作流模板
  getWorkflowTemplates(category?: string): WorkflowTemplate[] {
    const templates = Array.from(this.templates.values());
    return category ? templates.filter(t => t.category === category) : templates;
  }

  // 获取特定工作流模板
  getWorkflowTemplate(templateId: string): WorkflowTemplate | null {
    return this.templates.get(templateId) || null;
  }

  // 更新测试上下文
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

  // 记录工具执行
  recordToolExecution(toolName: string, result: any): void {
    this.context.executedTools.push(toolName);
    this.context.testResults.push({
      tool: toolName,
      timestamp: Date.now(),
      result
    });

    // 更新特定上下文
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

  // 获取智能建议（基于标准工作流程和实战经验）
  getSmartSuggestions(): SmartSuggestion[] {
    const suggestions: SmartSuggestion[] = [];
    const executed = this.context.executedTools;
    const lastTool = executed[executed.length - 1];

    // 基于实际案例的特殊建议逻辑
    this.addCaseBasedSuggestions(suggestions, executed, lastTool);

    // 使用标准工作流引擎获取建议
    const standardSuggestions = standardWorkflowEngine.getNextToolSuggestions(executed, lastTool);
    
    for (const suggestion of standardSuggestions) {
      suggestions.push({
        tool: suggestion.tool,
        reason: suggestion.reason,
        priority: 'high',
        description: suggestion.criticalNotes.length > 0 ? 
          suggestion.criticalNotes[0] : 
          `${suggestion.phase}的标准操作`,
        estimatedTime: this.estimateToolTime(suggestion.tool)
      });
    }

    // 如果标准流程没有建议，使用基础逻辑
    if (suggestions.length === 0) {
      // 完全没有执行过工具 - 推荐标准起点
      if (executed.length === 0) {
        suggestions.push({
          tool: 'frida_list_devices',
          reason: '【阶段一】移动安全测试的标准起点 - 检查设备连接状态',
          priority: 'high',
          description: '检查Frida可连接的设备，确保测试环境就绪',
          estimatedTime: '5秒'
        });
      }

      // 基础环境检查建议
      if (executed.length > 0 && !executed.includes('adb_screenshot')) {
        suggestions.push({
          tool: 'adb_screenshot',
          reason: '【关键操作】截图记录当前状态 - 每个阶段都需要的基础操作',
          priority: 'high',
          description: '截取设备当前屏幕，记录测试状态',
          estimatedTime: '3秒'
        });
      }

      // 智能建议工具本身
      if (executed.length > 3) {
        suggestions.push({
          tool: 'workflow_analyze_context',
          reason: '分析当前测试进度和阶段状态',
          priority: 'medium',
          description: '了解测试完成度和当前所处阶段',
          estimatedTime: '2秒'
        });
      }
    }

    // 始终提供工作流指导工具
    if (suggestions.length < 3) {
      suggestions.push({
        tool: 'workflow_get_templates',
        reason: '查看完整的测试流程模板和最佳实践',
        priority: 'low',
        description: '获取专业的移动安全测试工作流指导',
        estimatedTime: '2秒'
      });
    }

    return suggestions.slice(0, 3);
  }

  // 基于实际案例的特殊建议逻辑  
  private addCaseBasedSuggestions(suggestions: SmartSuggestion[], executed: string[], lastTool: string): void {
    // 🎯 基于麦子钱包案例的实战建议
    
    // 连接稳定性增强 - 来自实际案例
    if (executed.includes('frida_attach') && !executed.includes('frida_connection_status')) {
      suggestions.push({
        tool: 'frida_connection_status',
        reason: '【实战经验】附加后必须验证连接稳定性 - 避免后续操作失败',
        priority: 'high',
        description: '基于实际案例，连接验证是防止中途断开的关键步骤',
        estimatedTime: '3秒'
      });
    }

    // 🚀 Frida附加失败时的Gadget建议
    if (lastTool === 'frida_attach' && executed.length > 3) {
      suggestions.push({
        tool: 'frida_check_gadget_status',
        reason: '【附加失败解决方案】检查应用是否需要部署Gadget',
        priority: 'high',
        description: '非root环境下的Frida附加通常需要Gadget支持',
        estimatedTime: '5秒'
      });
      
      suggestions.push({
        tool: 'frida_deploy_gadget',
        reason: '【终极解决方案】自动部署Gadget解决附加问题',
        priority: 'medium',
        description: '彻底解决非root环境的Frida附加问题',
        estimatedTime: '60秒'
      });
    }

    // 长时间操作前的预防性检查
    if (executed.length > 5 && !executed.includes('frida_connection_status')) {
      suggestions.push({
        tool: 'frida_connection_status', 
        reason: '【预防性监控】长时间测试建议定期检查连接状态',
        priority: 'medium',
        description: '实战表明：批量操作前验证连接可避免中途失败',
        estimatedTime: '3秒'
      });
    }

    // 自动重连优化建议
    if (executed.includes('frida_force_reconnect')) {
      suggestions.push({
        tool: 'adb_screenshot',
        reason: '【错误恢复】重连后建议截屏确认应用状态',
        priority: 'high', 
        description: '实际案例证明：重连后截屏验证状态是最佳实践',
        estimatedTime: '3秒'
      });
    }

    // 批量Hook操作的稳定性建议
    if (lastTool === 'frida_batch_hook' || executed.includes('frida_batch_hook')) {
      suggestions.push({
        tool: 'frida_realtime_logs',
        reason: '【实战经验】批量Hook后立即检查执行结果',
        priority: 'high',
        description: '基于实际测试：批量Hook容易遗漏失败，必须验证',
        estimatedTime: '5秒'
      });
    }

    // 钱包类应用的专项建议
    if (executed.includes('adb_start_app') && this.context.currentApp?.includes('wallet')) {
      suggestions.push({
        tool: 'frida_memory_search',
        reason: '【钱包安全】搜索内存中的私钥和助记词',
        priority: 'high',
        description: '钱包类应用重点检查敏感数据泄露风险',
        estimatedTime: '10秒'
      });
    }

    // 📦 APK静态分析建议 - AAPT工具集
    if (executed.includes('adb_list_packages') && !executed.some(tool => tool.startsWith('aapt_'))) {
      suggestions.push({
        tool: 'aapt_dump_badging',
        reason: '【静态分析】APK基本信息分析 - 版本、权限、SDK信息',
        priority: 'high',
        description: '分析APK基本信息，为动态测试提供关键背景',
        estimatedTime: '5秒'
      });
    }

    // AAPT权限深度分析建议
    if (executed.includes('aapt_dump_badging') && !executed.includes('aapt_dump_permissions')) {
      suggestions.push({
        tool: 'aapt_dump_permissions',
        reason: '【权限分析】深度分析APK权限配置和保护级别',
        priority: 'high',
        description: '分析应用权限模型，识别潜在安全风险',
        estimatedTime: '3秒'
      });
    }

    // 完整APK分析建议
    if (executed.includes('aapt_dump_permissions') && !executed.includes('aapt_analyze_apk')) {
      suggestions.push({
        tool: 'aapt_analyze_apk',
        reason: '【安全评估】完整的APK安全分析和风险评估',
        priority: 'medium',
        description: '生成详细的安全评估报告，包含修复建议',
        estimatedTime: '10秒'
      });
    }

    // 🔍 JADX反编译建议 - 深度代码分析
    if (executed.includes('aapt_dump_badging') && !executed.some(tool => tool.startsWith('jadx_'))) {
      suggestions.push({
        tool: 'jadx_decompile_apk',
        reason: '【源码分析】APK反编译获取Java源代码，进行深度逻辑分析',
        priority: 'high',
        description: '反编译APK为可读的Java代码，分析应用内部逻辑',
        estimatedTime: '30-120秒'
      });
    }

    // JADX反编译完成后的信息分析
    if (executed.includes('jadx_decompile_apk') && !executed.includes('jadx_get_info')) {
      suggestions.push({
        tool: 'jadx_get_info',
        reason: '【代码统计】分析反编译结果的详细信息和项目结构',
        priority: 'medium',
        description: '获取反编译项目的统计信息和包结构概览',
        estimatedTime: '5秒'
      });
    }

    // APK验证建议（在反编译前）
    if (!executed.includes('jadx_validate_apk') && 
        (executed.includes('aapt_dump_badging') || executed.some(tool => tool.includes('apk')))) {
      suggestions.push({
        tool: 'jadx_validate_apk',
        reason: '【预检验证】验证APK文件完整性，确保可正常反编译',
        priority: 'low',
        description: '检查APK文件格式和完整性，避免反编译失败',
        estimatedTime: '3秒'
      });
    }

    // 基于实际测试结果的Frida附加智能建议  
    if (lastTool === 'frida_attach' || (executed.includes('adb_start_app') && !executed.includes('frida_attach'))) {
      suggestions.push({
        tool: 'frida_list_processes',
        reason: '【实战建议】确认目标应用进程已启动并可见',
        priority: 'high',
        description: '验证应用启动状态，为Frida附加做准备',
        estimatedTime: '3秒'
      });
      
      if (!executed.includes('frida_diagnose_environment')) {
        suggestions.push({
          tool: 'frida_diagnose_environment', 
          reason: '【故障排除】检查Frida环境和设备连接',
          priority: 'medium',
          description: '全面诊断Frida服务器状态和权限问题',
          estimatedTime: '8秒'
        });
      }
    }

    // 进程启动延迟的智能处理
    if (lastTool === 'adb_start_app' && !executed.includes('frida_attach')) {
      suggestions.push({
        tool: 'adb_screenshot',
        reason: '【延迟处理】确认应用完全启动后再附加',
        priority: 'high', 
        description: '等待应用完全加载，避免附加时机过早',
        estimatedTime: '3秒'
      });
    }

    // AI调试辅助建议
    if (executed.length > 10 && suggestions.length === 0) {
      suggestions.push({
        tool: 'workflow_analyze_context',
        reason: '【AI辅助】分析当前测试进度，获得后续建议',
        priority: 'medium', 
        description: '复杂测试流程中的智能导航和进度分析',
        estimatedTime: '2秒'
      });
    }
  }

  // 估算工具执行时间
  private estimateToolTime(toolName: string): string {
    const timeMap: { [key: string]: string } = {
      'frida_list_devices': '3秒',
      'adb_screenshot': '2秒', 
      'adb_list_packages': '5秒',
      'adb_start_app': '10秒',
      'frida_attach': '8秒',
      'frida_inject_script': '5秒',
      'adb_tap': '3秒',
      'adb_input_text': '4秒',
      'frida_memory_search': '15秒',
      'frida_save_logs': '5秒'
    };
    return timeMap[toolName] || '5秒';
  }

  // 分析当前测试上下文
  analyzeCurrentContext(): any {
    const executedCount = this.context.executedTools.length;
    const runtime = Math.round((Date.now() - this.context.startTime) / 1000);
    
    // 判断测试阶段
    let currentPhase = 'initialization';
    if (this.context.executedTools.includes('frida_attach')) {
      currentPhase = 'dynamic_analysis';
    } else if (this.context.executedTools.includes('adb_start_app')) {
      currentPhase = 'app_interaction';
    } else if (this.context.executedTools.includes('adb_list_devices')) {
      currentPhase = 'environment_setup';
    }

    // 计算完成度
    const basicTools = ['adb_list_devices', 'adb_list_packages', 'adb_screenshot'];
    const completedBasic = basicTools.filter(tool => this.context.executedTools.includes(tool)).length;
    const completionPercentage = Math.round((completedBasic / basicTools.length) * 100);

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

  // 获取工具协作帮助（基于标准流程）
  getToolCollaborationHelp(toolName: string): any {
    // 先从标准工作流获取专业建议
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
          '此工具是专业移动安全测试的标准组件',
          '建议按照标准工作流顺序执行',
          '每个阶段都有特定的执行要求'
        ]
      };
    }

    // 回退到基础协作建议
    const collaborations: Record<string, any> = {
      'adb_tap': {
        recommended_before: ['adb_screenshot', 'adb_shell_command'],
        recommended_after: ['adb_screenshot'],
        tips: [
          '【标准流程】点击前必须先截图记录界面状态',
          '【标准流程】执行uiautomator dump获取UI布局',
          '【标准流程】点击后立即截图验证结果'
        ],
        warnings: [
          '⚠️ 不按顺序执行可能导致操作失败',
          '⚠️ 跳过截屏验证会错过重要状态变化'
        ],
        standard_sequence: [
          '1. adb_screenshot - 记录当前界面',
          '2. adb_shell_command (uiautomator dump) - 获取UI布局',  
          '3. adb_pull_file - 拉取UI文件分析',
          '4. adb_tap - 执行点击',
          '5. adb_screenshot - 验证结果'
        ]
      },

      'frida_attach': {
        recommended_before: ['frida_list_devices', 'adb_start_app'],
        recommended_after: ['frida_connection_status', 'frida_inject_script'],
        tips: [
          '【标准流程】必须在脚本注入前执行',
          '【标准流程】确保目标应用正在运行',
          '【标准流程】附加成功后立即验证连接状态'
        ],
        warnings: [
          '⚠️ 脚本注入前未附加进程会失败',
          '⚠️ 应用未运行时附加会失败'
        ],
        standard_sequence: [
          '1. frida_list_devices - 确认设备连接',
          '2. adb_start_app - 启动目标应用',
          '3. frida_attach - 附加到进程', 
          '4. frida_connection_status - 验证连接',
          '5. frida_inject_script - 注入脚本'
        ]
      },

      'frida_inject_script': {
        recommended_before: ['frida_attach', 'frida_connection_status'],
        recommended_after: ['frida_realtime_logs'],
        tips: [
          '【标准流程】必须在进程附加后执行',
          '【标准流程】注入后立即启动日志监听',
          '【标准流程】脚本注入是监控的基础'
        ],
        warnings: [
          '⚠️ 未附加进程时注入脚本会失败',
          '⚠️ 连接断开后必须重新注入脚本'
        ],
        critical_dependencies: [
          'frida_attach - 必须先附加进程',
          'frida_connection_status - 建议验证连接稳定'
        ]
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
        '建议参考标准移动安全测试流程',
        '每个操作前后都应截图记录状态', 
        '重要操作前确认设备和应用状态',
        '遵循：准备→连接→操作→监控→恢复的五阶段流程'
      ],
      suggested_next_action: 'workflow_get_smart_suggestions() - 获取基于当前状态的下一步建议'
    };
  }

  // 重置测试会话
  resetSession(): void {
    this.context = {
      executedTools: [],
      testResults: [],
      startTime: Date.now()
    };
    
    console.log('[WorkflowManager] 测试会话已重置');
  }
}

// 全局工作流管理器
export const globalWorkflowManager = new WorkflowManager();