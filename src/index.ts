#!/usr/bin/env node

import { getEnvValue, loadProjectEnv } from './env-utils.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { globalADBManager } from './adb-manager.js';
import { globalWorkflowManager } from './workflow-manager.js';
import { globalAAPTManager } from './aapt-manager.js';
import { globalJADXManager } from './jadx-manager.js';
import { StaticAnalyzer } from './static-analyzer.js';
import { createHash } from 'crypto';
import { existsSync, statSync, readFileSync } from 'fs';
import { basename } from 'path';
import { spawnSync } from 'child_process';

loadProjectEnv();

const adbManager = globalADBManager;
const workflowManager = globalWorkflowManager;
const aaptManager = globalAAPTManager;
const jadxManager = globalJADXManager;

type DependencyCheckResult = {
  name: 'adb' | 'aapt' | 'jadx';
  level: 'required' | 'recommended' | 'optional';
  ok: boolean;
  detail: string;
};

function runVersionCommand(command: string, args: string[]): { ok: boolean; output: string } {
  try {
    const result = spawnSync(command, args, { encoding: 'utf8', stdio: 'pipe', shell: false });
    if (result.status === 0) {
      const output = `${result.stdout || ''}\n${result.stderr || ''}`.trim();
      return { ok: true, output };
    }
    return { ok: false, output: `${result.stderr || result.stdout || ''}`.trim() };
  } catch (error: any) {
    return { ok: false, output: error?.message || 'unknown error' };
  }
}

async function checkRuntimeDependencies(): Promise<DependencyCheckResult[]> {
  const adbCommand = getEnvValue('ADB_PATH') || 'adb';
  const adbResult = runVersionCommand(adbCommand, ['version']);

  const aaptAvailable = await aaptManager.isAvailable();
  const aaptVersion = aaptAvailable ? await aaptManager.getVersion() : null;
  const aaptFallbackHint = getEnvValue('AAPT_PATH') || 'aapt / ANDROID_HOME(build-tools)';

  const jadxAvailable = await jadxManager.isAvailable();
  const jadxVersion = jadxAvailable ? await jadxManager.getVersion() : null;
  const jadxFallbackHint = getEnvValue('JADX_PATH') || 'jadx';

  const adbDetail = adbResult.ok
    ? (adbResult.output.split('\n')[0] || adbCommand)
    : `未找到命令: ${adbCommand}`;
  const aaptDetail = aaptAvailable
    ? (aaptVersion?.split('\n')[0] || '已检测到可用 AAPT')
    : `未找到命令: ${aaptFallbackHint}`;
  const jadxDetail = jadxAvailable
    ? (jadxVersion?.split('\n')[0] || '已检测到可用 JADX')
    : `未找到命令: ${jadxFallbackHint}`;

  return [
    { name: 'adb', level: 'required', ok: adbResult.ok, detail: adbDetail },
    { name: 'aapt', level: 'recommended', ok: aaptAvailable, detail: aaptDetail },
    { name: 'jadx', level: 'optional', ok: jadxAvailable, detail: jadxDetail }
  ];
}

function printDependencyGuidance(results: DependencyCheckResult[]): void {
  const requiredMissing = results.filter(item => item.level === 'required' && !item.ok);
  const anyMissing = results.filter(item => !item.ok);

  console.log('\n[MCP] 运行环境检查:');
  for (const item of results) {
    const levelTag = item.level === 'required' ? '必需' : item.level === 'recommended' ? '推荐' : '可选';
    const statusTag = item.ok ? '✅' : item.level === 'required' ? '❌' : '⚠️';
    console.log(`  ${statusTag} ${item.name} (${levelTag}) - ${item.detail}`);
  }

  if (anyMissing.length === 0) {
    console.log('[MCP] 依赖检查通过，已启用完整能力。');
    return;
  }

  console.log('\n[MCP] 依赖缺失配置指引:');
  if (anyMissing.some(item => item.name === 'adb')) {
    console.log('  1. 安装 Android SDK Platform Tools（提供 adb）');
    console.log('  2. 配置 ADB_PATH，或将 $ANDROID_HOME/platform-tools 加入 PATH');
  }
  if (anyMissing.some(item => item.name === 'aapt')) {
    console.log('  3. 安装 Android SDK Build Tools（提供 aapt）');
    console.log('  4. 配置 AAPT_PATH，或设置 ANDROID_HOME/ANDROID_SDK_ROOT');
  }
  if (anyMissing.some(item => item.name === 'jadx')) {
    console.log('  5. 安装 JADX（可选，缺失会影响反编译工具）');
    console.log('     macOS: brew install jadx');
    console.log('  6. 配置 JADX_PATH，或将 jadx 加入 PATH');
  }
  console.log('  7. 在项目根目录执行: npm run check');
  console.log('  8. 全链路验证: npm run verify');
  console.log('  9. 可在 .env 中配置: ANDROID_HOME / ADB_PATH / AAPT_PATH / JADX_PATH');

  if (requiredMissing.length > 0) {
    console.warn('[MCP] 检测到必需依赖缺失：ADB 相关工具调用会失败，需先完成上面配置。');
  } else {
    console.warn('[MCP] 已进入降级模式：缺失的推荐/可选能力对应工具会不可用。');
  }
}

const server = new Server(
  {
    name: 'mobile-app-testing-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      // ===== ADB 设备管理工具 =====
      {
        name: 'adb_list_devices',
        description: 'ADB设备列表和连接管理',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'adb_connect_device', 
        description: '通过IP连接ADB设备',
        inputSchema: {
          type: 'object',
          properties: {
            host: {
              type: 'string',
              description: '设备IP地址',
            },
            port: {
              type: 'number',
              description: 'ADB端口（默认5555）',
              default: 5555,
            },
          },
          required: ['host'],
        },
      },
      {
        name: 'adb_set_device',
        description: '设置当前活动的ADB设备',
        inputSchema: {
          type: 'object',
          properties: {
            device_id: {
              type: 'string', 
              description: '设备ID',
            },
          },
          required: ['device_id'],
        },
      },

      // ===== ADB 应用管理工具 =====
      {
        name: 'adb_install_app',
        description: '安装APK应用到设备',
        inputSchema: {
          type: 'object',
          properties: {
            apk_path: {
              type: 'string',
              description: 'APK文件路径',
            },
            replace: {
              type: 'boolean', 
              description: '是否覆盖安装（默认false）',
              default: false,
            },
            test: {
              type: 'boolean',
              description: '是否允许测试APK（默认false）',
              default: false,
            },
            downgrade: {
              type: 'boolean',
              description: '是否允许降级安装（默认false）',
              default: false,
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['apk_path'],
        },
      },
      {
        name: 'adb_uninstall_app',
        description: '卸载应用',
        inputSchema: {
          type: 'object',
          properties: {
            package_name: {
              type: 'string',
              description: '应用包名',
            },
            keep_data: {
              type: 'boolean',
              description: '是否保留应用数据（默认false）',
              default: false,
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['package_name'],
        },
      },
      {
        name: 'adb_list_packages',
        description: '列出设备上的应用包',
        inputSchema: {
          type: 'object',
          properties: {
            third_party_only: {
              type: 'boolean',
              description: '只显示第三方应用（默认false）',
              default: false,
            },
            system_only: {
              type: 'boolean', 
              description: '只显示系统应用（默认false）',
              default: false,
            },
            enabled_only: {
              type: 'boolean',
              description: '只显示启用的应用（默认false）',
              default: false,
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
        },
      },
      {
        name: 'adb_grant_permission',
        description: '授予应用权限',
        inputSchema: {
          type: 'object',
          properties: {
            package_name: {
              type: 'string',
              description: '应用包名',
            },
            permission: {
              type: 'string',
              description: '权限名称（如android.permission.CAMERA）',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['package_name', 'permission'],
        },
      },
      {
        name: 'adb_grant_multiple_permissions',
        description: '批量授予应用权限',
        inputSchema: {
          type: 'object',
          properties: {
            package_name: {
              type: 'string',
              description: '应用包名',
            },
            permissions: {
              type: 'array',
              items: {
                type: 'string',
              },
              description: '权限列表',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['package_name', 'permissions'],
        },
      },
      {
        name: 'adb_start_app',
        description: '启动应用',
        inputSchema: {
          type: 'object',
          properties: {
            package_name: {
              type: 'string',
              description: '应用包名',
            },
            activity: {
              type: 'string',
              description: '指定Activity（可选）',
            },
            clear_task: {
              type: 'boolean',
              description: '启动前强制停止（默认false）',
              default: false,
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['package_name'],
        },
      },
      {
        name: 'adb_stop_app',
        description: '强制停止应用',
        inputSchema: {
          type: 'object',
          properties: {
            package_name: {
              type: 'string',
              description: '应用包名',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['package_name'],
        },
      },

      // ===== ADB 文件传输工具 =====
      {
        name: 'adb_push_file',
        description: '推送文件到设备',
        inputSchema: {
          type: 'object',
          properties: {
            local_path: {
              type: 'string',
              description: '本地文件路径',
            },
            remote_path: {
              type: 'string',
              description: '设备目标路径',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['local_path', 'remote_path'],
        },
      },
      {
        name: 'adb_pull_file',
        description: '从设备拉取文件',
        inputSchema: {
          type: 'object',
          properties: {
            remote_path: {
              type: 'string',
              description: '设备文件路径',
            },
            local_path: {
              type: 'string',
              description: '本地保存路径',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['remote_path', 'local_path'],
        },
      },
      {
        name: 'adb_pull_file_advanced',
        description: '高级文件拉取（支持受保护文件，使用多种传输策略）',
        inputSchema: {
          type: 'object',
          properties: {
            remote_path: {
              type: 'string',
              description: '设备文件路径',
            },
            local_path: {
              type: 'string',
              description: '本地保存路径',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['remote_path', 'local_path'],
        },
      },
      {
        name: 'adb_shell_command',
        description: '执行ADB Shell命令',
        inputSchema: {
          type: 'object',
          properties: {
            command: {
              type: 'string',
              description: 'Shell命令',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['command'],
        },
      },

      // ===== ADB 截屏录屏工具 =====
      {
        name: 'adb_screenshot',
        description: '📷 [关键操作] 截取设备屏幕 - 每个阶段都必须的基础操作',
        inputSchema: {
          type: 'object',
          properties: {
            filename: {
              type: 'string',
              description: '文件名（可选，自动生成时间戳文件名）',
            },
            output_dir: {
              type: 'string',
              description: '输出目录绝对路径（可选，默认使用项目screenshots目录）',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
        },
      },
      {
        name: 'adb_start_recording',
        description: '开始录制屏幕',
        inputSchema: {
          type: 'object',
          properties: {
            filename: {
              type: 'string',
              description: '录制文件名（可选）',
            },
            duration: {
              type: 'number',
              description: '录制时长（秒，可选）',
            },
            bit_rate: {
              type: 'number',
              description: '比特率（可选）',
            },
            size: {
              type: 'string',
              description: '视频尺寸，如"1280x720"（可选）',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
        },
      },
      {
        name: 'adb_stop_recording',
        description: '停止录制屏幕',
        inputSchema: {
          type: 'object',
          properties: {
            device_path: {
              type: 'string',
              description: '设备上的录制文件路径',
            },
            local_path: {
              type: 'string',
              description: '本地保存路径',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['device_path', 'local_path'],
        },
      },

      // ===== ADB 输入模拟工具 =====
      {
        name: 'adb_tap',
        description: '模拟点击屏幕',
        inputSchema: {
          type: 'object',
          properties: {
            x: {
              type: 'number',
              description: '点击X坐标',
            },
            y: {
              type: 'number',
              description: '点击Y坐标',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['x', 'y'],
        },
      },
      {
        name: 'adb_swipe',
        description: '模拟滑动手势',
        inputSchema: {
          type: 'object',
          properties: {
            x1: {
              type: 'number',
              description: '起始X坐标',
            },
            y1: {
              type: 'number',
              description: '起始Y坐标',
            },
            x2: {
              type: 'number',
              description: '结束X坐标',
            },
            y2: {
              type: 'number',
              description: '结束Y坐标',
            },
            duration: {
              type: 'number',
              description: '滑动时长（毫秒，默认300）',
              default: 300,
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['x1', 'y1', 'x2', 'y2'],
        },
      },
      {
        name: 'adb_input_text',
        description: '输入文本',
        inputSchema: {
          type: 'object',
          properties: {
            text: {
              type: 'string',
              description: '要输入的文本',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['text'],
        },
      },
      {
        name: 'adb_key_event',
        description: '发送按键事件',
        inputSchema: {
          type: 'object',
          properties: {
            key_code: {
              type: 'number',
              description: '按键代码（如4=返回键，3=Home键，26=电源键）',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['key_code'],
        },
      },
      {
        name: 'adb_long_press',
        description: '模拟长按操作',
        inputSchema: {
          type: 'object',
          properties: {
            x: {
              type: 'number',
              description: '长按X坐标',
            },
            y: {
              type: 'number',
              description: '长按Y坐标',
            },
            duration: {
              type: 'number',
              description: '长按时长（毫秒，默认1000）',
              default: 1000,
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['x', 'y'],
        },
      },

      // ===== 智能工作流协作工具 =====
      {
        name: 'workflow_get_templates',
        description: '获取预定义的测试工作流模板，帮助系统化地执行移动安全测试',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: '工作流类别筛选（security_audit/penetration_test/data_analysis/ui_automation）',
              enum: ['security_audit', 'penetration_test', 'data_analysis', 'ui_automation'],
            },
          },
          required: [],
        },
      },

      {
        name: 'workflow_get_template_details',
        description: '获取特定工作流模板的详细信息，包括步骤说明和预期结果',
        inputSchema: {
          type: 'object',
          properties: {
            template_id: {
              type: 'string',
              description: '工作流模板ID（如comprehensive_security_audit）',
            },
          },
          required: ['template_id'],
        },
      },

      {
        name: 'workflow_get_smart_suggestions',
        description: '基于当前测试上下文，获取下一步建议执行的工具和操作',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },

      {
        name: 'workflow_analyze_context',
        description: '分析当前测试会话的状态，包括已执行工具、测试阶段、完成度等',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },

      {
        name: 'workflow_get_tool_help',
        description: '获取特定工具的协作建议，包括前置条件、后续工具、使用技巧等',
        inputSchema: {
          type: 'object',
          properties: {
            tool_name: {
              type: 'string',
              description: '工具名称（如adb_tap、aapt_dump_badging）',
            },
          },
          required: ['tool_name'],
        },
      },

      {
        name: 'workflow_record_execution',
        description: '记录工具执行结果到测试上下文中，用于智能建议和进度跟踪',
        inputSchema: {
          type: 'object',
          properties: {
            tool_name: {
              type: 'string',
              description: '执行的工具名称',
            },
            result: {
              type: 'object',
              description: '工具执行结果',
            },
          },
          required: ['tool_name', 'result'],
        },
      },
      
      // ===== AAPT APK分析工具 =====
      {
        name: 'aapt_dump_badging',
        description: '🔍 [静态分析] 使用AAPT分析APK基本信息 - 包名、版本、权限、SDK版本等',
        inputSchema: {
          type: 'object',
          properties: {
            apk_path: {
              type: 'string',
              description: 'APK文件路径（本地路径或设备路径）',
            },
            auto_pull: {
              type: 'boolean',
              description: '如果是设备路径，是否自动从设备拉取APK（默认true）',
              default: true,
            },
          },
          required: ['apk_path'],
        },
      },
      {
        name: 'aapt_dump_permissions',
        description: '🔐 [权限分析] 使用AAPT分析APK权限详情',
        inputSchema: {
          type: 'object',
          properties: {
            apk_path: {
              type: 'string',
              description: 'APK文件路径（本地路径或设备路径）',
            },
            auto_pull: {
              type: 'boolean',
              description: '如果是设备路径，是否自动从设备拉取APK（默认true）',
              default: true,
            },
          },
          required: ['apk_path'],
        },
      },
      {
        name: 'aapt_analyze_apk',
        description: '📊 [完整分析] 使用AAPT对APK进行完整的静态分析 - 包含基本信息、权限、资源等',
        inputSchema: {
          type: 'object',
          properties: {
            apk_path: {
              type: 'string',
              description: 'APK文件路径（本地路径或设备路径）',
            },
            auto_pull: {
              type: 'boolean',
              description: '如果是设备路径，是否自动从设备拉取APK（默认true）',
              default: true,
            },
            include_resources: {
              type: 'boolean',
              description: '是否包含资源分析（可能产生大量数据，默认false）',
              default: false,
            },
            xml_trees: {
              type: 'array',
              items: { type: 'string' },
              description: '要分析的XML文件列表（如AndroidManifest.xml）',
              default: ['AndroidManifest.xml'],
            },
          },
          required: ['apk_path'],
        },
      },
      {
        name: 'aapt_dump_xmltree',
        description: '📄 [XML分析] 使用AAPT分析APK中的XML文件结构',
        inputSchema: {
          type: 'object',
          properties: {
            apk_path: {
              type: 'string',
              description: 'APK文件路径（本地路径或设备路径）',
            },
            xml_file: {
              type: 'string',
              description: '要分析的XML文件名（如AndroidManifest.xml）',
              default: 'AndroidManifest.xml',
            },
            auto_pull: {
              type: 'boolean',
              description: '如果是设备路径，是否自动从设备拉取APK（默认true）',
              default: true,
            },
          },
          required: ['apk_path'],
        },
      },
      
      // === 文件工具 ===
      {
        name: 'file_sha256',
        description: '🔐 [文件完整性] 计算文件的SHA256哈希值，用于文件指纹识别和完整性验证',
        inputSchema: {
          type: 'object',
          properties: {
            file_path: {
              type: 'string',
              description: '文件路径（本地路径或设备路径）',
            },
            auto_pull: {
              type: 'boolean',
              description: '如果是设备路径，是否自动从设备拉取文件（默认true）',
              default: true,
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选）',
            },
          },
          required: ['file_path'],
        },
      },
      
      // === 静态安全分析工具 ===
      {
        name: 'static_scan_secrets',
        description: '🔍 [静态分析] 扫描源码中的硬编码敏感信息（API密钥、密码、证书等）',
        inputSchema: {
          type: 'object',
          properties: {
            target_path: {
              type: 'string',
              description: '要扫描的文件或目录路径（反编译后的源码目录或APK文件）'
            },
            pattern_type: {
              type: 'string',
              enum: ['all', 'api_keys', 'passwords', 'certificates', 'database', 'cloud_keys', 'mobile_specific'],
              description: '扫描模式类型（默认: all）',
              default: 'all'
            }
          },
          required: ['target_path'],
        },
      },
      {
        name: 'static_scan_debug_leaks',
        description: '🐛 [静态分析] 扫描可能泄露调试信息的代码（日志输出、异常打印等）',
        inputSchema: {
          type: 'object',
          properties: {
            target_path: {
              type: 'string',
              description: '要扫描的文件或目录路径'
            }
          },
          required: ['target_path'],
        },
      },
      {
        name: 'static_scan_weak_crypto',
        description: '🔒 [静态分析] 检测弱加密算法的使用（MD5、DES、RC4等不安全算法）',
        inputSchema: {
          type: 'object',
          properties: {
            target_path: {
              type: 'string',
              description: '要扫描的文件或目录路径'
            }
          },
          required: ['target_path'],
        },
      },
      {
        name: 'static_comprehensive_analysis',
        description: '📊 [静态分析] 执行全面的静态安全分析，包括敏感信息、调试泄露、弱加密等',
        inputSchema: {
          type: 'object',
          properties: {
            target_path: {
              type: 'string',
              description: '要扫描的文件或目录路径'
            }
          },
          required: ['target_path'],
        },
      },
      
      // === JADX 反编译工具 ===
      {
        name: 'jadx_decompile_apk',
        description: '🔍 [APK反编译] 使用JADX将APK反编译为Java源代码，支持详细的代码分析',
        inputSchema: {
          type: 'object',
          properties: {
            apk_path: {
              type: 'string',
              description: 'APK文件路径（本地路径或设备路径）',
            },
            output_dir: {
              type: 'string',
              description: '反编译输出目录（可选，默认为decompiled/{apk_name}_decompiled）',
            },
            auto_pull: {
              type: 'boolean',
              description: '如果是设备路径，是否自动从设备拉取APK（默认true）',
              default: true,
            },
            show_bad_code: {
              type: 'boolean',
              description: '显示可能有问题的代码（默认false）',
              default: false,
            },
            deobfuscation: {
              type: 'boolean',
              description: '启用反混淆功能（默认false）',
              default: false,
            },
            threads_count: {
              type: 'number',
              description: '反编译使用的线程数（默认为CPU核心数）',
            },
            verbose: {
              type: 'boolean',
              description: '详细输出模式（默认false）',
              default: false,
            },
          },
          required: ['apk_path'],
        },
      },
      
      {
        name: 'jadx_get_info',
        description: '📊 [反编译信息] 获取已反编译APK的详细信息和统计数据',
        inputSchema: {
          type: 'object',
          properties: {
            output_dir: {
              type: 'string',
              description: '反编译输出目录路径',
            },
          },
          required: ['output_dir'],
        },
      },
      
      {
        name: 'jadx_validate_apk',
        description: '✅ [APK验证] 验证APK文件格式和完整性，确保可以正常反编译',
        inputSchema: {
          type: 'object',
          properties: {
            apk_path: {
              type: 'string',
              description: 'APK文件路径',
            },
          },
          required: ['apk_path'],
        },
      },
    ],
  };
});

// AAPT工具的辅助方法
async function handleAPKPath(apkPath: string, autoPull: boolean): Promise<string> {
  // 如果是本地路径且文件存在，直接返回
  if (!apkPath.startsWith('/data/app/') && !apkPath.startsWith('/system/app/')) {
    return apkPath;
  }

  // 设备路径需要拉取到本地
  if (autoPull) {
    try {
      const pullResult = await adbManager.pullFile(apkPath, './');
      if (pullResult.success && pullResult.localPath) {
        return pullResult.localPath;
      }
    } catch (error) {
      console.warn(`[AAPT] 无法从设备拉取APK: ${error}`);
    }
  }

  return apkPath;
}

function countDangerousPermissions(permissions: string[]): number {
  const dangerousPermissions = [
    'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
    'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALENDAR', 'WRITE_CALENDAR',
    'READ_SMS', 'SEND_SMS', 'READ_PHONE_STATE', 'CALL_PHONE',
    'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'
  ];
  
  return permissions.filter(perm => 
    dangerousPermissions.some(dangerous => perm.includes(dangerous))
  ).length;
}

function countSpecialPermissions(permissions: string[]): number {
  const specialPermissions = [
    'SYSTEM_ALERT_WINDOW', 'WRITE_SETTINGS', 'REQUEST_INSTALL_PACKAGES',
    'PACKAGE_USAGE_STATS', 'BIND_ACCESSIBILITY_SERVICE'
  ];
  
  return permissions.filter(perm =>
    specialPermissions.some(special => perm.includes(special))
  ).length;
}

function generateSecurityAssessment(badging: any, permissions: any[]): string {
  const assessments: string[] = [];
  
  if (badging?.applicationDebugable) {
    assessments.push('⚠️ 应用可调试 - 存在安全风险');
  }
  
  const dangerousCount = countDangerousPermissions(badging?.usesPermissions || []);
  if (dangerousCount > 5) {
    assessments.push('⚠️ 申请过多危险权限');
  }
  
  if (badging?.minSdkVersion && parseInt(badging.minSdkVersion) < 23) {
    assessments.push('⚠️ 支持较旧的Android版本');
  }
  
  if (!badging?.nativeCode || badging.nativeCode.length === 0) {
    assessments.push('✅ 纯Java应用，逆向分析相对容易');
  } else {
    assessments.push('⚠️ 包含原生代码，可能有反调试保护');
  }
  
  if (assessments.length === 0) {
    assessments.push('✅ 基本安全检查通过');
  }
  
  return assessments.join('\n');
}

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {



















      // ===== ADB 设备管理工具 =====
      case 'adb_list_devices': {
        const devices = await adbManager.listDevices();
        const deviceText = devices.length > 0 
          ? devices
              .map(d => `📱 ${d.id} (${d.state}) ${d.model ? `- ${d.model}` : ''}`)
              .join('\n')
          : '❌ 未发现ADB设备';
        
        return {
          content: [
            {
              type: 'text',
              text: `🔍 发现 ${devices.length} 个ADB设备:\n${deviceText}`,
            },
          ],
        };
      }

      case 'adb_connect_device': {
        const { host, port = 5555 } = args as { host: string; port?: number };
        const success = await adbManager.connectDevice(host, port);
        
        return {
          content: [
            {
              type: 'text',
              text: success 
                ? `✅ 成功连接设备: ${host}:${port}`
                : `❌ 连接设备失败: ${host}:${port}`,
            },
          ],
        };
      }

      case 'adb_set_device': {
        const { device_id } = args as { device_id: string };
        adbManager.setCurrentDevice(device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: `📱 已切换到设备: ${device_id}`,
            },
          ],
        };
      }

      // ===== ADB 应用管理工具 =====
      case 'adb_install_app': {
        const { apk_path, replace = false, test = false, downgrade = false, device_id } = args as {
          apk_path: string; replace?: boolean; test?: boolean; downgrade?: boolean; device_id?: string;
        };
        
        const success = await adbManager.installApp(apk_path, { 
          replace, test, downgrade, deviceId: device_id 
        });
        
        return {
          content: [
            {
              type: 'text',
              text: success 
                ? `✅ 应用安装成功: ${apk_path}`
                : `❌ 应用安装失败: ${apk_path}`,
            },
          ],
        };
      }

      case 'adb_uninstall_app': {
        const { package_name, keep_data = false, device_id } = args as {
          package_name: string; keep_data?: boolean; device_id?: string;
        };
        
        const success = await adbManager.uninstallApp(package_name, keep_data, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: success 
                ? `✅ 应用卸载成功: ${package_name}`
                : `❌ 应用卸载失败: ${package_name}`,
            },
          ],
        };
      }

      case 'adb_list_packages': {
        const { third_party_only = false, system_only = false, enabled_only = false, device_id } = args as {
          third_party_only?: boolean; system_only?: boolean; enabled_only?: boolean; device_id?: string;
        };
        
        const packages = await adbManager.listPackages({
          thirdPartyOnly: third_party_only,
          systemOnly: system_only,
          enabledOnly: enabled_only,
          deviceId: device_id
        });
        
        const packageText = packages.length > 0 
          ? packages.slice(0, 20).join('\n')
          : '❌ 未找到应用包';
        
        return {
          content: [
            {
              type: 'text',
              text: `📦 找到 ${packages.length} 个应用包:\n${packageText}${packages.length > 20 ? '\n... (显示前20个)' : ''}`,
            },
          ],
        };
      }

      case 'adb_grant_permission': {
        const { package_name, permission, device_id } = args as {
          package_name: string; permission: string; device_id?: string;
        };
        
        const success = await adbManager.grantPermission(package_name, permission, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: success 
                ? `✅ 权限授予成功: ${package_name} -> ${permission}`
                : `❌ 权限授予失败: ${package_name} -> ${permission}`,
            },
          ],
        };
      }

      case 'adb_grant_multiple_permissions': {
        const { package_name, permissions, device_id } = args as {
          package_name: string; permissions: string[]; device_id?: string;
        };
        
        const result = await adbManager.grantMultiplePermissions(package_name, permissions, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: `🔐 批量权限授予结果:\n成功: ${result.granted.length} 个\n失败: ${result.failed.length} 个\n\n成功权限:\n${result.granted.join('\n')}\n\n失败权限:\n${result.failed.join('\n')}`,
            },
          ],
        };
      }

      case 'adb_start_app': {
        const { package_name, activity, clear_task = false, device_id } = args as {
          package_name: string; activity?: string; clear_task?: boolean; device_id?: string;
        };
        
        const success = clear_task 
          ? await adbManager.startAppWithClear(package_name, activity, device_id)
          : await adbManager.startApp(package_name, activity, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: success 
                ? `✅ 应用启动成功: ${package_name}${activity ? ` (${activity})` : ''}`
                : `❌ 应用启动失败: ${package_name}`,
            },
          ],
        };
      }

      case 'adb_stop_app': {
        const { package_name, device_id } = args as { package_name: string; device_id?: string };
        
        const success = await adbManager.forceStopApp(package_name, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: success 
                ? `✅ 应用停止成功: ${package_name}`
                : `❌ 应用停止失败: ${package_name}`,
            },
          ],
        };
      }

      // ===== ADB 文件传输工具 =====
      case 'adb_push_file': {
        const { local_path, remote_path, device_id } = args as {
          local_path: string; remote_path: string; device_id?: string;
        };
        
        const result = await adbManager.pushFile(local_path, remote_path, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `✅ 文件推送成功:\n本地: ${result.localPath}\n设备: ${result.remotePath}`
                : `❌ 文件推送失败:\n错误: ${result.error}`,
            },
          ],
        };
      }

      case 'adb_pull_file': {
        const { remote_path, local_path, device_id } = args as {
          remote_path: string; local_path: string; device_id?: string;
        };
        
        const result = await adbManager.pullFile(remote_path, local_path, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `✅ 文件拉取成功:\n设备: ${result.remotePath}\n本地: ${result.localPath}`
                : `❌ 文件拉取失败:\n错误: ${result.error}`,
            },
          ],
        };
      }

      case 'adb_pull_file_advanced': {
        const { remote_path, local_path, device_id } = args as {
          remote_path: string; local_path: string; device_id?: string;
        };
        
        const result = await adbManager.pullFileAdvanced(remote_path, local_path, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `✅ 高级文件拉取成功:\n设备: ${result.remotePath}\n本地: ${result.localPath}\n大小: ${result.size} 字节`
                : `❌ 高级文件拉取失败:\n错误: ${result.error}`,
            },
          ],
        };
      }

      case 'adb_shell_command': {
        const { command, device_id } = args as { command: string; device_id?: string };
        
        const result = await adbManager.runShellCommand(command, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: `🐚 Shell命令执行结果:\n命令: ${command}\n状态: ${result.success ? '成功' : '失败'}\n\n输出:\n${result.stdout}\n\n错误:\n${result.stderr}`,
            },
          ],
        };
      }

      // ===== ADB 截屏录屏工具 =====
      case 'adb_screenshot': {
        const { filename, output_dir, device_id } = args as { filename?: string; output_dir?: string; device_id?: string };
        
        const result = await adbManager.takeScreenshot(filename, device_id, output_dir);
        
        // 记录工具执行
        workflowManager.recordToolExecution('adb_screenshot', result);
        
        // 获取下一步建议
        const suggestions = workflowManager.getSmartSuggestions();
        const nextSteps = suggestions.slice(0, 3).map(s => 
          `• ${s.tool} - ${s.reason}`
        ).join('\n');
        
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `📸 截屏成功:\n保存路径: ${result.localPath}\n\n🎯 建议下一步:\n${nextSteps}`
                : `❌ 截屏失败:\n错误: ${result.error}\n\n💡 故障排除:\n• workflow_get_smart_suggestions - 获取问题诊断建议\n• adb_list_devices - 检查设备连接状态`,
            },
          ],
        };
      }

      case 'adb_start_recording': {
        const { filename, duration, bit_rate, size, device_id } = args as {
          filename?: string; duration?: number; bit_rate?: number; size?: string; device_id?: string;
        };
        
        const result = await adbManager.startScreenRecord(filename, {
          duration, bitRate: bit_rate, size, deviceId: device_id
        });
        
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `🎥 开始录屏:\n文件: ${result.localPath}\n时长: ${result.duration ? `${result.duration}秒` : '无限制'}`
                : `❌ 录屏启动失败:\n错误: ${result.error}`,
            },
          ],
        };
      }

      case 'adb_stop_recording': {
        const { device_path, local_path, device_id } = args as {
          device_path: string; local_path: string; device_id?: string;
        };
        
        const result = await adbManager.stopScreenRecord(device_path, local_path, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `🎬 录屏停止成功:\n保存路径: ${result.localPath}`
                : `❌ 录屏停止失败:\n错误: ${result.error}`,
            },
          ],
        };
      }

      // ===== ADB 输入模拟工具 =====
      case 'adb_tap': {
        const { x, y, device_id } = args as { x: number; y: number; device_id?: string };
        
        const result = await adbManager.tap(x, y, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `👆 点击成功: (${x}, ${y})`
                : `❌ 点击失败: ${result.error}`,
            },
          ],
        };
      }

      case 'adb_swipe': {
        const { x1, y1, x2, y2, duration = 300, device_id } = args as {
          x1: number; y1: number; x2: number; y2: number; duration?: number; device_id?: string;
        };
        
        const result = await adbManager.swipe(x1, y1, x2, y2, duration, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `👆 滑动成功: (${x1}, ${y1}) → (${x2}, ${y2}) [${duration}ms]`
                : `❌ 滑动失败: ${result.error}`,
            },
          ],
        };
      }

      case 'adb_input_text': {
        const { text, device_id } = args as { text: string; device_id?: string };
        
        const result = await adbManager.inputText(text, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `⌨️ 文本输入成功: "${text}"`
                : `❌ 文本输入失败: ${result.error}`,
            },
          ],
        };
      }

      case 'adb_key_event': {
        const { key_code, device_id } = args as { key_code: number; device_id?: string };
        
        const result = await adbManager.keyEvent(key_code, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `⌨️ 按键事件成功: ${key_code}`
                : `❌ 按键事件失败: ${result.error}`,
            },
          ],
        };
      }

      case 'adb_long_press': {
        const { x, y, duration = 1000, device_id } = args as {
          x: number; y: number; duration?: number; device_id?: string;
        };
        
        const result = await adbManager.longPress(x, y, duration, device_id);
        
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `👆 长按成功: (${x}, ${y}) [${duration}ms]`
                : `❌ 长按失败: ${result.error}`,
            },
          ],
        };
      }

      // ===== 智能工作流协作工具处理 =====
      case 'workflow_get_templates': {
        const { category } = args as { category?: string };
        const templates = workflowManager.getWorkflowTemplates(category);
        
        return {
          content: [
            {
              type: 'text',
              text: `📋 **可用工作流模板 (${templates.length}个)**\n\n` +
                templates.map(t => 
                  `**${t.name}** (${t.difficulty})\n` +
                  `├── 分类: ${t.category}\n` +
                  `├── 预计时间: ${t.estimatedTime}\n` +
                  `├── 步骤数: ${t.steps.length}个\n` +
                  `└── 描述: ${t.description}\n`
                ).join('\n')
            },
          ],
        };
      }

      case 'workflow_get_template_details': {
        const { template_id } = args as { template_id: string };
        const template = workflowManager.getWorkflowTemplate(template_id);
        
        if (!template) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ 未找到工作流模板: ${template_id}`,
              },
            ],
          };
        }

        const stepsText = template.steps.map((step: any, index: number) =>
          `**步骤 ${index + 1}: ${step.toolName}**\n` +
          `├── 描述: ${step.description}\n` +
          `├── 预期结果: ${step.expectedResult}\n` +
          `├── 使用技巧: ${step.tips.join('; ')}\n` +
          (step.warnings ? `├── ⚠️  警告: ${step.warnings.join('; ')}\n` : '') +
          `└── 下一步建议: ${step.nextStepSuggestions?.join('; ') || '无'}\n`
        ).join('\n');

        return {
          content: [
            {
              type: 'text',
              text: `📖 **工作流详情: ${template.name}**\n\n` +
                `**基本信息:**\n` +
                `├── 分类: ${template.category}\n` +
                `├── 难度: ${template.difficulty}\n` +
                `├── 预计时间: ${template.estimatedTime}\n` +
                `└── 描述: ${template.description}\n\n` +
                `**前置条件:**\n${template.prerequisites.map((p: string) => `• ${p}`).join('\n')}\n\n` +
                `**预期输出:**\n${template.expectedOutputs.map((o: string) => `• ${o}`).join('\n')}\n\n` +
                `**执行步骤:**\n${stepsText}`
            },
          ],
        };
      }

      case 'workflow_get_smart_suggestions': {
        const suggestions = workflowManager.getSmartSuggestions();
        
        if (suggestions.length === 0) {
          return {
            content: [
              {
                type: 'text',
                text: '🤖 暂无智能建议，您可以从基础工具开始：\n\n' +
                      '• `adb_list_devices` - 获取设备信息\n' +
                      '• `adb_screenshot` - 截图记录当前状态\n' +
                      '• `adb_list_packages` - 查看已安装应用'
              },
            ],
          };
        }

        const suggestionsText = suggestions.map(s =>
          `**${s.tool}** (${s.priority}优先级)\n` +
          `├── 原因: ${s.reason}\n` +
          `├── 描述: ${s.description}\n` +
          `└── 预计时间: ${s.estimatedTime}\n`
        ).join('\n');

        return {
          content: [
            {
              type: 'text',
              text: `🎯 **智能建议 (${suggestions.length}个)**\n\n${suggestionsText}`
            },
          ],
        };
      }

      case 'workflow_analyze_context': {
        const context = workflowManager.analyzeCurrentContext();
        
        return {
          content: [
            {
              type: 'text',
              text: `📊 **测试会话分析**\n\n` +
                `**会话概要:**\n` +
                `├── 已执行工具: ${context.session_summary.executed_tools_count}个\n` +
                `├── 运行时间: ${context.session_summary.runtime_seconds}秒\n` +
                `├── 当前阶段: ${context.session_summary.current_phase}\n` +
                `└── 完成度: ${context.session_summary.completion_percentage}%\n\n` +
                `**设备状态:**\n` +
                `├── 设备连接: ${context.device_status.connected ? '✅' : '❌'}\n` +
                `├── 设备ID: ${context.device_status.device_id || '未知'}\n` +
                `└── 当前应用: ${context.device_status.current_app || '无'}\n\n` +
                `**最近活动:**\n${context.recent_activities.map((a: string) => `• ${a}`).join('\n')}\n\n` +
                `**可用数据:**\n` +
                `├── 截图文件: ${context.available_data.screenshots ? '✅' : '❌'}\n` +
                `├── 设备信息: ${context.available_data.device_info ? '✅' : '❌'}\n` +
                `└── 测试结果: ${context.available_data.test_results_count}个`
            },
          ],
        };
      }

      case 'workflow_get_tool_help': {
        const { tool_name } = args as { tool_name: string };

        const help = workflowManager.getToolCollaborationHelp(tool_name);
        
        return {
          content: [
            {
              type: 'text',
              text: `🛠️ **工具协作指南: ${tool_name}**\n\n` +
                (help.recommended_before && help.recommended_before.length > 0 ? `**建议前置工具:**\n${help.recommended_before.map((t: string) => `• ${t}`).join('\n')}\n\n` : '') +
                (help.recommended_after && help.recommended_after.length > 0 ? `**建议后续工具:**\n${help.recommended_after.map((t: string) => `• ${t}`).join('\n')}\n\n` : '') +
                (help.tips ? `**使用技巧:**\n${help.tips.map((t: string) => `• ${t}`).join('\n')}\n\n` : '') +
                (help.warnings ? `**⚠️ 注意事项:**\n${help.warnings.map((w: string) => `• ${w}`).join('\n')}\n\n` : '') +
                (help.common_workflows && help.common_workflows.length > 0 ? `**常用工作流:**\n${help.common_workflows.map((w: string) => `• ${w}`).join('\n')}\n\n` : '') +
                (help.general_tips ? `**通用建议:**\n${help.general_tips.map((t: string) => `• ${t}`).join('\n')}` : '') +
                (help.message ? help.message : '')
            },
          ],
        };
      }

      case 'workflow_record_execution': {
        const { tool_name, result } = args as { tool_name: string; result: any };
        workflowManager.recordToolExecution(tool_name, result);
        
        return {
          content: [
            {
              type: 'text',
              text: `📝 已记录工具执行: ${tool_name}\n\n` +
                    `您可以使用 \`workflow_get_smart_suggestions\` 获取下一步建议。`
            },
          ],
        };
      }

      // ===== AAPT APK分析工具处理 =====
      case 'aapt_dump_badging': {
        const { apk_path, auto_pull = true } = args as {
          apk_path: string;
          auto_pull?: boolean;
        };

        try {
          console.log(`[MCP] 开始AAPT badging分析: ${apk_path}`);
          
          // 处理APK路径 - 如果是设备路径则先拉取
          const localApkPath = await handleAPKPath(apk_path, auto_pull);
          
          const badging = await aaptManager.dumpBadging(localApkPath);
          
          return {
            content: [
              {
                type: 'text',
                text: `🔍 APK Badging 分析结果\n\n` +
                      `📦 基本信息:\n` +
                      `• 应用包名: ${badging.packageName || '未知'}\n` +
                      `• 版本名称: ${badging.versionName || '未知'}\n` +
                      `• 版本代码: ${badging.versionCode || '未知'}\n` +
                      `• 应用标签: ${badging.applicationLabel || '未知'}\n\n` +
                      
                      `🎯 SDK信息:\n` +
                      `• 最小SDK版本: ${badging.minSdkVersion || '未知'}\n` +
                      `• 目标SDK版本: ${badging.targetSdkVersion || '未知'}\n` +
                      `• 编译SDK版本: ${badging.compileSdkVersion || '未知'}\n` +
                      `• 平台版本: ${badging.platformBuildVersionName || '未知'}\n\n` +
                      
                      `🔐 权限信息:\n` +
                      `• 使用权限数量: ${badging.usesPermissions?.length || 0}\n` +
                      (badging.usesPermissions && badging.usesPermissions.length > 0 
                        ? `• 主要权限:\n${badging.usesPermissions.slice(0, 5).map(p => `  - ${p}`).join('\n')}\n` +
                          (badging.usesPermissions.length > 5 ? `  ... 还有 ${badging.usesPermissions.length - 5} 个权限\n` : '')
                        : '') + '\n' +
                      
                      `🛠️ 技术信息:\n` +
                      `• 安装位置: ${badging.installLocation || '默认'}\n` +
                      `• 可调试: ${badging.applicationDebugable ? '✅ 是' : '❌ 否'}\n` +
                      `• 支持架构: ${badging.nativeCode?.join(', ') || '无原生代码'}\n` +
                      `• 屏幕密度: ${badging.densities?.join(', ') || '通用'}\n\n` +
                      
                      `🎯 下一步建议:\n` +
                      `• 使用 aapt_dump_permissions 详细分析权限\n` +
                      `• 使用 aapt_dump_xmltree 分析AndroidManifest.xml\n` +
                      `• 使用 adb_start_app 启动应用进行动态分析`
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ AAPT badging 分析失败:\n${error.message}\n\n` +
                      `💡 可能的原因:\n` +
                      `• AAPT工具未安装或不在PATH中\n` +
                      `• APK文件路径错误或文件损坏\n` +
                      `• 权限不足无法访问文件\n\n` +
                      `🔧 解决建议:\n` +
                      `• 确保Android SDK已安装\n` +
                      `• 检查APK文件是否存在: ${apk_path}\n` +
                      `• 使用 adb_list_devices 检查设备连接环境`
              },
            ],
          };
        }
      }

      case 'aapt_dump_permissions': {
        const { apk_path, auto_pull = true } = args as {
          apk_path: string;
          auto_pull?: boolean;
        };

        try {
          console.log(`[MCP] 开始AAPT权限分析: ${apk_path}`);
          
          const localApkPath = await handleAPKPath(apk_path, auto_pull);
          const permissions = await aaptManager.dumpPermissions(localApkPath);
          
          return {
            content: [
              {
                type: 'text',
                text: `🔐 APK 权限详细分析\n\n` +
                      `📊 权限统计:\n` +
                      `• 总权限数量: ${permissions.length}\n\n` +
                      
                      (permissions.length > 0
                        ? `📋 权限列表:\n` +
                          permissions.map((perm, index) => 
                            `${index + 1}. ${perm.name}\n` +
                            (perm.protectionLevel ? `   保护级别: ${perm.protectionLevel}\n` : '') +
                            (perm.label ? `   标签: ${perm.label}\n` : '') +
                            (perm.description ? `   描述: ${perm.description}\n` : '')
                          ).join('\n') + '\n'
                        : '❌ 未找到权限信息\n\n'
                      ) +
                      
                      `🔍 权限分析建议:\n` +
                      `• 关注敏感权限 (CAMERA, LOCATION, CONTACTS等)\n` +
                      `• 检查是否有过度申请权限\n` +
                      `• 使用 adb_start_app + adb_shell_command 进行运行时验证`
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ AAPT权限分析失败:\n${error.message}\n\n` +
                      `请确认AAPT工具可用并且APK文件有效。`
              },
            ],
          };
        }
      }

      case 'aapt_analyze_apk': {
        const { apk_path, auto_pull = true, include_resources = false, xml_trees = ['AndroidManifest.xml'] } = args as {
          apk_path: string;
          auto_pull?: boolean;
          include_resources?: boolean;
          xml_trees?: string[];
        };

        try {
          console.log(`[MCP] 开始AAPT完整APK分析: ${apk_path}`);
          
          const localApkPath = await handleAPKPath(apk_path, auto_pull);
          
          const analysis = await aaptManager.analyzeAPK(localApkPath, {
            includeBadging: true,
            includePermissions: true,
            includeResources: include_resources,
            includeXmlTrees: xml_trees
          });

          if (!analysis.success) {
            throw new Error(analysis.error || '分析失败');
          }

          const badging = analysis.badging;
          const permissions = analysis.permissions;
          
          return {
            content: [
              {
                type: 'text',
                text: `📊 APK 完整分析报告\n\n` +
                      `📦 应用基本信息:\n` +
                      `• 包名: ${badging?.packageName || '未知'}\n` +
                      `• 应用名: ${badging?.applicationLabel || '未知'}\n` +
                      `• 版本: ${badging?.versionName || '未知'} (${badging?.versionCode || '未知'})\n` +
                      `• 可调试: ${badging?.applicationDebugable ? '✅ 是' : '❌ 否'}\n\n` +
                      
                      `🎯 SDK和平台:\n` +
                      `• 最小SDK: API ${badging?.minSdkVersion || '未知'}\n` +
                      `• 目标SDK: API ${badging?.targetSdkVersion || '未知'}\n` +
                      `• 编译SDK: ${badging?.compileSdkVersion || '未知'}\n` +
                      `• 平台版本: ${badging?.platformBuildVersionName || '未知'}\n\n` +
                      
                      `🔐 权限和安全:\n` +
                      `• 申请权限: ${permissions?.length || 0} 个\n` +
                      `• 危险权限: ${countDangerousPermissions(badging?.usesPermissions || [])} 个\n` +
                      `• 特殊权限: ${countSpecialPermissions(badging?.usesPermissions || [])} 个\n\n` +
                      
                      `🛠️ 技术特性:\n` +
                      `• 原生代码: ${badging?.nativeCode?.join(', ') || '无'}\n` +
                      `• 支持架构: ${badging?.nativeCode?.length || 0} 种\n` +
                      `• 使用库: ${badging?.usesLibrary?.length || 0} 个\n` +
                      `• 硬件特性: ${badging?.usesFeatures?.length || 0} 个\n\n` +
                      
                      (analysis.xmlTrees && Object.keys(analysis.xmlTrees).length > 0
                        ? `📄 XML文件分析:\n` +
                          Object.keys(analysis.xmlTrees).map(xmlFile => `• ${xmlFile}: 已分析`).join('\n') + '\n\n'
                        : ''
                      ) +
                      
                      `🔍 安全评估:\n` +
                      `${generateSecurityAssessment(badging, permissions || [])}\n\n` +
                      
                      `🎯 后续分析建议:\n` +
                      `• 使用 adb_start_app 启动应用\n` +
                      `• 使用 adb_screenshot 记录关键页面状态\n` +
                      `• 使用 jadx_decompile_apk 深入代码分析\n` +
                      `• 关注可调试应用的安全风险`
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ APK完整分析失败:\n${error.message}\n\n` +
                      `请确认AAPT工具可用并且APK文件有效。`
              },
            ],
          };
        }
      }

      case 'aapt_dump_xmltree': {
        const { apk_path, xml_file = 'AndroidManifest.xml', auto_pull = true } = args as {
          apk_path: string;
          xml_file?: string;
          auto_pull?: boolean;
        };

        try {
          console.log(`[MCP] 开始AAPT XML分析: ${xml_file}`);
          
          const localApkPath = await handleAPKPath(apk_path, auto_pull);
          const xmlTree = await aaptManager.dumpXmlTree(localApkPath, xml_file);
          
          return {
            content: [
              {
                type: 'text',
                text: `📄 XML文件结构分析: ${xml_file}\n\n` +
                      `📁 APK路径: ${apk_path}\n\n` +
                      `🌳 XML树结构:\n` +
                      `\`\`\`\n${xmlTree}\n\`\`\`\n\n` +
                      
                      `💡 分析提示:\n` +
                      `• 注意应用组件的导出状态 (android:exported)\n` +
                      `• 检查Intent过滤器的安全配置\n` +
                      `• 关注权限和安全相关设置\n` +
                      `• 查看网络安全配置 (network_security_config)`
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ XML分析失败:\n${error.message}\n\n` +
                      `可能的原因:\n` +
                      `• XML文件 "${xml_file}" 在APK中不存在\n` +
                      `• APK文件损坏或格式不正确\n` +
                      `• AAPT工具版本不兼容\n\n` +
                      `常见XML文件:\n` +
                      `• AndroidManifest.xml\n` +
                      `• res/xml/network_security_config.xml\n` +
                      `• res/xml/provider_paths.xml`
              },
            ],
          };
        }
      }

      // === 文件工具处理 ===
      case 'file_sha256': {
        const { file_path, auto_pull = true, device_id } = args as {
          file_path: string;
          auto_pull?: boolean;
          device_id?: string;
        };

        try {
          console.log(`[MCP] 计算文件SHA256: ${file_path}`);
          
          let localFilePath = file_path;
          let isFromDevice = false;

          // 检查是否为设备路径
          if ((file_path.startsWith('/data/') || file_path.startsWith('/system/') || file_path.startsWith('/sdcard/')) && auto_pull) {
            console.log(`[MCP] 检测到设备路径，准备从设备拉取文件`);
            
            try {
              // 使用ADB拉取文件到临时位置
              const pullResult = await adbManager.pullFile(file_path, './', device_id);
              if (pullResult.success && pullResult.localPath) {
                localFilePath = pullResult.localPath;
                isFromDevice = true;
                console.log(`[MCP] 文件已从设备拉取到: ${localFilePath}`);
              } else {
                throw new Error('无法从设备拉取文件');
              }
            } catch (pullError) {
              return {
                content: [
                  {
                    type: 'text',
                    text: `❌ 从设备拉取文件失败:\n${pullError}\n\n` +
                          `💡 可能的原因:\n` +
                          `• 文件不存在或无权限访问\n` +
                          `• ADB连接异常\n` +
                          `• 设备存储空间不足\n\n` +
                          `🔧 解决建议:\n` +
                          `• 检查文件路径是否正确\n` +
                          `• 使用 adb_list_devices 确认设备连接\n` +
                          `• 尝试使用 adb shell ls "${file_path}" 验证文件存在`
                  },
                ],
              };
            }
          }

          // 检查本地文件是否存在
          if (!existsSync(localFilePath)) {
            return {
              content: [
                {
                  type: 'text',
                  text: `❌ 文件不存在: ${localFilePath}\n\n` +
                        `💡 请确认文件路径是否正确`
                },
              ],
            };
          }

          // 获取文件信息
          const fileStats = statSync(localFilePath);
          const fileSize = fileStats.size;
          const fileName = basename(localFilePath);

          // 计算SHA256哈希值
          const fileBuffer = readFileSync(localFilePath);
          const hash = createHash('sha256');
          hash.update(fileBuffer);
          const sha256 = hash.digest('hex');

          // 格式化文件大小
          const formatFileSize = (bytes: number): string => {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
          };

          return {
            content: [
              {
                type: 'text',
                text: `🔐 文件SHA256哈希计算结果\n\n` +
                      `📁 文件信息:\n` +
                      `• 文件名: ${fileName}\n` +
                      `• 原始路径: ${file_path}\n` +
                      (isFromDevice ? `• 本地路径: ${localFilePath}\n` : '') +
                      `• 文件大小: ${formatFileSize(fileSize)}\n` +
                      `• 修改时间: ${fileStats.mtime.toISOString()}\n\n` +
                      
                      `🔑 SHA256哈希值:\n` +
                      `\`${sha256}\`\n\n` +
                      
                      `📋 用途说明:\n` +
                      `• 文件完整性验证\n` +
                      `• 恶意软件识别和分析\n` +
                      `• 文件指纹比对\n` +
                      `• 版本变更检测\n\n` +
                      
                      `💡 使用建议:\n` +
                      `• 将此哈希值保存用于后续比对\n` +
                      `• 可在VirusTotal等平台查询威胁情报\n` +
                      `• 用于安全分析报告的文件标识`
              },
            ],
          };

        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ SHA256计算失败:\n${error.message}\n\n` +
                      `💡 可能的原因:\n` +
                      `• 文件路径不正确\n` +
                      `• 文件权限不足\n` +
                      `• 文件正在被其他程序使用\n` +
                      `• 磁盘I/O错误\n\n` +
                      `🔧 解决建议:\n` +
                      `• 检查文件是否存在\n` +
                      `• 确认文件访问权限\n` +
                      `• 重试操作`
              },
            ],
          };
        }
      }

      // === 静态安全分析工具处理 ===
      case 'static_scan_secrets': {
        const { target_path, pattern_type = 'all' } = args as {
          target_path: string;
          pattern_type?: string;
        };

        try {
          console.log(`[MCP] 开始扫描硬编码敏感信息: ${target_path}`);
          
          const sessionId = `static-${Date.now()}`;
          const analyzer = new StaticAnalyzer(sessionId);
          const findings = analyzer.scanHardcodedSecrets(target_path, pattern_type);

          const severityCounts = findings.reduce((acc, finding) => {
            acc[finding.severity] = (acc[finding.severity] || 0) + 1;
            return acc;
          }, {} as Record<string, number>);

          let resultText = `🔍 硬编码敏感信息扫描结果\n\n`;
          resultText += `📊 扫描统计:\n`;
          resultText += `• 扫描目标: ${target_path}\n`;
          resultText += `• 扫描模式: ${pattern_type}\n`;
          resultText += `• 发现问题: ${findings.length}个\n`;
          
          if (findings.length > 0) {
            resultText += `• 严重程度分布:\n`;
            ['critical', 'high', 'medium', 'low', 'info'].forEach(severity => {
              const count = severityCounts[severity] || 0;
              if (count > 0) {
                const emoji = severity === 'critical' ? '🔴' : 
                             severity === 'high' ? '🟠' : 
                             severity === 'medium' ? '🟡' : '🔵';
                resultText += `  ${emoji} ${severity}: ${count}个\n`;
              }
            });
          }

          if (findings.length > 0) {
            resultText += `\n📋 详细发现:\n\n`;
            findings.slice(0, 20).forEach((finding, index) => {
              const emoji = finding.severity === 'critical' ? '🚨' : 
                           finding.severity === 'high' ? '⚠️' : 
                           finding.severity === 'medium' ? '⚡' : '💡';
              
              resultText += `${emoji} **${finding.title}**\n`;
              resultText += `   文件: ${finding.file}`;
              if (finding.line) resultText += `:${finding.line}`;
              resultText += `\n`;
              if (finding.code) {
                resultText += `   代码: \`${finding.code}\`\n`;
              }
              resultText += `   描述: ${finding.description}\n`;
              resultText += `   建议: ${finding.recommendation}\n\n`;
            });

            if (findings.length > 20) {
              resultText += `⚠️ 还有 ${findings.length - 20} 个发现未显示，建议导出完整报告\n\n`;
            }
          } else {
            resultText += `\n✅ 未发现硬编码敏感信息，安全状态良好！\n\n`;
          }

          resultText += `💡 安全建议:\n`;
          resultText += `• 使用环境变量存储敏感配置\n`;
          resultText += `• 采用配置文件管理密钥\n`;
          resultText += `• 实施密钥管理最佳实践\n`;
          resultText += `• 定期进行安全代码审计`;

          return {
            content: [{ type: 'text', text: resultText }],
          };

        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ 硬编码敏感信息扫描失败:\n${error.message}\n\n` +
                      `💡 可能的原因:\n` +
                      `• 目标路径不存在或无访问权限\n` +
                      `• 目标不是有效的代码目录\n` +
                      `• 文件读取权限不足\n\n` +
                      `🔧 解决建议:\n` +
                      `• 检查路径是否正确\n` +
                      `• 确认已有足够权限\n` +
                      `• 先使用jadx_decompile_apk反编译APK`
              },
            ],
          };
        }
      }

      case 'static_scan_debug_leaks': {
        const { target_path } = args as { target_path: string };

        try {
          console.log(`[MCP] 开始扫描调试信息泄露: ${target_path}`);
          
          const sessionId = `static-${Date.now()}`;
          const analyzer = new StaticAnalyzer(sessionId);
          const findings = analyzer.scanDebugInfoLeakage(target_path);

          const severityCounts = findings.reduce((acc, finding) => {
            acc[finding.severity] = (acc[finding.severity] || 0) + 1;
            return acc;
          }, {} as Record<string, number>);

          let resultText = `🐛 调试信息泄露扫描结果\n\n`;
          resultText += `📊 扫描统计:\n`;
          resultText += `• 扫描目标: ${target_path}\n`;
          resultText += `• 发现问题: ${findings.length}个\n`;
          
          if (findings.length > 0) {
            resultText += `• 严重程度分布:\n`;
            ['critical', 'high', 'medium', 'low', 'info'].forEach(severity => {
              const count = severityCounts[severity] || 0;
              if (count > 0) {
                const emoji = severity === 'critical' ? '🔴' : 
                             severity === 'high' ? '🟠' : 
                             severity === 'medium' ? '🟡' : '🔵';
                resultText += `  ${emoji} ${severity}: ${count}个\n`;
              }
            });
          }

          if (findings.length > 0) {
            resultText += `\n📋 详细发现:\n\n`;
            findings.slice(0, 15).forEach((finding) => {
              const emoji = finding.severity === 'high' ? '⚠️' : 
                           finding.severity === 'medium' ? '⚡' : '💡';
              
              resultText += `${emoji} **${finding.title}**\n`;
              resultText += `   文件: ${finding.file}`;
              if (finding.line) resultText += `:${finding.line}`;
              resultText += `\n`;
              if (finding.code) {
                resultText += `   代码: \`${finding.code}\`\n`;
              }
              resultText += `   描述: ${finding.description}\n`;
              resultText += `   建议: ${finding.recommendation}\n\n`;
            });

            if (findings.length > 15) {
              resultText += `⚠️ 还有 ${findings.length - 15} 个发现未显示\n\n`;
            }
          } else {
            resultText += `\n✅ 未发现调试信息泄露问题，代码清理良好！\n\n`;
          }

          resultText += `🛡️ 安全建议:\n`;
          resultText += `• 生产版本移除所有调试日志\n`;
          resultText += `• 使用可控制的日志级别\n`;
          resultText += `• 避免在日志中输出敏感信息\n`;
          resultText += `• 定期清理代码注释和调试代码`;

          return {
            content: [{ type: 'text', text: resultText }],
          };

        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ 调试信息泄露扫描失败:\n${error.message}`
              },
            ],
          };
        }
      }

      case 'static_scan_weak_crypto': {
        const { target_path } = args as { target_path: string };

        try {
          console.log(`[MCP] 开始扫描弱加密算法: ${target_path}`);
          
          const sessionId = `static-${Date.now()}`;
          const analyzer = new StaticAnalyzer(sessionId);
          const findings = analyzer.scanWeakCrypto(target_path);

          const severityCounts = findings.reduce((acc, finding) => {
            acc[finding.severity] = (acc[finding.severity] || 0) + 1;
            return acc;
          }, {} as Record<string, number>);

          let resultText = `🔒 弱加密算法检测结果\n\n`;
          resultText += `📊 扫描统计:\n`;
          resultText += `• 扫描目标: ${target_path}\n`;
          resultText += `• 发现问题: ${findings.length}个\n`;
          
          if (findings.length > 0) {
            resultText += `• 严重程度分布:\n`;
            ['critical', 'high', 'medium', 'low'].forEach(severity => {
              const count = severityCounts[severity] || 0;
              if (count > 0) {
                const emoji = severity === 'critical' ? '🔴' : 
                             severity === 'high' ? '🟠' : 
                             severity === 'medium' ? '🟡' : '🔵';
                resultText += `  ${emoji} ${severity}: ${count}个\n`;
              }
            });
          }

          if (findings.length > 0) {
            resultText += `\n📋 详细发现:\n\n`;
            findings.slice(0, 10).forEach((finding) => {
              const emoji = finding.severity === 'critical' ? '🚨' : 
                           finding.severity === 'high' ? '⚠️' : '⚡';
              
              resultText += `${emoji} **${finding.title}**\n`;
              resultText += `   文件: ${finding.file}`;
              if (finding.line) resultText += `:${finding.line}`;
              resultText += `\n`;
              if (finding.code) {
                resultText += `   代码: \`${finding.code}\`\n`;
              }
              resultText += `   描述: ${finding.description}\n`;
              resultText += `   建议: ${finding.recommendation}\n\n`;
            });

            if (findings.length > 10) {
              resultText += `⚠️ 还有 ${findings.length - 10} 个发现未显示\n\n`;
            }
          } else {
            resultText += `\n✅ 未发现弱加密算法使用，加密实现安全！\n\n`;
          }

          resultText += `🔐 安全建议:\n`;
          resultText += `• 使用AES-256-GCM进行对称加密\n`;
          resultText += `• 使用RSA-2048或ECDSA进行非对称加密\n`;
          resultText += `• 使用SHA-256或更强的哈希算法\n`;
          resultText += `• 采用SecureRandom生成加密随机数`;

          return {
            content: [{ type: 'text', text: resultText }],
          };

        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ 弱加密算法扫描失败:\n${error.message}`
              },
            ],
          };
        }
      }

      case 'static_comprehensive_analysis': {
        const { target_path } = args as { target_path: string };

        try {
          console.log(`[MCP] 开始全面静态安全分析: ${target_path}`);
          
          const sessionId = `static-${Date.now()}`;
          const analyzer = new StaticAnalyzer(sessionId);
          const result = analyzer.performComprehensiveAnalysis(target_path);

          let resultText = `📊 全面静态安全分析报告\n\n`;
          
          // 执行摘要
          resultText += `🎯 执行摘要:\n`;
          resultText += `• 扫描目标: ${target_path}\n`;
          resultText += `• 扫描文件: ${result.scannedFiles}个\n`;
          resultText += `• 扫描耗时: ${result.scanTime}ms\n`;
          resultText += `• 发现问题: ${result.summary.totalFindings}个\n\n`;

          // 风险分布
          resultText += `📈 风险分布:\n`;
          if (result.summary.critical > 0) resultText += `🔴 严重: ${result.summary.critical}个\n`;
          if (result.summary.high > 0) resultText += `🟠 高危: ${result.summary.high}个\n`;
          if (result.summary.medium > 0) resultText += `🟡 中危: ${result.summary.medium}个\n`;
          if (result.summary.low > 0) resultText += `🔵 低危: ${result.summary.low}个\n`;
          if (result.summary.info > 0) resultText += `ℹ️ 信息: ${result.summary.info}个\n`;

          // 风险评级
          let riskLevel = '🟢 低风险';
          if (result.summary.critical > 0) riskLevel = '🔴 极高风险';
          else if (result.summary.high > 3) riskLevel = '🟠 高风险';
          else if (result.summary.high > 0 || result.summary.medium > 5) riskLevel = '🟡 中等风险';
          
          resultText += `\n🎯 总体风险评级: ${riskLevel}\n\n`;

          // 分类统计
          const typeGroups = result.findings.reduce((acc, finding) => {
            if (!acc[finding.type]) acc[finding.type] = [];
            acc[finding.type].push(finding);
            return acc;
          }, {} as Record<string, any[]>);

          resultText += `📋 问题分类统计:\n`;
          Object.entries(typeGroups).forEach(([type, findings]) => {
            const typeNames: Record<string, string> = {
              'hardcoded_secret': '🔑 硬编码敏感信息',
              'debug_leak': '🐛 调试信息泄露', 
              'weak_crypto': '🔒 弱加密算法'
            };
            resultText += `• ${typeNames[type] || type}: ${findings.length}个\n`;
          });

          // 关键发现（仅显示严重和高危）
          const criticalFindings = result.findings.filter(f => f.severity === 'critical' || f.severity === 'high');
          if (criticalFindings.length > 0) {
            resultText += `\n🚨 关键安全问题:\n\n`;
            criticalFindings.slice(0, 8).forEach((finding, index) => {
              const emoji = finding.severity === 'critical' ? '🚨' : '⚠️';
              resultText += `${emoji} **${finding.title}**\n`;
              resultText += `   文件: ${finding.file}`;
              if (finding.line) resultText += `:${finding.line}`;
              resultText += `\n`;
              if (finding.code) {
                resultText += `   代码: \`${finding.code.substring(0, 80)}${finding.code.length > 80 ? '...' : ''}\`\n`;
              }
              resultText += `   建议: ${finding.recommendation}\n\n`;
            });

            if (criticalFindings.length > 8) {
              resultText += `⚠️ 还有 ${criticalFindings.length - 8} 个关键问题未显示\n\n`;
            }
          }

          // 安全建议
          resultText += `🛡️ 安全加固建议:\n`;
          if (result.summary.critical > 0 || result.summary.high > 0) {
            resultText += `• 🔥 立即修复所有严重和高危漏洞\n`;
            resultText += `• 🔑 建立密钥管理体系，杜绝硬编码敏感信息\n`;
            resultText += `• 🔒 升级加密算法到最新安全标准\n`;
          }
          resultText += `• 📝 建立代码安全审计流程\n`;
          resultText += `• 🔍 集成静态代码安全扫描到CI/CD\n`;
          resultText += `• 📚 加强开发人员安全意识培训\n`;
          
          resultText += `\n📄 报告生成时间: ${new Date().toISOString()}`;

          return {
            content: [{ type: 'text', text: resultText }],
          };

        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ 全面静态安全分析失败:\n${error.message}`
              },
            ],
          };
        }
      }

      // === JADX 反编译工具处理 ===
      case 'jadx_decompile_apk': {
        const { 
          apk_path, 
          output_dir, 
          auto_pull = true, 
          show_bad_code = false, 
          deobfuscation = false, 
          threads_count, 
          verbose = false 
        } = args as {
          apk_path: string;
          output_dir?: string;
          auto_pull?: boolean;
          show_bad_code?: boolean;
          deobfuscation?: boolean;
          threads_count?: number;
          verbose?: boolean;
        };

        try {
          console.log(`[MCP] 开始JADX反编译APK: ${apk_path}`);
          
          // 处理APK路径 - 如果是设备路径则先拉取
          const localApkPath = await handleAPKPath(apk_path, auto_pull);
          
          // 执行反编译
          const result = await jadxManager.decompileAPK(localApkPath, {
            outputDir: output_dir,
            showBadCode: show_bad_code,
            deobfuscation: deobfuscation,
            threadsCount: threads_count,
            verbose: verbose
          });

          if (result.success) {
            return {
              content: [
                {
                  type: 'text',
                  text: `✅ APK反编译成功！\n\n` +
                        `📦 APK文件: ${apk_path}\n` +
                        `📁 输出目录: ${result.outputPath}\n` +
                        `⏱️  耗时: ${result.duration}ms\n\n` +
                        
                        `📊 反编译统计:\n` +
                        `• Java文件: ${result.summary?.javaFiles || 0} 个\n` +
                        `• 资源文件: ${result.summary?.resourceFiles || 0} 个\n` +
                        `• 总大小: ${result.summary?.totalSize || '未知'}\n` +
                        `• AndroidManifest: ${result.summary?.manifestFound ? '✅ 已发现' : '❌ 未找到'}\n\n` +
                        
                        `🔍 后续分析建议:\n` +
                        `• 使用 jadx_get_info 获取详细信息\n` +
                        `• 检查sources目录中的Java代码\n` +
                        `• 分析AndroidManifest.xml文件\n` +
                        `• 查看resources目录中的资源文件\n\n` +
                        
                        `📂 目录结构:\n` +
                        `• ${result.outputPath}/sources/ - Java源代码\n` +
                        `• ${result.outputPath}/resources/ - 资源文件\n` +
                        `• ${result.outputPath}/AndroidManifest.xml - 清单文件`
                },
              ],
            };
          } else {
            throw new Error(result.error || '反编译失败');
          }

        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ JADX反编译失败:\n${error.message}\n\n` +
                      `💡 可能的原因:\n` +
                      `• JADX工具未安装或不在PATH中\n` +
                      `• APK文件损坏或格式不正确\n` +
                      `• 磁盘空间不足\n` +
                      `• 权限不足无法写入输出目录\n\n` +
                      `🔧 解决建议:\n` +
                      `• 确保JADX已正确安装\n` +
                      `• 使用 jadx_validate_apk 验证APK文件\n` +
                      `• 检查输出目录权限: ${output_dir || 'decompiled/'}\n` +
                      `• 尝试使用不同的反编译选项`
              },
            ],
          };
        }
      }

      case 'jadx_get_info': {
        const { output_dir } = args as {
          output_dir: string;
        };

        try {
          console.log(`[MCP] 获取反编译信息: ${output_dir}`);
          
          const info = await jadxManager.getDecompiledInfo(output_dir);
          
          return {
            content: [
              {
                type: 'text',
                text: `📊 反编译项目信息\n\n` +
                      `📁 项目路径: ${info.outputPath}\n\n` +
                      
                      `📈 文件统计:\n` +
                      `• Java文件: ${info.stats.javaFiles} 个\n` +
                      `• Smali文件: ${info.stats.smaliFiles} 个\n` +
                      `• 资源文件: ${info.stats.resourceFiles} 个\n` +
                      `• 总文件数: ${info.stats.totalFiles} 个\n` +
                      `• 目录数: ${info.stats.directories} 个\n\n` +
                      
                      `📄 重要文件:\n` +
                      `• AndroidManifest: ${info.manifestExists ? '✅ 存在' : '❌ 缺失'}\n` +
                      `• 源码目录: ${info.sourcesPath}\n` +
                      `• 资源目录: ${info.resourcesPath}\n\n` +
                      
                      (info.mainPackages.length > 0 
                        ? `📦 主要包结构:\n${info.mainPackages.map((pkg: string) => `• ${pkg}`).join('\n')}\n\n`
                        : ''
                      ) +
                      
                      `🔍 分析建议:\n` +
                      `• 重点关注主Application类的初始化逻辑\n` +
                      `• 检查网络请求和数据存储相关代码\n` +
                      `• 分析加密/解密和签名验证逻辑\n` +
                      `• 查看资源文件中的配置信息`
              },
            ],
          };

        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ 获取反编译信息失败:\n${error.message}\n\n` +
                      `可能的原因:\n` +
                      `• 输出目录不存在或无权限访问\n` +
                      `• 反编译未完成或已被清理\n` +
                      `• 目录结构异常\n\n` +
                      `请确认目录路径: ${output_dir}`
              },
            ],
          };
        }
      }

      case 'jadx_validate_apk': {
        const { apk_path } = args as {
          apk_path: string;
        };

        try {
          console.log(`[MCP] 验证APK文件: ${apk_path}`);
          
          const validation = await jadxManager.validateAPK(apk_path);
          
          if (validation.valid) {
            return {
              content: [
                {
                  type: 'text',
                  text: `✅ APK文件验证通过\n\n` +
                        `📁 文件路径: ${apk_path}\n` +
                        `📦 文件格式: 有效的APK文件\n\n` +
                        `🎯 后续操作建议:\n` +
                        `• 使用 jadx_decompile_apk 进行反编译\n` +
                        `• 使用 aapt_dump_badging 分析APK基本信息\n` +
                        `• 使用 aapt_dump_permissions 分析权限配置`
                },
              ],
            };
          } else {
            return {
              content: [
                {
                  type: 'text',
                  text: `❌ APK文件验证失败\n\n` +
                        `📁 文件路径: ${apk_path}\n` +
                        `❌ 错误原因: ${validation.error}\n\n` +
                        `💡 解决建议:\n` +
                        `• 确认文件路径正确\n` +
                        `• 检查文件是否完整下载\n` +
                        `• 确认文件确实是APK格式\n` +
                        `• 检查文件权限和访问权限`
                },
              ],
            };
          }

        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ APK验证过程出错:\n${error.message}\n\n` +
                      `请检查文件路径和权限: ${apk_path}`
              },
            ],
          };
        }
      }

      default:
        throw new McpError(ErrorCode.MethodNotFound, `未知工具: ${name}`);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : '未知错误';
    throw new McpError(ErrorCode.InternalError, `执行失败: ${errorMessage}`);
  }
});

async function main() {
  const runtimeDependencies = await checkRuntimeDependencies();
  printDependencyGuidance(runtimeDependencies);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.log('[MCP] mobile-app-testing-mcp 已启动，等待客户端连接...');
  
  process.on('SIGINT', async () => {
    process.exit(0);
  });
}

main().catch(console.error);
