#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { FridaManager } from './frida-manager.js';
import { SecurityManager } from './security.js';
import { globalADBManager } from './adb-manager.js';
import { globalWorkflowManager } from './workflow-manager.js';
import { globalGadgetManager } from './gadget-manager.js';
import { globalAAPTManager } from './aapt-manager.js';
import { globalJADXManager } from './jadx-manager.js';
import { StaticAnalyzer } from './static-analyzer.js';
import { createHash } from 'crypto';
import { existsSync, statSync, readFileSync } from 'fs';
import { basename } from 'path';

const fridaManager = new FridaManager();
const securityManager = new SecurityManager();
const adbManager = globalADBManager;
const workflowManager = globalWorkflowManager;
const aaptManager = globalAAPTManager;
const jadxManager = globalJADXManager;
const gadgetManager = globalGadgetManager;

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
      {
        name: 'frida_attach',
        description: '🔗 [阶段二/调试连接] 附加到指定移动应用进程进行动态分析',
        inputSchema: {
          type: 'object',
          properties: {
            target: {
              type: 'string',
              description: '目标应用包名、PID或进程名（如com.example.app）',
            },
            spawn: {
              type: 'boolean',
              description: '是否启动新应用实例（默认false，附加到现有进程）',
              default: false,
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选，默认选择USB设备）',
            },
          },
          required: ['target'],
        },
      },
      {
        name: 'frida_inject_script',
        description: '向已附加的进程注入JavaScript脚本',
        inputSchema: {
          type: 'object',
          properties: {
            script: {
              type: 'string',
              description: '要注入的JavaScript脚本代码',
            },
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认使用当前活动会话）',
            },
          },
          required: ['script'],
        },
      },
      {
        name: 'frida_detach',
        description: '从进程分离',
        inputSchema: {
          type: 'object',
          properties: {
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认分离所有会话）',
            },
          },
        },
      },
      {
        name: 'frida_list_processes',
        description: '列出设备中的所有进程（优先移动设备）',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: '进程/应用名称过滤条件（可选）',
            },
            device_id: {
              type: 'string',
              description: '指定设备ID（可选，默认选择USB设备）',
            },
          },
        },
      },
      {
        name: 'frida_list_devices',
        description: '枚举所有可用设备（本地/USB/远程）',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'frida_list_applications',
        description: '列出设备上的所有应用（移动应用）',
        inputSchema: {
          type: 'object',
          properties: {
            device_id: {
              type: 'string',
              description: '指定设备ID（可选，默认选择USB设备）',
            },
          },
        },
      },
      {
        name: 'frida_memory_search',
        description: '在目标进程内存中搜索指定数据',
        inputSchema: {
          type: 'object',
          properties: {
            pattern: {
              type: 'string',
              description: '搜索模式（十六进制字符串，如 "41 42 43" 或字符串）',
            },
            type: {
              type: 'string',
              enum: ['hex', 'string', 'utf8', 'utf16'],
              description: '搜索类型（hex=十六进制，string=ASCII字符串，utf8/utf16=Unicode字符串）',
              default: 'string',
            },
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认使用当前活动会话）',
            },
          },
          required: ['pattern'],
        },
      },
      {
        name: 'frida_memory_write',
        description: '修改目标进程内存中的数据',
        inputSchema: {
          type: 'object',
          properties: {
            address: {
              type: 'string',
              description: '内存地址（十六进制，如 0x12345678）',
            },
            data: {
              type: 'string',
              description: '要写入的数据（十六进制字符串，如 "41 42 43"）',
            },
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认使用当前活动会话）',
            },
          },
          required: ['address', 'data'],
        },
      },
      {
        name: 'frida_enumerate_classes',
        description: '枚举目标应用的所有类（Java类或ObjC类）',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: '类名过滤条件（可选）',
            },
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认使用当前活动会话）',
            },
          },
        },
      },
      {
        name: 'frida_enumerate_methods',
        description: '枚举指定类的所有方法',
        inputSchema: {
          type: 'object',
          properties: {
            class_name: {
              type: 'string',
              description: '类名（如 java.lang.String 或 NSString）',
            },
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认使用当前活动会话）',
            },
          },
          required: ['class_name'],
        },
      },
      {
        name: 'frida_find_function',
        description: '查找函数地址和详细信息',
        inputSchema: {
          type: 'object',
          properties: {
            function_name: {
              type: 'string',
              description: '函数名或方法名',
            },
            module_name: {
              type: 'string',
              description: '模块名（可选，如 libc、libssl 等）',
            },
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认使用当前活动会话）',
            },
          },
          required: ['function_name'],
        },
      },
      {
        name: 'frida_batch_hook',
        description: '批量Hook多个方法或函数',
        inputSchema: {
          type: 'object',
          properties: {
            targets: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  class_name: { type: 'string' },
                  method_name: { type: 'string' },
                  hook_type: { 
                    type: 'string',
                    enum: ['log', 'block', 'modify'],
                    default: 'log'
                  },
                },
                required: ['class_name', 'method_name'],
              },
              description: 'Hook目标列表，每个对象包含class_name和method_name',
            },
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认使用当前活动会话）',
            },
          },
          required: ['targets'],
        },
      },
      {
        name: 'frida_save_logs',
        description: '保存Hook结果到文件',
        inputSchema: {
          type: 'object',
          properties: {
            filename: {
              type: 'string',
              description: '保存的文件名（可选，默认使用时间戳）',
            },
            output_dir: {
              type: 'string',
              description: '输出目录绝对路径（可选，默认使用项目logs目录）',
            },
            format: {
              type: 'string',
              enum: ['json', 'txt', 'csv'],
              description: '保存格式',
              default: 'json',
            },
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认使用当前活动会话）',
            },
          },
        },
      },
      {
        name: 'frida_get_app_info',
        description: '获取应用详细信息（包名、权限、版本等）',
        inputSchema: {
          type: 'object',
          properties: {
            package_name: {
              type: 'string',
              description: '应用包名',
            },
            device_id: {
              type: 'string',
              description: '设备ID（可选，默认使用USB设备）',
            },
          },
          required: ['package_name'],
        },
      },
      {
        name: 'frida_auto_recovery',
        description: '启用自动崩溃恢复机制',
        inputSchema: {
          type: 'object',
          properties: {
            enable: {
              type: 'boolean',
              description: '是否启用自动恢复',
              default: true,
            },
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认使用当前活动会话）',
            },
          },
        },
      },
      {
        name: 'frida_connection_status',
        description: '获取所有连接状态和健康信息',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'frida_force_reconnect',
        description: '强制重新连接到断开的会话',
        inputSchema: {
          type: 'object',
          properties: {
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认使用当前活动会话）',
            },
          },
        },
      },
      {
        name: 'frida_diagnose_environment',
        description: '🔧 [环境诊断] 全面检测移动测试环境 - 设备连接、Frida服务、权限状态',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'frida_realtime_logs',
        description: '启用/停止实时日志监听',
        inputSchema: {
          type: 'object',
          properties: {
            action: {
              type: 'string',
              enum: ['start', 'stop', 'tail', 'stats'],
              description: 'start=启动监听, stop=停止监听, tail=获取最近日志, stats=获取统计',
            },
            session_id: {
              type: 'string',
              description: '会话ID（可选，默认使用当前活动会话）',
            },
            lines: {
              type: 'number',
              description: '获取日志行数（仅tail模式，默认50）',
              default: 50,
            },
          },
          required: ['action'],
        },
      },

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
              description: '工具名称（如adb_tap、frida_batch_hook）',
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
      
      // ===== Frida Gadget 自动部署工具 =====
      {
        name: 'frida_deploy_gadget',
        description: '🚀 [高级功能] 自动部署Frida Gadget到目标应用 - 解决非root环境下的附加问题',
        inputSchema: {
          type: 'object',
          properties: {
            package_name: {
              type: 'string',
              description: '目标应用包名（如com.example.app）',
            },
            target_arch: {
              type: 'string',
              enum: ['arm64', 'arm', 'x86_64', 'x86'],
              description: '目标架构（默认arm64）',
              default: 'arm64',
            },
            deployment_strategy: {
              type: 'string',
              enum: ['replace_lib', 'add_lib', 'manifest_modify'],
              description: '部署策略（replace_lib=替换现有库, add_lib=添加新库, manifest_modify=修改清单）',
              default: 'add_lib',
            },
            preserve_signature: {
              type: 'boolean',
              description: '是否保留原始签名（默认false，会重新签名）',
              default: false,
            },
          },
          required: ['package_name'],
        },
      },
      {
        name: 'frida_check_gadget_status',
        description: '📊 [状态检查] 检查应用的Frida Gadget部署状态',
        inputSchema: {
          type: 'object',
          properties: {
            package_name: {
              type: 'string',
              description: '要检查的应用包名',
            },
          },
          required: ['package_name'],
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
      case 'frida_attach': {
        const { target, spawn = false, device_id } = args as { 
          target: string; 
          spawn?: boolean; 
          device_id?: string;
        };
        
        const result = await fridaManager.attach(target, spawn, device_id);
        
        // 轻量级验证（移动应用测试不需要严格限制）
        securityManager.validateProcessAccess(result.process.name, result.process.pid);
        
        // 记录工具执行
        workflowManager.recordToolExecution('frida_attach', result);
        
        // 获取标准流程的下一步建议
        const suggestions = workflowManager.getSmartSuggestions();
        const nextSteps = suggestions.slice(0, 3).map(s => 
          `• ${s.tool} - ${s.reason}`
        ).join('\n');
        
        return {
          content: [
            {
              type: 'text',
              text: `✅ 成功附加到移动应用: ${result.process.name} (PID: ${result.process.pid})\n📱 会话ID: ${result.sessionId}\n\n🎯 【阶段二】标准下一步:\n${nextSteps}\n\n💡 关键提醒:\n• 现在可以注入Hook脚本进行监控\n• 建议先验证连接稳定性再注入脚本`,
            },
          ],
        };
      }

      case 'frida_inject_script': {
        const { script, session_id } = args as { script: string; session_id?: string };
        
        // 验证脚本安全性
        securityManager.validateScript(script);
        
        const result = await fridaManager.injectScript(script, session_id);
        return {
          content: [
            {
              type: 'text',
              text: `脚本注入成功\n脚本ID: ${result.scriptId}\n会话ID: ${result.sessionId}`,
            },
          ],
        };
      }

      case 'frida_detach': {
        const { session_id } = args as { session_id?: string };
        await fridaManager.detach(session_id);
        return {
          content: [
            {
              type: 'text',
              text: session_id ? `已从会话 ${session_id} 分离` : '已从所有会话分离',
            },
          ],
        };
      }

      case 'frida_list_processes': {
        const { filter, device_id } = args as { filter?: string; device_id?: string };
        const processes = await fridaManager.listProcesses(filter, device_id);
        const processText = processes
          .slice(0, 20) // 限制显示前20个
          .map(p => `📱 ${p.name} (PID: ${p.pid})`)
          .join('\n');
        return {
          content: [
            {
              type: 'text',
              text: `🔍 找到 ${processes.length} 个进程 ${filter ? `(包含 "${filter}")` : ''}:\n${processText}${processes.length > 20 ? '\n... (显示前20个)' : ''}`,
            },
          ],
        };
      }

      case 'frida_list_devices': {
        const devices = await fridaManager.enumerateDevices();
        const deviceText = devices
          .map(d => `📱 ${d.name} (${d.type}) - ID: ${d.id}`)
          .join('\n');
        return {
          content: [
            {
              type: 'text',
              text: `🔍 发现 ${devices.length} 个设备:\n${deviceText}`,
            },
          ],
        };
      }

      case 'frida_list_applications': {
        const { device_id } = args as { device_id?: string };
        const applications = await fridaManager.enumerateApplications(device_id);
        const appText = applications
          .slice(0, 15) // 限制显示前15个
          .map(app => `📦 ${app.name} (${app.identifier})`)
          .join('\n');
        return {
          content: [
            {
              type: 'text',
              text: `🔍 找到 ${applications.length} 个应用:\n${appText}${applications.length > 15 ? '\n... (显示前15个)' : ''}`,
            },
          ],
        };
      }

      case 'frida_memory_search': {
        const { pattern, type = 'string', session_id } = args as { 
          pattern: string; 
          type?: 'hex' | 'string' | 'utf8' | 'utf16';
          session_id?: string;
        };
        const result = await fridaManager.memorySearch(pattern, type, session_id);
        return {
          content: [
            {
              type: 'text',
              text: `🔍 内存搜索结果:\n找到 ${result.count} 个匹配项\n地址列表:\n${result.addresses.slice(0, 10).join('\n')}${result.count > 10 ? '\n... (显示前10个)' : ''}`,
            },
          ],
        };
      }

      case 'frida_memory_write': {
        const { address, data, session_id } = args as { 
          address: string; 
          data: string; 
          session_id?: string;
        };
        const result = await fridaManager.memoryWrite(address, data, session_id);
        return {
          content: [
            {
              type: 'text',
              text: result.success 
                ? `✅ 内存写入成功\n地址: ${result.address}\n写入字节数: ${result.bytesWritten}`
                : `❌ 内存写入失败\n地址: ${result.address}`,
            },
          ],
        };
      }

      case 'frida_enumerate_classes': {
        const { filter, session_id } = args as { filter?: string; session_id?: string };
        const classes = await fridaManager.enumerateClasses(filter, session_id);
        const classText = classes
          .map(c => `📦 ${c.name} (${c.methods} 方法)`)
          .join('\n');
        return {
          content: [
            {
              type: 'text',
              text: `🔍 找到 ${classes.length} 个类 ${filter ? `(包含 "${filter}")` : ''}:\n${classText}`,
            },
          ],
        };
      }

      case 'frida_enumerate_methods': {
        const { class_name, session_id } = args as { class_name: string; session_id?: string };
        const methods = await fridaManager.enumerateMethods(class_name, session_id);
        const methodText = methods
          .slice(0, 20)
          .map(m => `🔧 ${m.name}`)
          .join('\n');
        return {
          content: [
            {
              type: 'text',
              text: `🔍 类 ${class_name} 的方法 (${methods.length} 个):\n${methodText}${methods.length > 20 ? '\n... (显示前20个)' : ''}`,
            },
          ],
        };
      }

      case 'frida_find_function': {
        const { function_name, module_name, session_id } = args as { 
          function_name: string; 
          module_name?: string;
          session_id?: string;
        };
        const functions = await fridaManager.findFunction(function_name, module_name, session_id);
        const funcText = functions
          .map(f => `🎯 ${f.name} @ ${f.address} (${f.module})`)
          .join('\n');
        return {
          content: [
            {
              type: 'text',
              text: functions.length > 0 
                ? `🔍 找到 ${functions.length} 个函数:\n${funcText}`
                : `❌ 未找到函数: ${function_name}`,
            },
          ],
        };
      }

      case 'frida_batch_hook': {
        const { targets, session_id } = args as { 
          targets: Array<{class_name: string, method_name: string, hook_type: 'log' | 'block' | 'modify'}>;
          session_id?: string;
        };
        const result = await fridaManager.batchHook(targets, session_id);
        const detailText = result.details
          .map(d => `${d.status === 'success' ? '✅' : '❌'} ${d.target}`)
          .join('\n');
        return {
          content: [
            {
              type: 'text',
              text: `🎯 批量Hook结果:\n成功: ${result.success} 个\n失败: ${result.failed} 个\n\n详情:\n${detailText}`,
            },
          ],
        };
      }

      case 'frida_save_logs': {
        const { filename, output_dir, format = 'json', session_id } = args as { 
          filename?: string; 
          output_dir?: string;
          format?: 'json' | 'txt' | 'csv';
          session_id?: string;
        };
        const filePath = fridaManager.saveLogs(session_id || '', format, filename, output_dir);
        return {
          content: [
            {
              type: 'text',
              text: `💾 日志已保存到: ${filePath}`,
            },
          ],
        };
      }

      case 'frida_get_app_info': {
        const { package_name, device_id } = args as { 
          package_name: string; 
          device_id?: string;
        };
        const appInfo = await fridaManager.getApplicationInfo(package_name, device_id);
        return {
          content: [
            {
              type: 'text',
              text: `📱 应用信息:\n名称: ${appInfo.basic.name}\n包名: ${appInfo.basic.identifier}\nPID: ${appInfo.basic.pid || '未运行'}\n设备: ${appInfo.device}`,
            },
          ],
        };
      }

      case 'frida_auto_recovery': {
        const { enable = true, session_id } = args as { 
          enable?: boolean; 
          session_id?: string;
        };
        if (enable) {
          fridaManager.enableAutoRecovery(session_id);
        } else {
          fridaManager.disableAutoRecovery(session_id);
        }
        return {
          content: [
            {
              type: 'text',
              text: `🔄 自动崩溃恢复已${enable ? '启用' : '禁用'}`,
            },
          ],
        };
      }

      case 'frida_connection_status': {
        const connections = fridaManager.getConnectionStatuses();
        const statusText = connections.length > 0 
          ? connections
              .map(c => `🔗 ${c.processName} (${c.sessionId.substring(0, 8)})\n   状态: ${c.status}\n   重试: ${c.retryCount}/${5}\n   PID: ${c.pid || 'N/A'}\n   心跳: ${new Date(c.lastHeartbeat).toLocaleTimeString()}`)
              .join('\n\n')
          : '❌ 无活动连接';
        
        return {
          content: [
            {
              type: 'text',
              text: `📊 连接状态报告:\n\n${statusText}`,
            },
          ],
        };
      }

      case 'frida_force_reconnect': {
        const { session_id } = args as { session_id?: string };
        fridaManager.forceReconnection(session_id);
        return {
          content: [
            {
              type: 'text',
              text: `🔄 强制重连已启动 ${session_id ? `(会话: ${session_id.substring(0, 8)})` : '(当前会话)'}`,
            },
          ],
        };
      }

      case 'frida_diagnose_environment': {
        const diagnosis = await fridaManager.diagnoseEnvironment();
        
        const statusText = Object.entries(diagnosis.fridaServerStatus)
          .map(([deviceId, status]) => `  ${deviceId}: ${status}`)
          .join('\n');
        
        const recommendationsText = diagnosis.recommendations.length > 0 
          ? diagnosis.recommendations.map(rec => `• ${rec}`).join('\n\n')
          : '✅ 环境配置正常，无需额外操作';

        const capabilitiesText = Object.entries(diagnosis.deviceCapabilities)
          .map(([deviceId, cap]) => `  📱 ${cap.name} (${cap.type})`)
          .join('\n');

        return {
          content: [
            {
              type: 'text',
              text: `🔍 Frida 环境诊断报告:\n\n` +
                    `📊 设备状态:\n${statusText}\n\n` +
                    `📱 检测到的设备:\n${capabilitiesText}\n\n` +
                    `💡 配置建议:\n${recommendationsText}`,
            },
          ],
        };
      }

      case 'frida_realtime_logs': {
        const { action, session_id, lines = 50 } = args as { 
          action: 'start' | 'stop' | 'tail' | 'stats';
          session_id?: string;
          lines?: number;
        };

        switch (action) {
          case 'start':
            fridaManager.startRealtimeLogs(session_id);
            return {
              content: [
                {
                  type: 'text',
                  text: `📡 实时日志监听已启动 ${session_id ? `(会话: ${session_id.substring(0, 8)})` : '(当前会话)'}`,
                },
              ],
            };

          case 'stop':
            fridaManager.stopRealtimeLogs(session_id);
            return {
              content: [
                {
                  type: 'text',
                  text: `⏹️ 实时日志监听已停止 ${session_id ? `(会话: ${session_id.substring(0, 8)})` : '(当前会话)'}`,
                },
              ],
            };

          case 'tail':
            const logs = fridaManager.getTailLogs(session_id, lines);
            const logText = logs.length > 0 
              ? logs
                  .map(log => {
                    const time = new Date(log.timestamp).toLocaleTimeString();
                    return `[${time}] [${log.type.toUpperCase()}] ${JSON.stringify(log.data)}`;
                  })
                  .join('\n')
              : '📝 暂无日志';
            
            return {
              content: [
                {
                  type: 'text',
                  text: `📄 最近 ${lines} 条日志:\n\n${logText}`,
                },
              ],
            };

          case 'stats':
            const stats = fridaManager.getLogStats(session_id);
            if (stats) {
              const lastLogTime = stats.lastLogTime > 0 ? new Date(stats.lastLogTime).toLocaleString() : '从未';
              return {
                content: [
                  {
                    type: 'text',
                    text: `📊 日志统计:\n总计: ${stats.totalLogs}\n错误: ${stats.errorCount}\nHook: ${stats.hookCount}\n网络: ${stats.networkCount}\n最后日志: ${lastLogTime}`,
                  },
                ],
              };
            } else {
              return {
                content: [
                  {
                    type: 'text',
                    text: `❌ 无法获取日志统计`,
                  },
                ],
              };
            }

          default:
            throw new McpError(ErrorCode.InvalidParams, `未知的日志操作: ${action}`);
        }
      }

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

        const stepsText = template.steps.map((step, index) => 
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
                `**前置条件:**\n${template.prerequisites.map(p => `• ${p}`).join('\n')}\n\n` +
                `**预期输出:**\n${template.expectedOutputs.map(o => `• ${o}`).join('\n')}\n\n` +
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
                (help.recommended_before ? `**建议前置工具:**\n${help.recommended_before.map((t: string) => `• ${t}`).join('\n')}\n\n` : '') +
                (help.recommended_after ? `**建议后续工具:**\n${help.recommended_after.map((t: string) => `• ${t}`).join('\n')}\n\n` : '') +
                (help.tips ? `**使用技巧:**\n${help.tips.map((t: string) => `• ${t}`).join('\n')}\n\n` : '') +
                (help.warnings ? `**⚠️ 注意事项:**\n${help.warnings.map((w: string) => `• ${w}`).join('\n')}\n\n` : '') +
                (help.common_workflows ? `**常用工作流:**\n${help.common_workflows.map((w: string) => `• ${w}`).join('\n')}\n\n` : '') +
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

      // ===== Frida Gadget 自动部署工具处理 =====
      case 'frida_deploy_gadget': {
        const { package_name, target_arch = 'arm64', deployment_strategy = 'add_lib', preserve_signature = false } = args as {
          package_name: string;
          target_arch?: string;
          deployment_strategy?: string;
          preserve_signature?: boolean;
        };
        
        try {
          console.log(`[MCP] 开始部署Frida Gadget到 ${package_name}`);
          
          const result = await gadgetManager.deployGadget({
            packageName: package_name,
            targetArch: target_arch as any,
            deploymentStrategy: deployment_strategy as any,
            preserveSignature: preserve_signature,
          });
          
          if (result.success) {
            return {
              content: [
                {
                  type: 'text',
                  text: `🚀 Frida Gadget部署成功！\n\n` +
                        `📦 应用: ${package_name}\n` +
                        `🏗️ 架构: ${target_arch}\n` +
                        `⚙️ 策略: ${deployment_strategy}\n` +
                        `📁 APK路径: ${result.packagePath || '未知'}\n` +
                        `💾 备份路径: ${result.originalBackup || '未知'}\n\n` +
                        `✅ 现在可以使用 \`frida_attach\` 直接附加到应用，无需root权限！\n\n` +
                        `🎯 下一步建议:\n` +
                        `• 使用 adb_start_app 启动应用\n` +
                        `• 使用 frida_attach 附加到进程\n` +
                        `• 开始动态分析和Hook操作`
                },
              ],
            };
          } else {
            return {
              content: [
                {
                  type: 'text',
                  text: `❌ Frida Gadget部署失败\n\n` +
                        `错误信息: ${result.error}\n\n` +
                        `💡 可能的解决方案:\n` +
                        `• 确认应用已安装: adb_list_packages\n` +
                        `• 检查设备连接: adb_list_devices\n` +
                        `• 确认有足够的存储空间\n` +
                        `• 检查应用是否允许重新安装\n\n` +
                        `📝 如需帮助，请使用 frida_diagnose_environment`
                },
              ],
            };
          }
        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `💥 Gadget部署过程中出现异常:\n${error.message}\n\n` +
                      `🔧 故障排除:\n` +
                      `• 检查adb连接状态\n` +
                      `• 确认应用包名正确\n` +
                      `• 检查设备存储空间\n` +
                      `• 尝试手动启动应用后重试`
              },
            ],
          };
        }
      }

      case 'frida_check_gadget_status': {
        const { package_name } = args as { package_name: string };
        
        try {
          const hasGadget = await gadgetManager.checkGadgetStatus(package_name);
          
          return {
            content: [
              {
                type: 'text',
                text: `📊 Gadget状态检查: ${package_name}\n\n` +
                      `状态: ${hasGadget ? '✅ 已部署Gadget' : '❌ 未检测到Gadget'}\n\n` +
                      (hasGadget 
                        ? `🎉 应用已包含Frida Gadget，可以直接使用:\n` +
                          `• frida_attach ${package_name}\n` +
                          `• 无需root权限即可进行动态分析`
                        : `💡 建议操作:\n` +
                          `• 使用 frida_deploy_gadget 部署Gadget\n` +
                          `• 或确认应用正在运行并包含Gadget库`
                      )
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `❌ 无法检查Gadget状态: ${error.message}\n\n` +
                      `请确认:\n` +
                      `• 设备连接正常\n` +
                      `• 应用包名正确\n` +
                      `• 有必要的权限`
              },
            ],
          };
        }
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
                      `• 使用 frida_diagnose_environment 检查环境`
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
                      `• 使用 frida_attach 进行运行时权限分析`
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
                      `• 使用 frida_deploy_gadget 部署Gadget (如需动态分析)\n` +
                      `• 使用 adb_start_app 启动应用\n` +
                      `• 使用 frida_attach 进行Hook分析\n` +
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
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  process.on('SIGINT', async () => {
    await fridaManager.cleanup();
    process.exit(0);
  });
}

main().catch(console.error);