import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, extname } from 'path';
import { globalLogger } from './logger.js';

export interface SecurityFinding {
  type: 'hardcoded_secret' | 'debug_leak' | 'weak_crypto' | 'permission_issue' | 'sensitive_data';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  file: string;
  line?: number;
  code?: string;
  recommendation: string;
}

export interface StaticAnalysisResult {
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: SecurityFinding[];
  scanTime: number;
  scannedFiles: number;
}

type LiteralConstantKind = 'hex' | 'base64' | 'plain' | 'bytes';

interface LiteralConstantInfo {
  line: number;
  value: string;
  kind: LiteralConstantKind;
}

export class StaticAnalyzer {
  private sessionId: string;
  private scannedFiles: number = 0;
  
  constructor(sessionId: string) {
    this.sessionId = sessionId;
  }

  private log(type: string, data: any): void {
    globalLogger.addLog({
      type: 'info',
      sessionId: this.sessionId,
      data,
      source: `StaticAnalyzer.${type}`
    });
  }

  // 递归扫描目录中的所有代码文件
  private scanDirectory(dirPath: string): string[] {
    const files: string[] = [];
    const codeExtensions = ['.java', '.kt', '.xml', '.js', '.json', '.properties'];
    
    try {
      const items = readdirSync(dirPath);
      
      for (const item of items) {
        const itemPath = join(dirPath, item);
        const stat = statSync(itemPath);
        
        if (stat.isDirectory()) {
          // 跳过一些无关目录
          if (!['node_modules', '.git', 'build', 'gradle'].includes(item)) {
            files.push(...this.scanDirectory(itemPath));
          }
        } else if (stat.isFile()) {
          const ext = extname(item).toLowerCase();
          if (codeExtensions.includes(ext)) {
            files.push(itemPath);
          }
        }
      }
    } catch (error) {
      this.log('scanDirectory', { error: `无法扫描目录 ${dirPath}: ${error}` });
    }
    
    return files;
  }

  // 读取文件内容并按行分割
  private readFileLines(filePath: string): string[] {
    try {
      const content = readFileSync(filePath, 'utf-8');
      return content.split('\n');
    } catch (error) {
      this.log('readFileLines', { error: `无法读取文件 ${filePath}: ${error}` });
      return [];
    }
  }

  // 硬编码敏感信息扫描
  scanHardcodedSecrets(targetPath: string, patternType: string = 'all'): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    
    // 定义敏感信息模式
    const patterns = {
      api_keys: [
        { name: 'API密钥', pattern: /['"](sk_|pk_|key_|token_|secret_)[a-zA-Z0-9_-]{20,}['"]/, severity: 'critical' as const },
        { name: '访问令牌', pattern: /['"](access_token|auth_token)['"]\s*[:=]\s*['"][^'"]{10,}['"]/, severity: 'high' as const },
        { name: 'JWT令牌', pattern: /['"](jwt|token)['"]\s*[:=]\s*['"]eyJ[a-zA-Z0-9_-]+\./, severity: 'high' as const },
      ],
      passwords: [
        { name: '硬编码密码', pattern: /password\s*[:=]\s*['"][^'"]{6,}['"]/gi, severity: 'critical' as const },
        { name: '数据库密码', pattern: /(pwd|passwd|password)\s*[:=]\s*['"][^'"]+['"]/gi, severity: 'critical' as const },
        { name: '默认密码', pattern: /(admin|root|123456|password)\s*[:=]\s*['"][^'"]*['"]/gi, severity: 'high' as const },
      ],
      certificates: [
        { name: '私钥', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, severity: 'critical' as const },
        { name: '证书', pattern: /-----BEGIN CERTIFICATE-----/, severity: 'medium' as const },
        { name: 'PEM格式密钥', pattern: /-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/, severity: 'high' as const },
      ],
      database: [
        { name: '数据库连接', pattern: /jdbc:[^'"]+['"]|mongodb:\/\/[^'"]+['"]/gi, severity: 'high' as const },
        { name: 'Redis连接', pattern: /redis:\/\/[^'"]+['"]/gi, severity: 'medium' as const },
        { name: 'SQL Server连接', pattern: /Server=[^'"]+;[^'"]*Password=[^'"]+['"]/gi, severity: 'high' as const },
      ],
      cloud_keys: [
        { name: 'AWS访问密钥', pattern: /AKIA[0-9A-Z]{16}/, severity: 'critical' as const },
        { name: 'AWS私密访问密钥', pattern: /['"](aws_secret_access_key|secretAccessKey)['"]\s*[:=]\s*['"][^'"]{20,}['"]/, severity: 'critical' as const },
        { name: '阿里云AccessKey', pattern: /LTAI[a-zA-Z0-9]{12,20}/, severity: 'critical' as const },
      ],
      mobile_specific: [
        { name: '微信AppID', pattern: /wx[a-f0-9]{16}/, severity: 'medium' as const },
        { name: '微信AppSecret', pattern: /['"](app_?secret|appsecret)['"]\s*[:=]\s*['"][a-f0-9]{32}['"]/, severity: 'high' as const },
        { name: '支付宝AppID', pattern: /['"](app_?id|appid)['"]\s*[:=]\s*['"]20\d{14}['"]/, severity: 'medium' as const },
        { name: '友盟AppKey', pattern: /['"](umeng_?key|appkey)['"]\s*[:=]\s*['"][a-f0-9]{24}['"]/, severity: 'medium' as const },
      ]
    };

    // 选择要扫描的模式
    let selectedPatterns: Array<{ name: string; pattern: RegExp; severity: 'critical' | 'high' | 'medium' | 'low' }> = [];
    if (patternType === 'all') {
      selectedPatterns = Object.values(patterns).flat();
    } else if (patterns[patternType as keyof typeof patterns]) {
      selectedPatterns = patterns[patternType as keyof typeof patterns];
    }

    this.log('scanHardcodedSecrets', { 
      message: `开始扫描硬编码敏感信息: ${targetPath}`,
      patternType,
      patternsCount: selectedPatterns.length
    });

    // 获取要扫描的文件列表
    const filesToScan = existsSync(targetPath) && statSync(targetPath).isDirectory() 
      ? this.scanDirectory(targetPath)
      : [targetPath];

    this.scannedFiles = filesToScan.length;

    // 扫描每个文件
    for (const filePath of filesToScan) {
      const lines = this.readFileLines(filePath);
      
      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];
        
        for (const { name, pattern, severity } of selectedPatterns) {
          const matches = line.match(pattern);
          if (matches) {
            for (const match of matches) {
              findings.push({
                type: 'hardcoded_secret',
                severity,
                title: `发现${name}`,
                description: `在代码中发现硬编码的${name}，这可能导致敏感信息泄露`,
                file: filePath,
                line: lineIndex + 1,
                code: line.trim(),
                recommendation: `将敏感信息移动到配置文件或环境变量中，不要在源码中硬编码敏感信息`
              });
            }
          }
        }
      }
    }

    this.log('scanHardcodedSecrets', {
      message: `硬编码敏感信息扫描完成`,
      findingsCount: findings.length,
      scannedFiles: filesToScan.length
    });

    return findings;
  }

  // 调试信息泄露扫描
  scanDebugInfoLeakage(targetPath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const debugPatterns = [
      { name: 'Android Log调用', pattern: /Log\.[dviwe]\s*\([^)]*\)/, severity: 'medium' as const, risk: '可能在生产环境中泄露敏感信息' },
      { name: '系统输出', pattern: /System\.out\.print[ln]?\s*\(/, severity: 'low' as const, risk: '调试信息可能被其他应用读取' },
      { name: '异常堆栈打印', pattern: /\.printStackTrace\s*\(\)/, severity: 'medium' as const, risk: '异常堆栈可能包含敏感路径信息' },
      { name: 'Console日志', pattern: /console\.(log|debug|info|warn|error)\s*\(/, severity: 'low' as const, risk: 'Web调试信息可能被检查' },
      { name: '调试断点', pattern: /debugger\s*;/, severity: 'medium' as const, risk: '生产代码中不应包含调试断点' },
      { name: 'TODO/FIXME注释', pattern: /(TODO|FIXME|XXX|HACK)[:：]\s*.+/, severity: 'info' as const, risk: '待办注释可能包含敏感信息' },
      { name: '敏感日志内容', pattern: /Log\.[dviwe]\([^)]*(?:password|token|key|secret)[^)]*\)/i, severity: 'high' as const, risk: '日志中包含敏感信息' },
    ];

    this.log('scanDebugInfoLeakage', { 
      message: `开始扫描调试信息泄露: ${targetPath}`,
      patternsCount: debugPatterns.length
    });

    // 获取要扫描的文件列表
    const filesToScan = existsSync(targetPath) && statSync(targetPath).isDirectory() 
      ? this.scanDirectory(targetPath)
      : [targetPath];

    // 扫描每个文件
    for (const filePath of filesToScan) {
      const lines = this.readFileLines(filePath);
      
      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];
        
        for (const { name, pattern, severity, risk } of debugPatterns) {
          const matches = line.match(pattern);
          if (matches) {
            findings.push({
              type: 'debug_leak',
              severity,
              title: `发现${name}`,
              description: `在代码中发现${name}，${risk}`,
              file: filePath,
              line: lineIndex + 1,
              code: line.trim(),
              recommendation: severity === 'info' 
                ? '建议清理代码注释，确保不包含敏感信息'
                : '移除生产代码中的调试信息，或使用可控制的日志级别'
            });
          }
        }
      }
    }

    this.log('scanDebugInfoLeakage', {
      message: `调试信息泄露扫描完成`,
      findingsCount: findings.length,
      scannedFiles: filesToScan.length
    });

    return findings;
  }

  // 弱加密算法检测
  scanWeakCrypto(targetPath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const weakCryptoPatterns = [
      { name: 'MD5哈希算法', pattern: /MessageDigest\.getInstance\s*\(\s*['"](MD5|md5)['"]\s*\)/, severity: 'high' as const, risk: 'MD5已被证明不安全，容易被碰撞攻击' },
      { name: 'SHA-1哈希算法', pattern: /MessageDigest\.getInstance\s*\(\s*['"](SHA-1|SHA1|sha-1|sha1)['"]\s*\)/, severity: 'medium' as const, risk: 'SHA-1存在安全风险，建议使用SHA-256或更强算法' },
      { name: 'DES加密算法', pattern: /Cipher\.getInstance\s*\(\s*['"]DES/, severity: 'critical' as const, risk: 'DES密钥长度过短，极易被暴力破解' },
      { name: '3DES加密算法', pattern: /Cipher\.getInstance\s*\(\s*['"]DESede/, severity: 'high' as const, risk: '3DES已被认为不安全，建议使用AES' },
      { name: 'RC4流密码', pattern: /Cipher\.getInstance\s*\(\s*['"]RC4/, severity: 'critical' as const, risk: 'RC4存在严重安全漏洞，应立即替换' },
      { name: 'ECB模式', pattern: /Cipher\.getInstance\s*\(\s*['"][^'"]*\/ECB\//, severity: 'high' as const, risk: 'ECB模式不安全，相同明文产生相同密文' },
      { name: 'AES默认模式(疑似ECB)', pattern: /Cipher\.getInstance\s*\(\s*['"]AES['"]\s*\)/, severity: 'high' as const, risk: '仅指定AES算法通常会触发不安全默认模式（常见为ECB）' },
      { name: '无填充模式', pattern: /Cipher\.getInstance\s*\(\s*['"][^'"]*\/NoPadding['"]\s*\)/, severity: 'medium' as const, risk: '无填充模式可能导致信息泄露' },
      { name: '弱随机数生成', pattern: /new\s+Random\s*\(/, severity: 'medium' as const, risk: 'Random类不适用于加密场景，应使用SecureRandom' },
      { name: 'Math.random使用', pattern: /Math\.random\s*\(\)/, severity: 'medium' as const, risk: 'Math.random()不适用于安全场景，应使用SecureRandom' },
      { name: '固定IV使用', pattern: /new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[/, severity: 'high' as const, risk: '使用固定IV违反了加密安全性原则' },
      { name: 'Base64加密误用', pattern: /Base64\.(encode|decode)[^\/]*\/\/.*(?:encrypt|decrypt|password|secret)/, severity: 'high' as const, risk: 'Base64是编码不是加密，不能用于保护敏感数据' },
    ];

    this.log('scanWeakCrypto', { 
      message: `开始扫描弱加密算法: ${targetPath}`,
      patternsCount: weakCryptoPatterns.length
    });

    // 获取要扫描的文件列表
    const filesToScan = existsSync(targetPath) && statSync(targetPath).isDirectory() 
      ? this.scanDirectory(targetPath)
      : [targetPath];

    // 扫描每个文件
    for (const filePath of filesToScan) {
      const lines = this.readFileLines(filePath);
      const literalConstants = this.collectLiteralConstants(lines);
      
      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];
        
        for (const { name, pattern, severity, risk } of weakCryptoPatterns) {
          const matches = line.match(pattern);
          if (matches) {
            findings.push({
              type: 'weak_crypto',
              severity,
              title: `发现${name}`,
              description: `在代码中发现${name}的使用，${risk}`,
              file: filePath,
              line: lineIndex + 1,
              code: line.trim(),
              recommendation: this.getCryptoRecommendation(name)
            });
          }
        }

        const keyDetection = this.detectHardcodedSecretKey(line, literalConstants);
        if (keyDetection) {
          const referenceHint = keyDetection.referenceLine
            ? `，密钥常量定义于第${keyDetection.referenceLine}行`
            : '';
          findings.push({
            type: 'weak_crypto',
            severity: 'high',
            title: '发现硬编码加密密钥',
            description: `检测到 SecretKeySpec 使用硬编码密钥（${keyDetection.source}）${referenceHint}，攻击者可通过逆向提取密钥并解密本地敏感数据`,
            file: filePath,
            line: lineIndex + 1,
            code: line.trim(),
            recommendation: this.getCryptoRecommendation('硬编码加密密钥')
          });
        }
      }

      const offlineRecoverableSecret = this.detectOfflineRecoverableSecret(filePath, lines, literalConstants);
      if (offlineRecoverableSecret) {
        findings.push(offlineRecoverableSecret);
      }
    }

    this.log('scanWeakCrypto', {
      message: `弱加密算法扫描完成`,
      findingsCount: findings.length,
      scannedFiles: filesToScan.length
    });

    return findings;
  }

  private collectLiteralConstants(lines: string[]): Map<string, LiteralConstantInfo> {
    const constants = new Map<string, LiteralConstantInfo>();

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];

      const byteArrayMatch = line.match(/\b(?:final\s+)?byte\[\]\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+byte\[\]\s*\{([^}]+)\}/);
      if (byteArrayMatch) {
        constants.set(byteArrayMatch[1], {
          line: lineIndex + 1,
          value: byteArrayMatch[2].trim(),
          kind: 'bytes'
        });
      }

      const javaStringMatch = line.match(/\b(?:final\s+)?String\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']{8,})["']/);
      const kotlinStringMatch = line.match(/\b(?:const\s+val|val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']{8,})["']/);
      const stringMatch = javaStringMatch || kotlinStringMatch;
      if (stringMatch) {
        constants.set(stringMatch[1], {
          line: lineIndex + 1,
          value: stringMatch[2],
          kind: this.classifyConstantValue(stringMatch[2])
        });
      }

      const base64DecodeMatch = line.match(/\b(?:final\s+)?(?:byte\[\]|String|var|val)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*Base64\.(?:decode|getDecoder\(\)\.decode)\s*\(\s*["']([A-Za-z0-9+/=]{12,})["']/i);
      if (base64DecodeMatch) {
        constants.set(base64DecodeMatch[1], {
          line: lineIndex + 1,
          value: base64DecodeMatch[2],
          kind: 'base64'
        });
      }
    }

    return constants;
  }

  private classifyConstantValue(value: string): LiteralConstantKind {
    if (/^[0-9a-fA-F]{16,}$/.test(value)) {
      return 'hex';
    }
    if (/^[A-Za-z0-9+/]{16,}={0,2}$/.test(value) && value.length % 4 === 0) {
      return 'base64';
    }
    return 'plain';
  }

  private detectHardcodedSecretKey(
    line: string,
    literalConstants: Map<string, LiteralConstantInfo>
  ): { source: string; referenceLine?: number } | null {
    if (!/SecretKeySpec\s*\(/.test(line)) {
      return null;
    }

    if (
      /SecretKeySpec\s*\(\s*(?:new\s+byte\[\]\s*\{[^}]+\}|["'][^"']{8,}["'](?:\s*\.\s*getBytes\s*\(\s*\))?)/.test(line) ||
      /SecretKeySpec\s*\(\s*Base64\.(?:decode|getDecoder\(\)\.decode)\s*\(\s*["'][A-Za-z0-9+/=]{12,}["']/.test(line)
    ) {
      return { source: 'inline literal' };
    }

    const directVarMatch = line.match(/SecretKeySpec\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))/);
    if (directVarMatch) {
      const variableName = directVarMatch[1];
      const literalInfo = literalConstants.get(variableName);
      if (literalInfo) {
        return { source: `constant variable ${variableName}`, referenceLine: literalInfo.line };
      }
    }

    const getBytesVarMatch = line.match(/SecretKeySpec\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*getBytes\s*\(/);
    if (getBytesVarMatch) {
      const variableName = getBytesVarMatch[1];
      const literalInfo = literalConstants.get(variableName);
      if (literalInfo) {
        return { source: `constant variable ${variableName}`, referenceLine: literalInfo.line };
      }
    }

    return null;
  }

  private detectOfflineRecoverableSecret(
    filePath: string,
    lines: string[],
    literalConstants: Map<string, LiteralConstantInfo>
  ): SecurityFinding | null {
    const encodedConstants = Array.from(literalConstants.entries())
      .map(([name, info]) => ({ name, ...info }))
      .filter(item => item.kind === 'hex' || item.kind === 'base64')
      .sort((a, b) => a.line - b.line);

    if (encodedConstants.length === 0) {
      return null;
    }

    const decryptStep = this.findDecryptStep(lines);
    if (!decryptStep) {
      return null;
    }

    const compareStep = this.findCompareStep(lines, decryptStep.line, encodedConstants.map(item => item.name), decryptStep.variable);
    if (!compareStep) {
      return null;
    }

    const constantRef = encodedConstants[0];
    const chain = `${constantRef.kind.toUpperCase()}常量(${constantRef.name})@${constantRef.line} -> 解密逻辑@${decryptStep.line} -> 比较逻辑@${compareStep.line}`;

    return {
      type: 'sensitive_data',
      severity: 'high',
      title: '发现可离线恢复secret链路',
      description: `检测到 ${chain}，攻击者可能通过逆向还原密钥与算法后离线恢复客户端secret`,
      file: filePath,
      line: compareStep.line,
      code: compareStep.code,
      recommendation: '将secret校验迁移到服务端；避免在客户端存放可逆密钥或可还原常量；对关键校验增加服务端签名和时效控制'
    };
  }

  private findDecryptStep(lines: string[]): { line: number; code: string; variable?: string } | null {
    const decryptPattern = /(Cipher\.getInstance\s*\(|\.doFinal\s*\(|\bdecrypt\s*\(|SecretKeySpec\s*\()/i;
    const decryptAssignPattern = /\b(?:String|byte\[\]|var|val)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=.*(?:doFinal|decrypt)\s*\(/i;

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      if (!decryptPattern.test(line)) {
        continue;
      }

      const assignMatch = line.match(decryptAssignPattern);
      return {
        line: lineIndex + 1,
        code: line.trim(),
        variable: assignMatch ? assignMatch[1] : undefined
      };
    }

    return null;
  }

  private findCompareStep(
    lines: string[],
    startLine: number,
    constantNames: string[],
    decryptVariable?: string
  ): { line: number; code: string } | null {
    const comparePattern = /(\.equals\s*\(|\.equalsIgnoreCase\s*\(|\.compareTo\s*\(|Objects\.equals\s*\()/;
    let fallback: { line: number; code: string } | null = null;

    for (let lineIndex = Math.max(0, startLine - 1); lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      if (!comparePattern.test(line)) {
        continue;
      }

      const candidate = {
        line: lineIndex + 1,
        code: line.trim()
      };

      const usesDecryptVar = decryptVariable ? line.includes(decryptVariable) : false;
      const usesConstantVar = constantNames.some(name => line.includes(name));
      if (usesDecryptVar || usesConstantVar) {
        return candidate;
      }

      if (!fallback) {
        fallback = candidate;
      }
    }

    return fallback;
  }

  private getCryptoRecommendation(cryptoType: string): string {
    const recommendations: Record<string, string> = {
      'MD5哈希算法': '使用SHA-256或SHA-3代替MD5',
      'SHA-1哈希算法': '使用SHA-256、SHA-384或SHA-512代替SHA-1',
      'DES加密算法': '使用AES-256-GCM代替DES',
      '3DES加密算法': '使用AES-256-GCM代替3DES',
      'RC4流密码': '使用AES-GCM或ChaCha20-Poly1305代替RC4',
      'ECB模式': '使用CBC、GCM或CTR模式，并确保使用随机IV',
      'AES默认模式(疑似ECB)': '显式指定安全模式，例如 AES/GCM/NoPadding，避免仅写 AES 导致默认不安全模式',
      '无填充模式': '使用PKCS5Padding或OAEP填充',
      '弱随机数生成': '使用SecureRandom代替Random',
      'Math.random使用': '在安全场景中使用SecureRandom代替Math.random',
      '固定IV使用': '为每次加密生成随机IV',
      'Base64加密误用': 'Base64仅用于编码，敏感数据需使用真正的加密算法如AES',
      '硬编码加密密钥': '密钥不得硬编码在客户端，建议使用Android Keystore并由服务端下发短期会话密钥'
    };
    
    return recommendations[cryptoType] || '遵循最新的加密算法安全标准';
  }

  // 综合静态分析
  performComprehensiveAnalysis(targetPath: string): StaticAnalysisResult {
    const startTime = Date.now();
    
    this.log('performComprehensiveAnalysis', { 
      message: `开始综合静态分析: ${targetPath}` 
    });

    // 执行所有扫描
    const allFindings: SecurityFinding[] = [
      ...this.scanHardcodedSecrets(targetPath),
      ...this.scanDebugInfoLeakage(targetPath),
      ...this.scanWeakCrypto(targetPath)
    ];

    // 统计结果
    const summary = {
      totalFindings: allFindings.length,
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high: allFindings.filter(f => f.severity === 'high').length,
      medium: allFindings.filter(f => f.severity === 'medium').length,
      low: allFindings.filter(f => f.severity === 'low').length,
      info: allFindings.filter(f => f.severity === 'info').length,
    };

    const scanTime = Date.now() - startTime;

    const result: StaticAnalysisResult = {
      summary,
      findings: allFindings.sort((a, b) => {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return severityOrder[a.severity] - severityOrder[b.severity];
      }),
      scanTime,
      scannedFiles: this.scannedFiles
    };

    this.log('performComprehensiveAnalysis', {
      message: `静态分析完成`,
      summary,
      scanTime: `${scanTime}ms`,
      scannedFiles: this.scannedFiles
    });

    return result;
  }
}
