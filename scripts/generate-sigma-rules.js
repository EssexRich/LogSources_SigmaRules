#!/usr/bin/env node

/**
 * Intelligent Sigma Rule Generator
 * 
 * Generates realistic, technique-aware Sigma rules by:
 * 1. Reading MITRE ATT&CK technique definitions
 * 2. Consulting logsources.json for available fields
 * 3. Building detection logic specific to each technique
 * 4. Generating complete Sigma rules for each log source
 */

const fs = require('fs');
const path = require('path');

// Technique-to-detection logic mapping
// Maps MITRE techniques to detection patterns and field requirements
const TECHNIQUE_PATTERNS = {
  'T1059.001': {
    name: 'Command and Scripting Interpreter: PowerShell',
    patterns: {
      'windows|security|process_creation': {
        description: 'Detects PowerShell process execution',
        fields: ['Image', 'CommandLine', 'User', 'ParentImage'],
        selection: [
          {
            filter_name: 'selection_powershell',
            conditions: {
              Image: ['*powershell.exe', '*pwsh.exe'],
            },
          },
          {
            filter_name: 'selection_obfuscation',
            conditions: {
              CommandLine: [
                '*-EncodedCommand*',
                '*-enc*',
                '*bypass*',
                '*IEX*',
                '*Invoke-Expression*',
              ],
            },
            optional: true,
          },
        ],
        condition: 'selection_powershell or selection_obfuscation',
      },
      'windows|sysmon|process_creation': {
        description: 'Detects PowerShell process execution via Sysmon',
        fields: ['Image', 'CommandLine', 'User', 'ParentImage', 'IntegrityLevel'],
        selection: [
          {
            filter_name: 'selection',
            conditions: {
              Image: ['*powershell.exe', '*pwsh.exe'],
              CommandLine: [
                '*-EncodedCommand*',
                '*-enc*',
                '*bypass*',
                '*IEX*',
              ],
            },
          },
        ],
        condition: 'selection',
      },
      'linux|auditd|process_creation': {
        description: 'Detects PowerShell invocation on Linux',
        fields: ['Image', 'CommandLine', 'User', 'ProcessName'],
        selection: [
          {
            filter_name: 'selection',
            conditions: {
              'Image|contains': 'pwsh',
              'CommandLine|contains': ['-EncodedCommand', 'bypass'],
            },
          },
        ],
        condition: 'selection',
      },
    },
    references: ['https://attack.mitre.org/techniques/T1059/001/'],
  },

  'T1078.001': {
    name: 'Valid Accounts: Default Accounts',
    patterns: {
      'windows|security|process_creation': {
        description: 'Detects default account abuse',
        fields: ['User', 'SubjectUserName', 'LogonId', 'ProcessId'],
        selection: [
          {
            filter_name: 'selection_defaults',
            conditions: {
              'SubjectUserName|endswith': [
                '$',
                '-a',
                '-b',
                '-c',
                'SYSTEM',
                'LOCAL SERVICE',
                'NETWORK SERVICE',
              ],
            },
          },
          {
            filter_name: 'selection_anomalous',
            conditions: {
              'TokenElevationType': ['%%1937', '%%1938'], // TokenElevationTypeDefault
            },
            optional: true,
          },
        ],
        condition: 'selection_defaults and selection_anomalous',
      },
      'windows|defender|process_creation': {
        description: 'Detects default account usage via Defender',
        fields: ['AccountName', 'ProcessIntegrityLevel', 'ProcessTokenElevation'],
        selection: [
          {
            filter_name: 'selection',
            conditions: {
              'AccountName|endswith': ['$', 'SYSTEM'],
              'ProcessTokenElevation': 'TokenElevated',
            },
          },
        ],
        condition: 'selection',
      },
      'm365|entra_id|authentication': {
        description: 'Detects suspicious authentication patterns',
        fields: ['AccountName', 'RiskLevel', 'AuthenticationDetails', 'Location'],
        selection: [
          {
            filter_name: 'selection',
            conditions: {
              'RiskLevel': 'high',
              'AuthenticationDetails|contains': 'MFA failed',
            },
          },
        ],
        condition: 'selection',
      },
    },
    references: ['https://attack.mitre.org/techniques/T1078/001/'],
  },

  'T1486': {
    name: 'Data Encrypted for Impact',
    patterns: {
      'windows|sysmon|process_creation': {
        description: 'Detects suspicious file encryption activities',
        fields: ['Image', 'CommandLine', 'ParentImage', 'User'],
        selection: [
          {
            filter_name: 'selection_encryption_tools',
            conditions: {
              'Image|endswith': [
                'cipher.exe',
                'certutil.exe',
                'openssl.exe',
                'gpg.exe',
              ],
              'CommandLine|contains': [
                '/k',
                '-e',
                '-encrypt',
                '-aes',
                'enc',
              ],
            },
          },
          {
            filter_name: 'selection_bulk_operations',
            conditions: {
              'CommandLine|contains': ['/s', '/r', '-r', 'recurse'],
            },
            optional: true,
          },
        ],
        condition: 'selection_encryption_tools',
      },
      'linux|auditd|process_creation': {
        description: 'Detects file encryption commands on Linux',
        fields: ['Image', 'CommandLine', 'User', 'ProcessId'],
        selection: [
          {
            filter_name: 'selection',
            conditions: {
              'Image|endswith': ['openssl', 'gpg', 'cryptsetup'],
              'CommandLine|contains': ['enc', '-e', '-encrypt'],
            },
          },
        ],
        condition: 'selection',
      },
      'windows|defender|process_creation': {
        description: 'Detects encryption tool usage via Defender',
        fields: ['InitiatingProcessFileName', 'ProcessCommandLine', 'AccountName'],
        selection: [
          {
            filter_name: 'selection',
            conditions: {
              'InitiatingProcessFileName|endswith': [
                'cipher.exe',
                'certutil.exe',
              ],
              'ProcessCommandLine|contains': ['/k', '-e'],
            },
          },
        ],
        condition: 'selection',
      },
    },
    references: ['https://attack.mitre.org/techniques/T1486/'],
  },

  'T1190': {
    name: 'Exploit Public-Facing Application',
    patterns: {
      'windows|sysmon|process_creation': {
        description: 'Detects potential web application exploitation',
        fields: ['Image', 'CommandLine', 'ParentImage', 'ParentCommandLine'],
        selection: [
          {
            filter_name: 'selection_web_process',
            conditions: {
              'ParentImage|endswith': [
                'w3wp.exe',
                'apache.exe',
                'nginx.exe',
                'java.exe',
                'node.exe',
              ],
            },
          },
          {
            filter_name: 'selection_suspicious_child',
            conditions: {
              'Image|endswith': [
                'cmd.exe',
                'powershell.exe',
                'bash',
                'sh',
              ],
            },
          },
        ],
        condition: 'selection_web_process and selection_suspicious_child',
      },
      'linux|auditd|process_creation': {
        description: 'Detects web server spawning suspicious child processes',
        fields: ['ParentProcessName', 'Image', 'CommandLine', 'User'],
        selection: [
          {
            filter_name: 'selection',
            conditions: {
              'ParentProcessName|in': [
                'apache2',
                'nginx',
                'java',
                'node',
              ],
              'Image|in': ['bash', 'sh', 'python'],
            },
          },
        ],
        condition: 'selection',
      },
    },
    references: ['https://attack.mitre.org/techniques/T1190/'],
  },

  'T1566.001': {
    name: 'Phishing: Spearphishing Attachment',
    patterns: {
      'm365|entra_id|authentication': {
        description: 'Detects phishing attachment indicators',
        fields: ['SenderEmailAddress', 'AttachmentCount', 'URLCount', 'UserAgent'],
        selection: [
          {
            filter_name: 'selection_attachment',
            conditions: {
              'AttachmentCount': ['1', '2', '3', '4', '5'],
              'AttachmentExtension|in': [
                'exe',
                'dll',
                'scr',
                'zip',
                'rar',
                'iso',
              ],
            },
          },
        ],
        condition: 'selection_attachment',
      },
    },
    references: ['https://attack.mitre.org/techniques/T1566/001/'],
  },

  'T1070.001': {
    name: 'Indicator Removal: Clear Windows Event Logs',
    patterns: {
      'windows|security|process_creation': {
        description: 'Detects attempts to clear Windows event logs',
        fields: ['Image', 'CommandLine', 'User', 'ParentImage'],
        selection: [
          {
            filter_name: 'selection_wevtutil',
            conditions: {
              'Image|endswith': 'wevtutil.exe',
              'CommandLine|contains': ['cl', 'clear-log', 'delete-log'],
            },
          },
          {
            filter_name: 'selection_powershell',
            conditions: {
              'Image|endswith': 'powershell.exe',
              'CommandLine|contains': [
                'Clear-EventLog',
                'Remove-EventLog',
                'Get-EventLog',
              ],
            },
          },
        ],
        condition: 'selection_wevtutil or selection_powershell',
      },
      'windows|sysmon|process_creation': {
        description: 'Detects event log clearing via Sysmon',
        fields: ['Image', 'CommandLine', 'IntegrityLevel', 'User'],
        selection: [
          {
            filter_name: 'selection',
            conditions: {
              'Image|endswith': ['wevtutil.exe', 'powershell.exe'],
              'CommandLine|contains': [
                'clear-log',
                'Clear-EventLog',
                'delete-log',
              ],
              'IntegrityLevel': 'System',
            },
          },
        ],
        condition: 'selection',
      },
    },
    references: ['https://attack.mitre.org/techniques/T1070/001/'],
  },
};

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function buildDetectionLogic(patterns) {
  const detectionLines = [];

  patterns.forEach((pattern) => {
    if (pattern.filter_name === 'condition') return;

    detectionLines.push(`  ${pattern.filter_name}:`);

    Object.entries(pattern.conditions).forEach(([field, values]) => {
      if (Array.isArray(values)) {
        detectionLines.push(`    ${field}:`);
        values.forEach((v) => {
          detectionLines.push(`      - '${v}'`);
        });
      } else {
        detectionLines.push(`    ${field}: ${values}`);
      }
    });
  });

  return detectionLines.join('\n');
}

function generateSigmaRule(techniqueId, techData, logsourceDef) {
  const uuid = generateUUID();
  const now = new Date().toISOString().split('T')[0];
  const logsourceKey = `${logsourceDef.product}|${logsourceDef.service}|${logsourceDef.category}`;

  // Get the pattern for this logsource combination
  const pattern = techData.patterns[logsourceKey];
  if (!pattern) return null;

  const detectionLogic = buildDetectionLogic(pattern.selection);
  const condition = pattern.condition || 'selection';

  const rule = `title: ${techData.name} (${logsourceDef.product.toUpperCase()})
id: ${uuid}
description: >
  ${pattern.description}
  
  MITRE ATT&CK Technique: ${techniqueId} - ${techData.name}
  
  This rule detects activity consistent with this technique.
references:
  - ${techData.references[0]}
  - https://incidentbuddy.ai/gapmatrix/techniques/${techniqueId}
author: GapMATRIX Intelligent Sigma Generator
date: ${now}
status: experimental
severity: medium

logsource:
  product: ${logsourceDef.product}
  service: ${logsourceDef.service}
  category: ${logsourceDef.category}

detection:
${detectionLogic}
  condition: ${condition}

falsepositives:
  - Legitimate system administration activity
  - Authorized security testing
  - Expected software deployments

tags:
  - attack.${techniqueId}
  - attack_pattern
  - detection_rule
`;

  return rule;
}

function main() {
  console.log('[SigmaGen] Starting intelligent Sigma rule generation...');

  // Load logsources
  let logsources = [];
  try {
    const logsourcesPath = path.join(process.cwd(), 'logsources.json');
    if (!fs.existsSync(logsourcesPath)) {
      console.error('[SigmaGen] logsources.json not found!');
      process.exit(1);
    }
    const logsourcesData = JSON.parse(fs.readFileSync(logsourcesPath, 'utf8'));
    logsources = logsourcesData.logsources;
    console.log(`[SigmaGen] Loaded ${logsources.length} logsources`);
  } catch (error) {
    console.error('[SigmaGen] Failed to load logsources:', error.message);
    process.exit(1);
  }

  // Create sigma-rules directory structure
  const baseDir = path.join(process.cwd(), 'sigma-rules-intelligent');
  if (!fs.existsSync(baseDir)) {
    fs.mkdirSync(baseDir, { recursive: true });
  }

  let totalRulesGenerated = 0;
  const techniqueMap = new Map();

  // Generate rules for each technique
  Object.entries(TECHNIQUE_PATTERNS).forEach(([techniqueId, techData]) => {
    console.log(`\n[SigmaGen] Processing ${techniqueId}: ${techData.name}`);

    // For each applicable logsource, generate a rule
    logsources.forEach((logsource) => {
      const logsourceKey = `${logsource.product}|${logsource.service}|${logsource.category}`;

      // Check if this technique has patterns for this logsource
      if (techData.patterns[logsourceKey]) {
        const rule = generateSigmaRule(
          techniqueId,
          techData,
          logsource,
          techData.patterns[logsourceKey]
        );

        if (rule) {
          // Create product-specific directory
          const productDir = path.join(baseDir, logsource.product);
          if (!fs.existsSync(productDir)) {
            fs.mkdirSync(productDir, { recursive: true });
          }

          // Create service-specific directory
          const serviceDir = path.join(productDir, logsource.service);
          if (!fs.existsSync(serviceDir)) {
            fs.mkdirSync(serviceDir, { recursive: true });
          }

          // Write rule to file
          const filename = `${techniqueId}_${logsource.category}.yml`;
          const filepath = path.join(serviceDir, filename);
          fs.writeFileSync(filepath, rule);

          totalRulesGenerated++;
          console.log(
            `  [+] Generated rule for ${logsource.product}/${logsource.service}/${logsource.category}`
          );
        }
      }
    });
  });

  console.log(
    `\n[SigmaGen] ✓ Generated ${totalRulesGenerated} intelligent Sigma rules`
  );
  console.log(`[SigmaGen] Rules saved to: ${baseDir}`);
  console.log(`[SigmaGen] Techniques covered: ${Object.keys(TECHNIQUE_PATTERNS).length}`);
}

main();
