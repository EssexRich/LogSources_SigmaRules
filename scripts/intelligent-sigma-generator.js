#!/usr/bin/env node

/**
 * Intelligent Sigma Rule Generator
 * 
 * Dynamically generates Sigma rules by:
 * 1. Fetching threat actor TTPs from EssexRich/ThreatActors-TTPs (ttp-index.json)
 * 2. Fetching MITRE ATT&CK enterprise-attack.json directly from MITRE
 * 3. Consulting logsources.json for available fields
 * 4. Generating Sigma rules based on technique descriptions and platforms
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

function fetchURL(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`Failed to parse JSON from ${url}`));
        }
      });
    }).on('error', reject);
    
    request.setTimeout(30000, () => {
      request.destroy();
      reject(new Error(`Request timeout for ${url}`));
    });
  });
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function buildDetectionYAML(conditions) {
  const lines = [];
  Object.entries(conditions).forEach(([field, values]) => {
    if (Array.isArray(values)) {
      lines.push(`    ${field}:`);
      values.forEach((v) => {
        lines.push(`      - '${v}'`);
      });
    } else {
      lines.push(`    ${field}: ${values}`);
    }
  });
  return lines.join('\n');
}

function generateSigmaRule(techniqueId, techName, logsource, conditions) {
  const uuid = generateUUID();
  const now = new Date().toISOString().split('T')[0];
  const detection = buildDetectionYAML(conditions);

  return `title: ${techName} (${logsource.product.toUpperCase()})
id: ${uuid}
description: >
  Detects techniques consistent with MITRE ATT&CK technique ${techniqueId}.
references:
  - https://attack.mitre.org/techniques/${techniqueId}/
author: GapMATRIX Intelligent Sigma Generator
date: ${now}
status: experimental
severity: medium

logsource:
  product: ${logsource.product}
  service: ${logsource.service}
  category: ${logsource.category}

detection:
  selection:
${detection}
  condition: selection

falsepositives:
  - Legitimate system administration activity
  - Authorized security testing

tags:
  - attack.${techniqueId}
`;
}

// Dynamic detection patterns based on technique keywords
function buildDetectionForTechnique(techniqueId, techName, description, logsource) {
  const techLower = techName.toLowerCase();
  const descLower = description ? description.toLowerCase() : '';
  
  // Match patterns based on technique and logsource
  if (logsource.product === 'windows' && logsource.service === 'sysmon') {
    if (techLower.includes('powershell') || techLower.includes('command') || techLower.includes('script')) {
      return {
        'Image|endswith': ['powershell.exe', 'pwsh.exe', 'cmd.exe'],
        'CommandLine|contains': ['-EncodedCommand', '-enc', 'bypass', 'IEX']
      };
    }
    if (techLower.includes('encryption') || techLower.includes('encrypt')) {
      return {
        'Image|endswith': ['cipher.exe', 'certutil.exe', 'openssl.exe'],
        'CommandLine|contains': ['/e', '/s', '-encrypt', '-aes']
      };
    }
    if (techLower.includes('credential') || techLower.includes('password') || techLower.includes('dumping')) {
      return {
        'Image|endswith': ['lsass.exe', 'mimikatz.exe', 'procdump.exe'],
        'CommandLine|contains': ['/prot:off', 'sekurlsa', 'logonpasswords']
      };
    }
    if (techLower.includes('lateral') || techLower.includes('psexec') || techLower.includes('wmiexec')) {
      return {
        'Image|endswith': ['svchost.exe', 'wmiprvse.exe', 'rundll32.exe'],
        'CommandLine|contains': ['\\\\', 'wmic', 'psexec']
      };
    }
    if (techLower.includes('persistence') || techLower.includes('registry')) {
      return {
        'Image|endswith': ['reg.exe', 'regedit.exe', 'powershell.exe'],
        'CommandLine|contains': ['add', 'run', 'startup']
      };
    }
  }
  
  if (logsource.product === 'windows' && logsource.service === 'security') {
    if (techLower.includes('account') || techLower.includes('login') || techLower.includes('credential')) {
      return {
        'EventID': ['4624', '4625', '4648'],
        'AccountName|endswith': ['$', 'SYSTEM', 'LOCAL SERVICE']
      };
    }
    if (techLower.includes('logon')) {
      return {
        'EventID': ['4624', '4768', '4769', '4771'],
        'LogonType': ['2', '3', '10']
      };
    }
  }
  
  if (logsource.product === 'windows' && logsource.service === 'defender') {
    if (techLower.includes('malware') || techLower.includes('detect')) {
      return {
        'ActionType': ['Detected', 'Blocked', 'Remediated'],
        'ThreatName|contains': ['Malware', 'PUA', 'Trojan']
      };
    }
  }
  
  if (logsource.product === 'linux' && logsource.service === 'auditd') {
    if (techLower.includes('powershell') || techLower.includes('command') || techLower.includes('execution')) {
      return {
        'Image|endswith': ['/bash', '/sh', '/pwsh', '/python'],
        'CommandLine|contains': ['bash', 'sh', 'python', 'perl']
      };
    }
    if (techLower.includes('encryption') || techLower.includes('encrypt')) {
      return {
        'Image|endswith': ['/openssl', '/gpg', '/cryptsetup'],
        'CommandLine|contains': ['enc', '-e', '-encrypt']
      };
    }
    if (techLower.includes('sudo') || techLower.includes('privilege')) {
      return {
        'Image|endswith': ['/sudo', '/su'],
        'CommandLine|contains': ['sudo', 'su -']
      };
    }
  }
  
  if (logsource.product === 'macos' && logsource.service === 'unified_logging') {
    if (techLower.includes('command') || techLower.includes('execution')) {
      return {
        'ProcessName|endswith': ['/bash', '/sh', '/zsh'],
        'EventMessage|contains': ['executed', 'launch']
      };
    }
  }
  
  if (logsource.product === 'm365' && logsource.service === 'entra_id') {
    if (techLower.includes('phishing') || techLower.includes('attachment')) {
      return {
        'AttachmentExtension|in': ['exe', 'dll', 'zip', 'iso', 'scr'],
      };
    }
    if (techLower.includes('credential') || techLower.includes('password') || techLower.includes('sign')) {
      return {
        'RiskLevel': 'high',
        'AuthenticationDetails|contains': ['failed', 'suspicious']
      };
    }
  }
  
  if (logsource.product === 'google' && logsource.service === 'workspace') {
    if (techLower.includes('phishing') || techLower.includes('email')) {
      return {
        'email_subject|contains': ['invoice', 'urgent', 'confirm'],
        'email_from|endswith': ['.ru', '.cn', '.tk']
      };
    }
  }
  
  // Generic fallback
  return {
    'EventID|contains': '4688',
    'Image|contains': 'process'
  };
}

async function main() {
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

  // Fetch threat actor TTPs
  console.log('\n[SigmaGen] Fetching threat actor TTPs from EssexRich/ThreatActors-TTPs...');
  let threatActorIndex = {};
  const techniqueToActors = {};
  try {
    threatActorIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/ThreatActors-TTPs/main/ttp-index.json');
    if (threatActorIndex.actors) {
      threatActorIndex.actors.forEach((actor) => {
        actor.techniques.forEach((technique) => {
          if (!techniqueToActors[technique]) {
            techniqueToActors[technique] = [];
          }
          techniqueToActors[technique].push(actor.name);
        });
      });
      console.log(`[SigmaGen] Loaded ${threatActorIndex.actorCount} threat actors`);
    }
  } catch (error) {
    console.warn('[SigmaGen] Warning: Could not fetch threat actors:', error.message);
  }

  // Fetch MITRE ATT&CK data
  console.log('\n[SigmaGen] Fetching MITRE ATT&CK data...');
  let mitreData = {};
  const techniqueMap = {};
  try {
    mitreData = await fetchURL('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack.json');
    if (mitreData.objects) {
      mitreData.objects
        .filter(obj => obj.type === 'attack-pattern')
        .forEach(pattern => {
          const extRef = pattern.external_references?.find(r => r.source_name === 'mitre-attack');
          if (extRef) {
            techniqueMap[extRef.external_id] = {
              name: pattern.name,
              description: pattern.description
            };
          }
        });
      console.log(`[SigmaGen] Loaded ${Object.keys(techniqueMap).length} MITRE techniques`);
    }
  } catch (error) {
    console.error('[SigmaGen] Failed to fetch MITRE data:', error.message);
    process.exit(1);
  }

  // Create output directory
  const baseDir = path.join(process.cwd(), 'sigma-rules-intelligent');
  if (fs.existsSync(baseDir)) {
    fs.rmSync(baseDir, { recursive: true });
  }
  fs.mkdirSync(baseDir, { recursive: true });

  let totalRulesGenerated = 0;

  // Generate rules for each technique that has actor data
  Object.entries(techniqueToActors).forEach(([techniqueId, actors]) => {
    const techData = techniqueMap[techniqueId];
    if (!techData) return;

    console.log(`\n[SigmaGen] ${techniqueId}: ${techData.name} (${actors.length} actors)`);

    // For each logsource, generate a rule for each actor
    logsources.forEach((logsource) => {
      const conditions = buildDetectionForTechnique(techniqueId, techData.name, techData.description, logsource);
      if (!conditions) return;

      actors.forEach((actor) => {
        const rule = generateSigmaRule(techniqueId, techData.name, logsource, conditions);

        // Create actor-specific directory
        const actorDir = path.join(baseDir, logsource.product, actor);
        if (!fs.existsSync(actorDir)) {
          fs.mkdirSync(actorDir, { recursive: true });
        }

        const filename = `${techniqueId}.yml`;
        const filepath = path.join(actorDir, filename);
        fs.writeFileSync(filepath, rule);

        totalRulesGenerated++;
      });
    });
  });

  console.log(`\n[SigmaGen] ✓ Generated ${totalRulesGenerated} intelligent Sigma rules`);
  console.log(`[SigmaGen] Rules saved to: ${baseDir}`);
}

main().catch(err => {
  console.error('[SigmaGen] Fatal error:', err);
  process.exit(1);
});
