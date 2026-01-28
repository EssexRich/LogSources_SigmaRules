#!/usr/bin/env node

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
      reject(new Error(`Request timeout`));
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

function buildDetectionForTechnique(techniqueId, techName, logsource) {
  const techLower = (techName || '').toLowerCase();
  
  if (logsource.product === 'windows' && logsource.service === 'sysmon') {
    if (techLower.includes('powershell') || techLower.includes('command') || techLower.includes('script') || techLower.includes('interpreter')) {
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
    if (techLower.includes('credential') || techLower.includes('password') || techLower.includes('dump')) {
      return {
        'Image|endswith': ['lsass.exe', 'mimikatz.exe', 'procdump.exe'],
        'CommandLine|contains': ['sekurlsa', 'logonpasswords', '/prot:off']
      };
    }
    if (techLower.includes('lateral') || techLower.includes('remote')) {
      return {
        'Image|endswith': ['svchost.exe', 'wmiprvse.exe', 'rundll32.exe'],
        'CommandLine|contains': ['\\\\', 'wmic', 'psexec']
      };
    }
  }
  
  if (logsource.product === 'windows' && logsource.service === 'security') {
    if (techLower.includes('account') || techLower.includes('login') || techLower.includes('logon')) {
      return {
        'EventID': ['4624', '4625', '4648'],
        'AccountName|endswith': ['$', 'SYSTEM', 'LOCAL SERVICE']
      };
    }
  }
  
  if (logsource.product === 'windows' && logsource.service === 'defender') {
    if (techLower.includes('malware') || techLower.includes('threat') || techLower.includes('detect')) {
      return {
        'ActionType': ['Detected', 'Blocked', 'Remediated'],
        'ThreatName': ['Malware', 'PUA', 'Trojan']
      };
    }
  }
  
  if (logsource.product === 'linux' && logsource.service === 'auditd') {
    if (techLower.includes('command') || techLower.includes('execution') || techLower.includes('shell')) {
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
  }
  
  if (logsource.product === 'macos' && logsource.service === 'unified_logging') {
    if (techLower.includes('execution') || techLower.includes('command')) {
      return {
        'ProcessName|endswith': ['/bash', '/sh', '/zsh'],
        'EventMessage|contains': ['executed', 'launch']
      };
    }
  }
  
  if (logsource.product === 'm365' && logsource.service === 'entra_id') {
    if (techLower.includes('phishing') || techLower.includes('attachment') || techLower.includes('email')) {
      return {
        'AttachmentExtension|in': ['exe', 'dll', 'zip', 'iso', 'scr']
      };
    }
    if (techLower.includes('credential') || techLower.includes('sign') || techLower.includes('password')) {
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
    'Image|contains': 'process',
    'CommandLine|contains': 'cmd'
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

  // Fetch MITRE techniques from vectorized repo
  console.log('\n[SigmaGen] Fetching MITRE ATT&CK techniques...');
  let techniqueMap = {};
  try {
    const mitreIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/index.json');
    if (mitreIndex.techniques) {
      mitreIndex.techniques.forEach((tech) => {
        techniqueMap[tech.id] = {
          name: tech.name,
          description: tech.description
        };
      });
      console.log(`[SigmaGen] Loaded ${Object.keys(techniqueMap).length} MITRE techniques`);
    }
  } catch (error) {
    console.warn('[SigmaGen] Warning: Could not fetch from mitre_attack repo, using threat actor data only');
    // Fallback: use techniques from threat actors
    Object.keys(techniqueToActors).forEach(techniqueId => {
      techniqueMap[techniqueId] = {
        name: techniqueId,
        description: techniqueId
      };
    });
  }

  console.log(`[SigmaGen] Total techniques: ${Object.keys(techniqueMap).length}`);

  // Create output directory
  const baseDir = path.join(process.cwd(), 'sigma-rules-intelligent');
  if (fs.existsSync(baseDir)) {
    fs.rmSync(baseDir, { recursive: true });
  }
  fs.mkdirSync(baseDir, { recursive: true });

  let totalRulesGenerated = 0;
  let techniquesProcessed = 0;

  // Generate rules for ALL techniques
  Object.entries(techniqueMap).forEach(([techniqueId, techData]) => {
    const actors = techniqueToActors[techniqueId] || [];
    
    if (actors.length === 0) {
      return; // Skip techniques with no actors
    }

    techniquesProcessed++;
    if (techniquesProcessed % 50 === 0) {
      console.log(`[SigmaGen] Processed ${techniquesProcessed} techniques...`);
    }

    // For each logsource, generate a rule for each actor
    logsources.forEach((logsource) => {
      const conditions = buildDetectionForTechnique(techniqueId, techData.name, logsource);
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
  console.log(`[SigmaGen] From ${techniquesProcessed} techniques and ${Object.keys(techniqueToActors).length} unique threat actors`);
  console.log(`[SigmaGen] Rules saved to: ${baseDir}`);
}

main().catch(err => {
  console.error('[SigmaGen] Fatal error:', err.message);
  process.exit(1);
});
