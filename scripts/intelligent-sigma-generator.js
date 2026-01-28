#!/usr/bin/env node

/**
 * Intelligent Sigma Rule Generator
 * 
 * Generates technique-aware Sigma rules by:
 * 1. Fetching threat actor TTPs from EssexRich/ThreatActors-TTPs (ttp-index.json)
 * 2. Fetching MITRE ATT&CK technique data from EssexRich/mitre_attack
 * 3. Consulting logsources.json for available fields
 * 4. Generating complete Sigma rules for each log source
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

  const rule = `title: ${techName} (${logsource.product.toUpperCase()})
id: ${uuid}
description: >
  Detects techniques consistent with MITRE ATT&CK technique ${techniqueId}.
  Adversaries may use a variety of techniques throughout the attack lifecycle.
  This rule provides baseline detection for security monitoring and threat hunting.
references:
  - https://attack.mitre.org/techniques/${techniqueId}/
  - https://incidentbuddy.ai/gapmatrix/techniques/${techniqueId}
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
  - Expected software deployments

tags:
  - attack.${techniqueId}
  - attack_pattern
  - detection_rule
`;

  return rule;
}

// Generic detection patterns - will be enhanced with real data from repos
const TECHNIQUE_DETECTION_PATTERNS = {
  'T1059.001': { name: 'Command and Scripting Interpreter: PowerShell', patterns: { 'windows|sysmon|process_creation': { Image: ['powershell.exe', 'pwsh.exe'], CommandLine: ['-EncodedCommand', '-enc', 'bypass'] } } },
  'T1078': { name: 'Valid Accounts', patterns: { 'windows|security|process_creation': { SubjectUserName: ['SYSTEM', 'LOCAL SERVICE'] } } },
  'T1190': { name: 'Exploit Public-Facing Application', patterns: { 'windows|sysmon|process_creation': { ParentImage: ['w3wp.exe', 'apache.exe'], Image: ['cmd.exe', 'powershell.exe'] } } },
  'T1486': { name: 'Data Encrypted for Impact', patterns: { 'windows|sysmon|process_creation': { Image: ['cipher.exe', 'certutil.exe'], CommandLine: ['/e', '/s'] } } },
  'T1566': { name: 'Phishing', patterns: { 'm365|entra_id|authentication': { AttachmentExtension: ['exe', 'dll', 'zip'] } } },
  'T1070.001': { name: 'Indicator Removal: Clear Windows Event Logs', patterns: { 'windows|sysmon|process_creation': { Image: ['wevtutil.exe', 'powershell.exe'], CommandLine: ['clear-log'] } } },
};

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

  // Fetch threat actor data from EssexRich/ThreatActors-TTPs
  console.log('\n[SigmaGen] Fetching threat actor TTPs from EssexRich/ThreatActors-TTPs...');
  let threatActorIndex = {};
  try {
    threatActorIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/ThreatActors-TTPs/main/ttp-index.json');
    console.log(`[SigmaGen] Loaded ${threatActorIndex.actorCount} threat actors with ${threatActorIndex.totalTechniques} total technique mappings`);
  } catch (error) {
    console.error('[SigmaGen] Failed to fetch threat actor data:', error.message);
    console.log('[SigmaGen] Continuing with generic patterns...');
  }

  // Build reverse mapping: technique -> [actors]
  const techniqueToActors = {};
  if (threatActorIndex.actors) {
    threatActorIndex.actors.forEach((actor) => {
      actor.techniques.forEach((technique) => {
        if (!techniqueToActors[technique]) {
          techniqueToActors[technique] = [];
        }
        techniqueToActors[technique].push(actor.name);
      });
    });
    console.log(`[SigmaGen] Built mapping for ${Object.keys(techniqueToActors).length} techniques`);
  }

  // Create output directory
  const baseDir = path.join(process.cwd(), 'sigma-rules-intelligent');
  if (fs.existsSync(baseDir)) {
    fs.rmSync(baseDir, { recursive: true });
  }
  fs.mkdirSync(baseDir, { recursive: true });

  let totalRulesGenerated = 0;

  // Generate rules for each technique that has actor data
  const techniquesToProcess = Object.keys(techniqueToActors).length > 0 
    ? Object.entries(techniqueToActors) 
    : Object.entries(TECHNIQUE_DETECTION_PATTERNS).map(([tech, data]) => [tech, ['Unknown']]);

  console.log(`[SigmaGen] techniquesToProcess: ${techniquesToProcess.length} techniques`);

  techniquesToProcess.forEach(([techniqueId, actors]) => {
    const basePattern = TECHNIQUE_DETECTION_PATTERNS[techniqueId] || TECHNIQUE_DETECTION_PATTERNS[techniqueId.split('.')[0]];
    if (!basePattern) {
      console.log(`[SigmaGen] No pattern found for ${techniqueId}`);
      return;
    }

    console.log(`\n[SigmaGen] Processing ${techniqueId}: ${basePattern.name} (${actors.length} actors)`);
    console.log(`[SigmaGen]   Patterns available: ${Object.keys(basePattern.patterns).join(', ')}`);

    // For each pattern in this technique
    Object.entries(basePattern.patterns).forEach(([patternKey, conditions]) => {
      const [product, service, category] = patternKey.split('|');

      // Find matching logsource
      const logsource = logsources.find(ls => ls.product === product && ls.service === service && ls.category === category);
      if (!logsource) {
        console.log(`[SigmaGen]   No logsource found for ${patternKey}`);
        return;
      }

      console.log(`[SigmaGen]   Found logsource: ${patternKey}`);

      // Generate rule for each actor
      actors.forEach((actor) => {
        const rule = generateSigmaRule(techniqueId, basePattern.name, logsource, conditions);

        // Create actor-specific directory
        const actorDir = path.join(baseDir, logsource.product, actor);
        if (!fs.existsSync(actorDir)) {
          fs.mkdirSync(actorDir, { recursive: true });
        }

        const filename = `${techniqueId}.yml`;
        const filepath = path.join(actorDir, filename);
        fs.writeFileSync(filepath, rule);

        totalRulesGenerated++;
        console.log(`[SigmaGen]     Generated ${logsource.product}/${actor}/${techniqueId}`);
      });
    });
  });

  console.log(`\n[SigmaGen] ✓ Generated ${totalRulesGenerated} intelligent Sigma rules`);
  console.log(`[SigmaGen] Rules saved to: ${baseDir}`);
  console.log(`[SigmaGen] Structure: /sigma-rules-intelligent/[product]/[actor]/[technique].yml`);
}

main().catch(err => {
  console.error('[SigmaGen] Fatal error:', err);
  process.exit(1);
});
