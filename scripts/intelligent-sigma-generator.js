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
          reject(new Error(`Failed to parse JSON`));
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
      return { 'Image|endswith': ['powershell.exe', 'pwsh.exe', 'cmd.exe'], 'CommandLine|contains': ['-EncodedCommand', '-enc', 'bypass'] };
    }
    if (techLower.includes('encryption') || techLower.includes('encrypt')) {
      return { 'Image|endswith': ['cipher.exe', 'certutil.exe'], 'CommandLine|contains': ['/e', '/s'] };
    }
    if (techLower.includes('credential') || techLower.includes('dump')) {
      return { 'Image|endswith': ['lsass.exe', 'mimikatz.exe'], 'CommandLine|contains': ['sekurlsa'] };
    }
  }
  
  if (logsource.product === 'windows' && logsource.service === 'security') {
    if (techLower.includes('account') || techLower.includes('logon') || techLower.includes('credential')) {
      return { 'EventID': ['4624', '4625', '4648'] };
    }
  }
  
  if (logsource.product === 'linux' && logsource.service === 'auditd') {
    if (techLower.includes('command') || techLower.includes('execution')) {
      return { 'Image|endswith': ['/bash', '/sh', '/python'] };
    }
  }
  
  if (logsource.product === 'm365' && logsource.service === 'entra_id') {
    if (techLower.includes('phishing') || techLower.includes('email')) {
      return { 'AttachmentExtension|in': ['exe', 'dll', 'zip'] };
    }
  }
  
  // Fallback
  return { 'Image|contains': 'process', 'CommandLine|contains': 'cmd' };
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

  // Fetch ransomware gangs from ThreatActors-TTPs
  console.log('\n[SigmaGen] Fetching ransomware gangs from EssexRich/ThreatActors-TTPs...');
  let ransomwareActorMap = {};
  try {
    const ttpIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/ThreatActors-TTPs/main/ttp-index.json');
    if (ttpIndex.actors) {
      ttpIndex.actors.forEach(actor => {
        actor.techniques.forEach(tech => {
          if (!ransomwareActorMap[tech]) {
            ransomwareActorMap[tech] = [];
          }
          ransomwareActorMap[tech].push(actor.name);
        });
      });
      console.log(`[SigmaGen] Loaded ${ttpIndex.actorCount} ransomware gangs`);
    }
  } catch (error) {
    console.warn('[SigmaGen] Warning: Could not fetch ransomware gangs:', error.message);
  }

  // Fetch MITRE relationships to map intrusion-sets to techniques
  console.log('\n[SigmaGen] Fetching MITRE relationships from EssexRich/mitre_attack...');
  let mitreActorMap = {};
  let techniqueNames = {};
  try {
    const relationships = await fetchURL('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/relationships/index.json');
    if (Array.isArray(relationships)) {
      relationships.forEach(rel => {
        // source_ref is like "intrusion-set--123", target_ref is like "attack-pattern--456"
        if (rel.relationship_type === 'uses' && rel.source_ref.includes('intrusion-set') && rel.target_ref.includes('attack-pattern')) {
          const source_id = rel.source_ref.split('--')[1];
          const target_id = rel.target_ref.split('--')[1];
          
          if (!mitreActorMap[target_id]) {
            mitreActorMap[target_id] = [];
          }
          mitreActorMap[target_id].push(source_id);
        }
      });
      console.log(`[SigmaGen] Loaded ${Object.keys(mitreActorMap).length} MITRE techniques from relationships`);
    }
  } catch (error) {
    console.warn('[SigmaGen] Warning: Could not fetch MITRE relationships:', error.message);
  }

  // Fetch MITRE technique names
  console.log('\n[SigmaGen] Fetching MITRE technique names...');
  try {
    const mitreIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/index.json');
    if (mitreIndex.techniques) {
      techniqueNames = mitreIndex.techniques;
      console.log(`[SigmaGen] Loaded ${Object.keys(techniqueNames).length} technique names`);
    }
  } catch (error) {
    console.warn('[SigmaGen] Warning: Could not fetch MITRE index');
  }

  // Combine all actor-technique mappings
  const allActorTechMap = {};
  
  // Add ransomware gangs
  Object.entries(ransomwareActorMap).forEach(([tech, actors]) => {
    if (!allActorTechMap[tech]) {
      allActorTechMap[tech] = [];
    }
    allActorTechMap[tech].push(...actors);
  });
  
  // Add MITRE intrusion-sets
  Object.entries(mitreActorMap).forEach(([tech, actors]) => {
    if (!allActorTechMap[tech]) {
      allActorTechMap[tech] = [];
    }
    allActorTechMap[tech].push(...actors);
  });

  console.log(`\n[SigmaGen] Total techniques with actors: ${Object.keys(allActorTechMap).length}`);

  // Create output directory
  const baseDir = path.join(process.cwd(), 'sigma-rules-intelligent');
  if (fs.existsSync(baseDir)) {
    fs.rmSync(baseDir, { recursive: true });
  }
  fs.mkdirSync(baseDir, { recursive: true });

  let totalRulesGenerated = 0;
  let techniquesProcessed = 0;

  // Generate rules for all techniques with actors
  Object.entries(allActorTechMap).forEach(([techniqueId, actors]) => {
    const techName = techniqueNames[techniqueId] || techniqueId;
    
    techniquesProcessed++;
    if (techniquesProcessed % 50 === 0) {
      console.log(`[SigmaGen] Processed ${techniquesProcessed} techniques...`);
    }

    // For each logsource, generate a rule for each unique actor
    const uniqueActors = [...new Set(actors)];
    
    logsources.forEach((logsource) => {
      const conditions = buildDetectionForTechnique(techniqueId, techName, logsource);
      if (!conditions) return;

      uniqueActors.forEach((actor) => {
        const rule = generateSigmaRule(techniqueId, techName, logsource, conditions);

        // Create product/service/actor-specific directory
        const actorDir = path.join(baseDir, logsource.product, logsource.service, actor);
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
  console.log(`[SigmaGen] From ${techniquesProcessed} techniques`);
  console.log(`[SigmaGen] Ransomware gangs: ${Object.keys(ransomwareActorMap).length} techniques`);
  console.log(`[SigmaGen] MITRE intrusion-sets: ${Object.keys(mitreActorMap).length} techniques`);
  console.log(`[SigmaGen] Rules saved to: ${baseDir}`);
}

main().catch(err => {
  console.error('[SigmaGen] Fatal error:', err.message);
  process.exit(1);
});
