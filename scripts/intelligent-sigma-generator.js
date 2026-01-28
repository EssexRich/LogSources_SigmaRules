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

function generateSigmaRule(techniqueId, techName, logsource, conditions, actor) {
  const uuid = generateUUID();
  const now = new Date().toISOString().split('T')[0];
  const detection = buildDetectionYAML(conditions);

  return `title: ${techName} (${logsource.product.toUpperCase()} - ${logsource.service})
id: ${uuid}
description: >
  Detects techniques consistent with MITRE ATT&CK technique ${techniqueId}.
  Threat Actor: ${actor}
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
  - actor.${actor.toLowerCase().replace(/\s+/g, '_')}
`;
}

function buildDetectionFromSigmaPatterns(sigmaRules, logsource) {
  const matchingRules = sigmaRules.filter(rule => {
    return rule.product === logsource.product && 
           (rule.service === logsource.service || rule.category === logsource.category);
  });

  if (matchingRules.length === 0) {
    return buildDetectionFromFieldMapping(logsource);
  }

  const detection = {};
  
  matchingRules.slice(0, 3).forEach(rule => {
    rule.detections.slice(0, 2).forEach(pattern => {
      const field = pattern.field;
      const values = pattern.values;
      
      if (field && values && values.length > 0) {
        const filteredValues = values
          .filter(v => v && typeof v === 'string')
          .filter(v => !v.match(/^(C:\\Windows|system32|\\system32)/i))
          .slice(0, 3);
        
        if (filteredValues.length > 0) {
          detection[`${field}|contains`] = filteredValues;
        }
      }
    });
  });

  if (Object.keys(detection).length === 0) {
    return buildDetectionFromFieldMapping(logsource);
  }

  return detection;
}

function buildDetectionFromFieldMapping(logsource) {
  const detection = {};
  
  if (logsource.product === 'windows') {
    detection['Image|contains'] = ['cmd.exe', 'powershell.exe', 'rundll32.exe'];
  } else if (logsource.product === 'linux') {
    detection['exe|contains'] = ['/bin/bash', '/bin/sh', '/usr/bin/python'];
  } else if (logsource.product === 'macos') {
    detection['exe|contains'] = ['/bin/bash', '/bin/sh', '/usr/bin/python'];
  } else {
    detection['event|contains'] = 'action';
  }
  
  return detection;
}

async function main() {
  console.log('[SigmaGen] Starting intelligent Sigma rule generation...\n');

  let logsources = [];
  try {
    const logsourcesPath = path.join(process.cwd(), 'logsources.json');
    if (!fs.existsSync(logsourcesPath)) {
      console.error('[SigmaGen] ERROR: logsources.json not found!');
      process.exit(1);
    }
    const logsourcesData = JSON.parse(fs.readFileSync(logsourcesPath, 'utf8'));
    logsources = logsourcesData.logsources;
    console.log(`[SigmaGen] ✓ Loaded ${logsources.length} logsources`);
  } catch (error) {
    console.error('[SigmaGen] ERROR: Failed to load logsources:', error.message);
    process.exit(1);
  }

  let sigmaTechniqueMap = {};
  try {
    const sigmaMapPath = path.join(process.cwd(), 'data/sigma-technique-map.json');
    if (fs.existsSync(sigmaMapPath)) {
      sigmaTechniqueMap = JSON.parse(fs.readFileSync(sigmaMapPath, 'utf8'));
      console.log(`[SigmaGen] ✓ Loaded SigmaHQ technique map`);
    }
  } catch (error) {
    console.warn('[SigmaGen] ⚠ Could not load sigma-technique-map.json');
  }

  const mitreActorTechMap = {};
  const mitreActorNames = new Set();
  const techniqueNames = {};
  const actorIdToName = {};
  
  try {
    console.log('[SigmaGen] Fetching MITRE data...');
    for (let i = 1; i <= 500; i++) {
      const actorId = `G${String(i).padStart(4, '0')}`;
      try {
        const actor = await fetchURL(`https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/actors/${actorId}.json`);
        if (actor && actor.name && actor.id) {
          mitreActorNames.add(actor.name);
          actorIdToName[actor.id] = actor.name;
        }
      } catch (e) {
        if (i > 50 && mitreActorNames.size === 0) throw e;
      }
    }
    console.log(`[SigmaGen] ✓ Found ${mitreActorNames.size} MITRE actors`);

    const mitreIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/index.json');
    if (mitreIndex.techniques) {
      Object.entries(mitreIndex.techniques).forEach(([techId, techName]) => {
        techniqueNames[techId] = techName;
      });
    }
    console.log(`[SigmaGen] ✓ Found ${Object.keys(techniqueNames).length} techniques`);

    const relationships = await fetchURL('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/relationships/index.json');
    const stixIdToTech = {};
    
    for (const techId of Object.keys(techniqueNames).slice(0, 500)) {
      try {
        const tech = await fetchURL(`https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/techniques/${techId}.json`);
        if (tech && tech.id) stixIdToTech[tech.id] = techId;
      } catch (e) {}
    }

    let relCount = 0;
    relationships.forEach(rel => {
      if (rel.relationship_type === 'uses' && rel.source_ref.startsWith('intrusion-set--') && rel.target_ref.startsWith('attack-pattern--')) {
        const actorName = actorIdToName[rel.source_ref];
        const techId = stixIdToTech[rel.target_ref];
        
        if (actorName && techId) {
          if (!mitreActorTechMap[techId]) mitreActorTechMap[techId] = [];
          if (!mitreActorTechMap[techId].includes(actorName)) {
            mitreActorTechMap[techId].push(actorName);
            relCount++;
          }
        }
      }
    });
    console.log(`[SigmaGen] ✓ Loaded ${relCount} MITRE relationships`);
  } catch (error) {
    console.warn('[SigmaGen] ⚠ Could not fetch MITRE data:', error.message);
  }

  const ransomwareActorTechMap = {};
  const ransomwareActorNames = new Set();
  
  try {
    const ttpIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/ThreatActors-TTPs/main/ttp-index.json');
    if (ttpIndex.actors && Array.isArray(ttpIndex.actors)) {
      let ttpCount = 0;
      ttpIndex.actors.forEach(actor => {
        if (actor.name && actor.techniques && Array.isArray(actor.techniques)) {
          ransomwareActorNames.add(actor.name);
          actor.techniques.forEach(tech => {
            if (tech.match(/^T\d+(\.\d+)?$/)) {
              if (!ransomwareActorTechMap[tech]) ransomwareActorTechMap[tech] = [];
              if (!ransomwareActorTechMap[tech].includes(actor.name)) {
                ransomwareActorTechMap[tech].push(actor.name);
                ttpCount++;
              }
            }
          });
        }
      });
      console.log(`[SigmaGen] ✓ Loaded ${ransomwareActorNames.size} ransomware gangs`);
    }
  } catch (error) {
    console.warn('[SigmaGen] ⚠ Could not fetch ransomware gangs:', error.message);
  }

  const allActorTechMap = {};
  const allActors = new Set([...mitreActorNames, ...ransomwareActorNames]);
  
  Object.entries(mitreActorTechMap).forEach(([tech, actors]) => {
    if (!allActorTechMap[tech]) allActorTechMap[tech] = [];
    allActorTechMap[tech].push(...actors);
  });
  
  Object.entries(ransomwareActorTechMap).forEach(([tech, actors]) => {
    if (!allActorTechMap[tech]) allActorTechMap[tech] = [];
    allActorTechMap[tech].push(...actors);
  });
  
  Object.keys(allActorTechMap).forEach(tech => {
    allActorTechMap[tech] = [...new Set(allActorTechMap[tech])];
  });
  
  console.log(`[SigmaGen] ✓ ${allActors.size} total threat actors, ${Object.keys(allActorTechMap).length} techniques\n`);

  const baseDir = path.join(process.cwd(), 'sigma-rules-intelligent');
  if (fs.existsSync(baseDir)) fs.rmSync(baseDir, { recursive: true });
  fs.mkdirSync(baseDir, { recursive: true });

  let totalRulesGenerated = 0;
  let techniquesProcessed = 0;

  Object.entries(allActorTechMap).forEach(([techniqueId, actors]) => {
    const techName = techniqueNames[techniqueId] || techniqueId;
    
    techniquesProcessed++;
    if (techniquesProcessed % 50 === 0) {
      console.log(`[SigmaGen] Processing technique ${techniquesProcessed}/${Object.keys(allActorTechMap).length}...`);
    }

    const uniqueActors = [...new Set(actors)];
    const sigmaRulesForTech = sigmaTechniqueMap[techniqueId] || [];
    
    logsources.forEach((logsource) => {
      const conditions = buildDetectionFromSigmaPatterns(sigmaRulesForTech, logsource);

      if (!conditions || Object.keys(conditions).length === 0) return;

      uniqueActors.forEach((actor) => {
        if (!techniqueId || !techniqueId.match(/^T\d+(\.\d+)?$/)) return;

        const rule = generateSigmaRule(techniqueId, techName, logsource, conditions, actor);
        const actorDir = path.join(baseDir, logsource.product, logsource.service, actor);
        
        if (!fs.existsSync(actorDir)) fs.mkdirSync(actorDir, { recursive: true });

        try {
          fs.writeFileSync(path.join(actorDir, `${techniqueId}.yml`), rule);
          totalRulesGenerated++;
        } catch (error) {
          console.warn(`[SigmaGen] Failed to write ${techniqueId}/${actor}: ${error.message}`);
        }
      });
    });
  });

  console.log(`\n[SigmaGen] ✓ Generated ${totalRulesGenerated} Sigma rules`);
  console.log(`[SigmaGen] From ${techniquesProcessed} techniques, ${allActors.size} actors, ${logsources.length} logsources`);
}

main().catch(err => {
  console.error('[SigmaGen] ERROR:', err.message);
  process.exit(1);
});
