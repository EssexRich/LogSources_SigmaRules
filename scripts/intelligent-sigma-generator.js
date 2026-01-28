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

function fetchText(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
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

function extractTNumberFromYAML(content) {
  const match = content.match(/attack\.t\d+(\.\d+)?/gi);
  return match ? match[0].replace('attack.', '').toUpperCase() : null;
}

function extractTNumberFromTOML(content) {
  const match = content.match(/T\d+(\.\d+)?/);
  return match ? match[0] : null;
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

function generatePlaceholderRule(techniqueId, techName, logsource, actor) {
  const uuid = generateUUID();
  const now = new Date().toISOString().split('T')[0];
  const detection = buildDetectionYAML({
    'placeholder|contains': ['PLACEHOLDER - Analyst to populate indicators']
  });

  return `title: ${techName} (${logsource.product.toUpperCase()} - ${logsource.service})
id: ${uuid}
description: >
  Detects techniques consistent with MITRE ATT&CK technique ${techniqueId}.
  Threat Actor: ${actor}
  STATUS: Placeholder - waiting for detection indicators to be populated
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

async function fetchExternalRules() {
  console.log('[SigmaGen] Fetching external detection rules...');
  
  const rules = {
    elastic: {},
    splunk: {},
    microsoft: {}
  };

  // Fetch Elastic rules tree
  try {
    console.log('[SigmaGen]   - Indexing Elastic detection-rules...');
    const elasticTree = await fetchURL('https://api.github.com/repos/elastic/detection-rules/git/trees/main?recursive=1');
    if (elasticTree.tree) {
      const ruleFiles = elasticTree.tree.filter(f => f.path.endsWith('.toml') && f.path.includes('rules/'));
      console.log(`[SigmaGen]     ✓ Found ${ruleFiles.length} Elastic rules`);
      
      // Index a sample of them (to avoid rate limits)
      for (let i = 0; i < Math.min(ruleFiles.length, 50); i++) {
        try {
          const file = ruleFiles[i];
          const content = await fetchText(`https://raw.githubusercontent.com/elastic/detection-rules/main/${file.path}`);
          const tNum = extractTNumberFromTOML(content);
          if (tNum) {
            if (!rules.elastic[tNum]) rules.elastic[tNum] = [];
            rules.elastic[tNum].push({
              path: file.path,
              content: content.substring(0, 500) // Store just snippet
            });
          }
        } catch (e) {
          // Continue on error
        }
      }
    }
  } catch (error) {
    console.warn('[SigmaGen]   ⚠ Could not fetch Elastic rules:', error.message);
  }

  // Fetch Splunk rules tree
  try {
    console.log('[SigmaGen]   - Indexing Splunk security_content...');
    const splunkTree = await fetchURL('https://api.github.com/repos/splunk/security_content/git/trees/develop?recursive=1');
    if (splunkTree.tree) {
      const ruleFiles = splunkTree.tree.filter(f => (f.path.endsWith('.yml') || f.path.endsWith('.yaml')) && f.path.includes('detections/'));
      console.log(`[SigmaGen]     ✓ Found ${ruleFiles.length} Splunk rules`);
      
      for (let i = 0; i < Math.min(ruleFiles.length, 50); i++) {
        try {
          const file = ruleFiles[i];
          const content = await fetchText(`https://raw.githubusercontent.com/splunk/security_content/develop/${file.path}`);
          const tNum = extractTNumberFromYAML(content);
          if (tNum) {
            if (!rules.splunk[tNum]) rules.splunk[tNum] = [];
            rules.splunk[tNum].push({
              path: file.path,
              content: content.substring(0, 500)
            });
          }
        } catch (e) {
          // Continue on error
        }
      }
    }
  } catch (error) {
    console.warn('[SigmaGen]   ⚠ Could not fetch Splunk rules:', error.message);
  }

  // Fetch Microsoft Sentinel rules tree
  try {
    console.log('[SigmaGen]   - Indexing Microsoft Sentinel rules...');
    const msTree = await fetchURL('https://api.github.com/repos/microsoft/Microsoft-Sentinel2Go/git/trees/master?recursive=1');
    if (msTree.tree) {
      const ruleFiles = msTree.tree.filter(f => f.path.endsWith('.json') && f.path.includes('analytics'));
      console.log(`[SigmaGen]     ✓ Found ${ruleFiles.length} Microsoft rules`);
      
      for (let i = 0; i < Math.min(ruleFiles.length, 50); i++) {
        try {
          const file = ruleFiles[i];
          const content = await fetchText(`https://raw.githubusercontent.com/microsoft/Microsoft-Sentinel2Go/master/${file.path}`);
          const tNum = extractTNumberFromYAML(content);
          if (tNum) {
            if (!rules.microsoft[tNum]) rules.microsoft[tNum] = [];
            rules.microsoft[tNum].push({
              path: file.path,
              content: content.substring(0, 500)
            });
          }
        } catch (e) {
          // Continue on error
        }
      }
    }
  } catch (error) {
    console.warn('[SigmaGen]   ⚠ Could not fetch Microsoft rules:', error.message);
  }

  return rules;
}

async function main() {
  console.log('[SigmaGen] Starting intelligent Sigma rule generation...\n');

  // Load logsources
  let logsources = [];
  try {
    const logsourcesPath = path.join(process.cwd(), 'logsources.json');
    if (!fs.existsSync(logsourcesPath)) {
      console.error('[SigmaGen] ERROR: logsources.json not found!');
      process.exit(1);
    }
    const logsourcesData = JSON.parse(fs.readFileSync(logsourcesPath, 'utf8'));
    logsources = logsourcesData.logsources;
    console.log(`[SigmaGen] ✓ Loaded ${logsources.length} logsources\n`);
  } catch (error) {
    console.error('[SigmaGen] ERROR: Failed to load logsources:', error.message);
    process.exit(1);
  }

  // Fetch external rules
  const externalRules = await fetchExternalRules();
  console.log(`[SigmaGen] ✓ Indexed external rules\n`);

  // Fetch MITRE data
  console.log('[SigmaGen] Fetching MITRE intrusion-sets and TTPs...');
  const mitreActorTechMap = {};
  const mitreActorNames = new Set();
  const techniqueNames = {};
  const actorIdToName = {};

  try {
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

  // Fetch ransomware gangs
  console.log('[SigmaGen] Fetching ransomware gangs and TTPs...');
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
      console.log(`[SigmaGen] ✓ Loaded ${ransomwareActorNames.size} ransomware gangs\n`);
    }
  } catch (error) {
    console.warn('[SigmaGen] ⚠ Could not fetch ransomware gangs:', error.message);
  }

  // Combine all actors and techniques
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

  console.log(`[SigmaGen] ✓ ${allActors.size} threat actors, ${Object.keys(allActorTechMap).length} techniques\n`);

  // Generate rules
  console.log('[SigmaGen] Generating rules...');
  const baseDir = path.join(process.cwd(), 'sigma-rules-intelligent');
  if (fs.existsSync(baseDir)) fs.rmSync(baseDir, { recursive: true });
  fs.mkdirSync(baseDir, { recursive: true });

  let totalRulesGenerated = 0;
  let fromExternal = 0;
  let fromPlaceholder = 0;
  let techniquesProcessed = 0;

  Object.entries(allActorTechMap).forEach(([techniqueId, actors]) => {
    const techName = techniqueNames[techniqueId] || techniqueId;

    techniquesProcessed++;
    if (techniquesProcessed % 50 === 0) {
      console.log(`[SigmaGen] Processing ${techniquesProcessed}/${Object.keys(allActorTechMap).length}...`);
    }

    const uniqueActors = [...new Set(actors)];

    logsources.forEach((logsource) => {
      let rule = null;

      // Check if external rule exists for this technique
      const externalRule = externalRules.elastic[techniqueId] || externalRules.splunk[techniqueId] || externalRules.microsoft[techniqueId];

      if (externalRule) {
        // Use external rule (with minimal adaptation)
        rule = externalRule[0].content + `\n# Adapted for actor attribution\n`;
        fromExternal++;
      } else {
        // Generate placeholder
        rule = null; // Will generate per-actor below
      }

      uniqueActors.forEach((actor) => {
        if (!techniqueId || !techniqueId.match(/^T\d+(\.\d+)?$/)) return;

        const finalRule = rule || generatePlaceholderRule(techniqueId, techName, logsource, actor);
        const actorDir = path.join(baseDir, logsource.product, logsource.service, actor);

        if (!fs.existsSync(actorDir)) fs.mkdirSync(actorDir, { recursive: true });

        try {
          fs.writeFileSync(path.join(actorDir, `${techniqueId}.yml`), finalRule);
          totalRulesGenerated++;
          if (!rule) fromPlaceholder++;
        } catch (error) {
          console.warn(`[SigmaGen] Failed to write ${techniqueId}/${actor}: ${error.message}`);
        }
      });
    });
  });

  console.log(`\n[SigmaGen] ✓ Generated ${totalRulesGenerated} Sigma rules`);
  console.log(`[SigmaGen]   - From external repos: ${fromExternal}`);
  console.log(`[SigmaGen]   - Placeholders: ${fromPlaceholder}`);
  console.log(`[SigmaGen] From ${techniquesProcessed} techniques, ${allActors.size} actors, ${logsources.length} logsources`);
}

main().catch(err => {
  console.error('[SigmaGen] ERROR:', err.message);
  process.exit(1);
});
