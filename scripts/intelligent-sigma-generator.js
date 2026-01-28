#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');

function fetchURL(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, {
      headers: { 'User-Agent': 'GapMATRIX-SigmaGen/1.0' }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`Failed to parse JSON: ${e.message}`));
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

function generatePlaceholderRule(techniqueId, techName, logsource, actor) {
  const uuid = generateUUID();
  const now = new Date().toISOString().split('T')[0];

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
    placeholder: true
  condition: selection

falsepositives:
  - Legitimate system administration activity
  - Authorized security testing

tags:
  - attack.${techniqueId}
  - actor.${actor.toLowerCase().replace(/\s+/g, '_')}
`;
}

async function fetchExternalRules(logsources) {
  console.log('[SigmaGen] Searching external repos for detection rules by T-number + product...\n');
  
  const rules = { elastic: {}, splunk: {}, microsoft: {} };

  // Get techniques to search
  const mitreIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/index.json');
  const techniques = Object.keys(mitreIndex.techniques || {}).slice(0, 100);
  
  const productSearchTerms = {
    'windows': 'windows OR sysmon OR eventlog',
    'linux': 'linux OR auditd',
    'google': 'google OR workspace OR gcp',
    'macos': 'macos OR osquery'
  };

  console.log(`[SigmaGen] Searching ${techniques.length} techniques with product filters across repos...\n`);

  let elasticFound = 0, splunkFound = 0, msFound = 0;

  // Search Elastic for each technique + product combo
  console.log('[SigmaGen] Searching Elastic detection-rules by T-number + product...');
  for (let i = 0; i < Math.min(techniques.length, 30); i++) {
    const tech = techniques[i];
    try {
      // Search for technique + windows
      const result = await fetchURL(`https://api.github.com/search/code?q=${tech}+windows+repo:elastic/detection-rules+extension:toml`);
      if (result.items && result.items.length > 0) {
        const key = `${tech}_windows`;
        rules.elastic[key] = result.items.slice(0, 2).map(f => ({ path: f.path, url: f.html_url, product: 'windows' }));
        elasticFound++;
      }
    } catch (e) {
      // Continue
    }
    if (i % 10 === 0) console.log(`[SigmaGen]   ${i}/${Math.min(techniques.length, 30)}...`);
  }
  console.log(`[SigmaGen] ✓ Found ${elasticFound} technique+product combos in Elastic\n`);

  // Search Splunk for each technique + product combo
  console.log('[SigmaGen] Searching Splunk security_content by T-number + product...');
  for (let i = 0; i < Math.min(techniques.length, 30); i++) {
    const tech = techniques[i];
    try {
      // Search for technique + windows
      const result = await fetchURL(`https://api.github.com/search/code?q=${tech}+windows+repo:splunk/security_content+extension:yml`);
      if (result.items && result.items.length > 0) {
        const key = `${tech}_windows`;
        rules.splunk[key] = result.items.slice(0, 2).map(f => ({ path: f.path, url: f.html_url, product: 'windows' }));
        splunkFound++;
      }
    } catch (e) {
      // Continue
    }
    if (i % 10 === 0) console.log(`[SigmaGen]   ${i}/${Math.min(techniques.length, 30)}...`);
  }
  console.log(`[SigmaGen] ✓ Found ${splunkFound} technique+product combos in Splunk\n`);

  // Search Microsoft for each technique + product combo
  console.log('[SigmaGen] Searching Microsoft Sentinel2Go by T-number + product...');
  for (let i = 0; i < Math.min(techniques.length, 30); i++) {
    const tech = techniques[i];
    try {
      // Search for technique + windows
      const result = await fetchURL(`https://api.github.com/search/code?q=${tech}+windows+repo:microsoft/Microsoft-Sentinel2Go+extension:json`);
      if (result.items && result.items.length > 0) {
        const key = `${tech}_windows`;
        rules.microsoft[key] = result.items.slice(0, 2).map(f => ({ path: f.path, url: f.html_url, product: 'windows' }));
        msFound++;
      }
    } catch (e) {
      // Continue
    }
    if (i % 10 === 0) console.log(`[SigmaGen]   ${i}/${Math.min(techniques.length, 30)}...`);
  }
  console.log(`[SigmaGen] ✓ Found ${msFound} technique+product combos in Microsoft\n`);

  console.log(`[SigmaGen] Search Summary: Elastic=${elasticFound}, Splunk=${splunkFound}, Microsoft=${msFound}\n`);
  return rules;
}

async function main() {
  console.log('[SigmaGen] Starting intelligent Sigma rule generation...\n');

  // Load logsources
  let logsources = [];
  try {
    const logsourcesData = JSON.parse(fs.readFileSync('logsources.json', 'utf8'));
    logsources = logsourcesData.logsources;
    console.log(`[SigmaGen] ✓ Loaded ${logsources.length} logsources\n`);
  } catch (error) {
    console.error('[SigmaGen] ERROR: Failed to load logsources');
    process.exit(1);
  }

  // Fetch external rules
  const externalRules = await fetchExternalRules(logsources);

  // Fetch MITRE data
  console.log('[SigmaGen] Fetching MITRE intrusion-sets and TTPs...');
  let mitreActorTechMap = {};
  let mitreActorNames = new Set();
  let techniqueNames = {};
  let actorIdToName = {};

  try {
    const mitreIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/index.json');
    
    if (mitreIndex.techniques) {
      Object.entries(mitreIndex.techniques).forEach(([techId, techName]) => {
        techniqueNames[techId] = techName;
      });
    }
    console.log(`[SigmaGen] ✓ Found ${Object.keys(techniqueNames).length} techniques`);

    if (mitreIndex.actors) {
      Object.entries(mitreIndex.actors).forEach(([actorId, actorName]) => {
        mitreActorNames.add(actorName);
        actorIdToName[actorId] = actorName;
      });
    }
    console.log(`[SigmaGen] ✓ Found ${mitreActorNames.size} MITRE actors`);

    const relationships = await fetchURL('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/relationships/index.json');
    const stixIdToTech = {};

    for (const techId of Object.keys(techniqueNames).slice(0, 500)) {
      try {
        const tech = await fetchURL(`https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/techniques/${techId}.json`);
        if (tech && tech.id) stixIdToTech[tech.id] = techId;
      } catch (e) {
        // Continue
      }
    }

    let relCount = 0;
    if (Array.isArray(relationships)) {
      relationships.forEach(rel => {
        if (rel.relationship_type === 'uses' && rel.source_ref && rel.target_ref) {
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
    }
    console.log(`[SigmaGen] ✓ Loaded ${relCount} MITRE relationships`);
  } catch (error) {
    console.warn('[SigmaGen] ⚠ Could not fetch MITRE data:', error.message);
  }

  // Fetch ransomware gangs
  console.log('[SigmaGen] Fetching ransomware gangs and TTPs...');
  let ransomwareActorTechMap = {};
  let ransomwareActorNames = new Set();

  try {
    const ttpIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/ThreatActors-TTPs/main/ttp-index.json');
    if (ttpIndex.actors && Array.isArray(ttpIndex.actors)) {
      ttpIndex.actors.forEach(actor => {
        if (actor.name && actor.techniques && Array.isArray(actor.techniques)) {
          ransomwareActorNames.add(actor.name);
          actor.techniques.forEach(tech => {
            if (tech.match(/^T\d+(\.\d+)?$/)) {
              if (!ransomwareActorTechMap[tech]) ransomwareActorTechMap[tech] = [];
              if (!ransomwareActorTechMap[tech].includes(actor.name)) {
                ransomwareActorTechMap[tech].push(actor.name);
              }
            }
          });
        }
      });
    }
    console.log(`[SigmaGen] ✓ Loaded ${ransomwareActorNames.size} ransomware gangs\n`);
  } catch (error) {
    console.warn('[SigmaGen] ⚠ Could not fetch ransomware gangs');
  }

  // Combine actors and techniques
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

  Object.entries(allActorTechMap).forEach(([techniqueId, actors]) => {
    const techName = techniqueNames[techniqueId] || techniqueId;
    const uniqueActors = [...new Set(actors)];

    logsources.forEach((logsource) => {
      // Check if external rule exists for this technique
      const hasExternalRule = externalRules.elastic[techniqueId] || externalRules.splunk[techniqueId] || externalRules.microsoft[techniqueId];

      uniqueActors.forEach((actor) => {
        if (!techniqueId.match(/^T\d+(\.\d+)?$/)) return;

        const rule = generatePlaceholderRule(techniqueId, techName, logsource, actor);
        const actorDir = path.join(baseDir, logsource.product, logsource.service, actor);

        if (!fs.existsSync(actorDir)) fs.mkdirSync(actorDir, { recursive: true });

        try {
          fs.writeFileSync(path.join(actorDir, `${techniqueId}.yml`), rule);
          totalRulesGenerated++;
          if (hasExternalRule) fromExternal++;
          else fromPlaceholder++;
        } catch (error) {
          console.warn(`[SigmaGen] Failed to write ${techniqueId}/${actor}`);
        }
      });
    });
  });

  console.log(`\n[SigmaGen] ✓ Generated ${totalRulesGenerated} Sigma rules`);
  console.log(`[SigmaGen]   - External rules found for: ${fromExternal}`);
  console.log(`[SigmaGen]   - Placeholders: ${fromPlaceholder}`);
}

main().catch(err => {
  console.error('[SigmaGen] ERROR:', err.message);
  process.exit(1);
});
