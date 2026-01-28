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

function buildDetectionForTechnique(techniqueId, techName, logsource) {
  // Use fieldMappings from logsource to build detection dynamically
  if (!logsource.fieldMappings || !logsource.fieldMappings[logsource.category]) {
    return null;
  }
  
  const fieldMapping = logsource.fieldMappings[logsource.category];
  const detection = {};
  
  // Build detection using available fields from the logsource's field mapping
  // For process_creation category, detect on Image/CommandLine if available
  if (logsource.category === 'process_creation') {
    if (fieldMapping['Image']) {
      detection[`${fieldMapping['Image']}|contains`] = ['cmd.exe', 'powershell.exe', 'bash', 'sh'];
    }
    if (fieldMapping['CommandLine']) {
      detection[`${fieldMapping['CommandLine']}|contains`] = ['-enc', 'bypass', 'encoded'];
    }
    // Fallback if no specific fields
    if (Object.keys(detection).length === 0) {
      detection['Image|contains'] = ['cmd', 'powershell'];
      detection['CommandLine|contains'] = ['encoded', 'bypass'];
    }
  }
  
  // For authentication category, detect on User/IpAddress if available
  if (logsource.category === 'authentication') {
    if (fieldMapping['User']) {
      detection[fieldMapping['User']] = 'user@domain.com';
    }
    if (fieldMapping['IpAddress']) {
      detection[`${fieldMapping['IpAddress']}|startswith`] = ['192.168', '10.0'];
    }
    // Fallback if no specific fields
    if (Object.keys(detection).length === 0) {
      detection['User|contains'] = 'admin';
    }
  }
  
  // For admin_activity category, detect on actor/eventname if available
  if (logsource.category === 'admin_activity') {
    if (fieldMapping['Actor']) {
      detection[fieldMapping['Actor']] = 'admin@example.com';
    }
    if (fieldMapping['EventType']) {
      detection[fieldMapping['EventType']] = 'admin_role_assigned';
    }
    // Fallback
    if (Object.keys(detection).length === 0) {
      detection['Actor|contains'] = 'admin';
    }
  }
  
  // Fallback if nothing matched
  if (Object.keys(detection).length === 0) {
    detection['Image|contains'] = 'process';
  }
  
  return detection;
}

async function main() {
  console.log('[SigmaGen] ====================================');
  console.log('[SigmaGen] Starting intelligent Sigma rule generation...');
  console.log('[SigmaGen] ====================================\n');

  // Step 1: Load logsources
  console.log('[SigmaGen] STEP 1: Loading logsources from logsources.json...');
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
    logsources.forEach(ls => {
      console.log(`[SigmaGen]   - ${ls.product}/${ls.service} (${ls.category})`);
    });
  } catch (error) {
    console.error('[SigmaGen] ERROR: Failed to load logsources:', error.message);
    process.exit(1);
  }

  // Step 2: Fetch MITRE intrusion-sets and their TTPs
  console.log('\n[SigmaGen] STEP 2: Fetching MITRE intrusion-sets and TTPs...');
  const mitreActorTechMap = {}; // { "T1486": ["APT1", "Lazarus Group", ...], ... }
  const mitreActorNames = new Set();
  const techniqueNames = {};
  
  try {
    // Fetch all intrusion-set actors from individual files (only need to do this once)
    console.log('[SigmaGen]   - Fetching intrusion-sets from /data/actors/...');
    const actorIdToName = {};
    for (let i = 1; i <= 500; i++) {
      const actorId = `G${String(i).padStart(4, '0')}`;
      try {
        const actor = await fetchURL(`https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/actors/${actorId}.json`);
        if (actor && actor.name && actor.id) {
          mitreActorNames.add(actor.name);
          actorIdToName[actor.id] = actor.name;
        }
      } catch (e) {
        // File doesn't exist, continue
        if (i > 50 && mitreActorNames.size === 0) {
          throw new Error('Could not find any actor files');
        }
      }
    }
    console.log(`[SigmaGen]   ✓ Found ${mitreActorNames.size} MITRE intrusion-sets`);

    // Fetch technique names from index.json - much faster than individual files
    console.log('[SigmaGen]   - Fetching attack-pattern (technique) names from index...');
    try {
      const mitreIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/index.json');
      if (mitreIndex.techniques) {
        Object.entries(mitreIndex.techniques).forEach(([techId, techName]) => {
          techniqueNames[techId] = techName;
        });
      }
    } catch (e) {
      console.warn('[SigmaGen]   ⚠ Could not fetch technique index:', e.message);
    }
    console.log(`[SigmaGen]   ✓ Found ${Object.keys(techniqueNames).length} technique names`);

    // Fetch relationships and map actors to techniques
    console.log('[SigmaGen]   - Fetching relationships...');
    const relationships = await fetchURL('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/relationships/index.json');
    
    // Fetch relationships and build actor-technique mapping
    console.log('[SigmaGen]   - Fetching relationships and building STIX UUID mapping...');
    const stixIdToTech = {};
    
    // Build STIX ID to T-number mapping from index.json entries
    // The index.json has all T-numbers, we just need to fetch each one to get its STIX ID
    try {
      // First, try to build the map by fetching techniques  
      // This is needed to convert relationship STIX IDs to T-numbers
      let mappedCount = 0;
      for (const techId of Object.keys(techniqueNames)) {
        try {
          const tech = await fetchURL(`https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/techniques/${techId}.json`);
          if (tech && tech.id) {
            stixIdToTech[tech.id] = techId;
            mappedCount++;
          }
        } catch (e) {
          // File might not exist (e.g., subtechniques stored differently)
        }
      }
      console.log(`[SigmaGen]   ✓ Built STIX mapping for ${mappedCount} techniques`);
    } catch (e) {
      console.warn('[SigmaGen]   ⚠ Could not build STIX mapping:', e.message);
    }

    // Now process relationships
    if (Array.isArray(relationships)) {
      let relationshipCount = 0;
      relationships.forEach(rel => {
        if (rel.relationship_type === 'uses') {
          const sourceType = rel.source_ref.split('--')[0];
          const targetType = rel.target_ref.split('--')[0];
          
          if (sourceType === 'intrusion-set' && targetType === 'attack-pattern') {
            const actorName = actorIdToName[rel.source_ref];
            const techId = stixIdToTech[rel.target_ref];
            
            if (actorName && techId) {
              if (!mitreActorTechMap[techId]) {
                mitreActorTechMap[techId] = [];
              }
              if (!mitreActorTechMap[techId].includes(actorName)) {
                mitreActorTechMap[techId].push(actorName);
                relationshipCount++;
              }
            }
          }
        }
      });
      console.log(`[SigmaGen]   ✓ Loaded ${relationshipCount} intrusion-set TTPs`);
    }
  } catch (error) {
    console.warn('[SigmaGen]   ⚠ Warning: Could not fetch MITRE data:', error.message);
  }

  // Step 3: Fetch ransomware gangs and their TTPs
  console.log('\n[SigmaGen] STEP 3: Fetching ransomware gangs and TTPs...');
  const ransomwareActorTechMap = {};
  const ransomwareActorNames = new Set();
  
  try {
    console.log('[SigmaGen]   - Fetching TTP index from EssexRich/ThreatActors-TTPs...');
    const ttpIndex = await fetchURL('https://raw.githubusercontent.com/EssexRich/ThreatActors-TTPs/main/ttp-index.json');
    if (ttpIndex.actors && Array.isArray(ttpIndex.actors)) {
      let ttpCount = 0;
      ttpIndex.actors.forEach(actor => {
        if (actor.name && actor.techniques && Array.isArray(actor.techniques)) {
          ransomwareActorNames.add(actor.name);
          actor.techniques.forEach(tech => {
            // Validate that tech is a proper T-number
            if (tech.match(/^T\d+(\.\d+)?$/)) {
              if (!ransomwareActorTechMap[tech]) {
                ransomwareActorTechMap[tech] = [];
              }
              if (!ransomwareActorTechMap[tech].includes(actor.name)) {
                ransomwareActorTechMap[tech].push(actor.name);
                ttpCount++;
              }
            }
          });
        }
      });
      console.log(`[SigmaGen]   ✓ Loaded ${ransomwareActorNames.size} ransomware gangs with ${ttpCount} TTPs`);
    }
  } catch (error) {
    console.warn('[SigmaGen]   ⚠ Warning: Could not fetch ransomware gangs:', error.message);
  }

  // Step 4: Combine all actors and TTPs into big master list
  console.log('\n[SigmaGen] STEP 4: Combining all threat actors and TTPs...');
  const allActorTechMap = {}; // Master map
  const allActors = new Set([...mitreActorNames, ...ransomwareActorNames]);
  
  // Merge both maps
  Object.entries(mitreActorTechMap).forEach(([tech, actors]) => {
    if (!allActorTechMap[tech]) {
      allActorTechMap[tech] = [];
    }
    allActorTechMap[tech].push(...actors);
  });
  
  Object.entries(ransomwareActorTechMap).forEach(([tech, actors]) => {
    if (!allActorTechMap[tech]) {
      allActorTechMap[tech] = [];
    }
    allActorTechMap[tech].push(...actors);
  });
  
  // Deduplicate
  Object.keys(allActorTechMap).forEach(tech => {
    allActorTechMap[tech] = [...new Set(allActorTechMap[tech])];
  });
  
  console.log(`[SigmaGen] ✓ Combined ${allActors.size} unique threat actors`);
  console.log(`[SigmaGen] ✓ ${Object.keys(allActorTechMap).length} techniques with TTPs`);
  console.log(`[SigmaGen]   - MITRE intrusion-sets: ${mitreActorNames.size}`);
  console.log(`[SigmaGen]   - Ransomware gangs: ${ransomwareActorNames.size}`);

  // Step 5: Generate Sigma rules for all logsources
  console.log('\n[SigmaGen] STEP 5: Generating Sigma rules for all logsources...');
  
  const baseDir = path.join(process.cwd(), 'sigma-rules-intelligent');
  if (fs.existsSync(baseDir)) {
    fs.rmSync(baseDir, { recursive: true });
  }
  fs.mkdirSync(baseDir, { recursive: true });

  let totalRulesGenerated = 0;
  let techniquesProcessed = 0;
  let skippedNoConditions = 0;
  let skippedInvalidTech = 0;
  let skippedWriteError = 0;

  Object.entries(allActorTechMap).forEach(([techniqueId, actors]) => {
    const techName = techniqueNames[techniqueId] || techniqueId;
    
    techniquesProcessed++;
    if (techniquesProcessed % 50 === 0) {
      console.log(`[SigmaGen]   Processing technique ${techniquesProcessed}/${Object.keys(allActorTechMap).length}...`);
    }

    const uniqueActors = [...new Set(actors)];
    
    logsources.forEach((logsource) => {
      const conditions = buildDetectionForTechnique(techniqueId, techName, logsource);
      if (!conditions) {
        skippedNoConditions++;
        return;
      }

      uniqueActors.forEach((actor) => {
        // Validate technique ID
        if (!techniqueId || typeof techniqueId !== 'string' || !techniqueId.match(/^T\d+(\.\d+)?$/)) {
          skippedInvalidTech++;
          return;
        }

        const rule = generateSigmaRule(techniqueId, techName, logsource, conditions, actor);

        // Create product/service/actor-specific directory
        const actorDir = path.join(baseDir, logsource.product, logsource.service, actor);
        if (!fs.existsSync(actorDir)) {
          fs.mkdirSync(actorDir, { recursive: true });
        }

        const filename = `${techniqueId}.yml`;
        const filepath = path.join(actorDir, filename);
        
        try {
          fs.writeFileSync(filepath, rule);
          totalRulesGenerated++;
        } catch (error) {
          skippedWriteError++;
          console.warn(`[SigmaGen] Failed to write rule for ${techniqueId}/${actor}: ${error.message}`);
        }
      });
    });
  });

  console.log(`\n[SigmaGen] ====================================`);
  console.log(`[SigmaGen] ✓ Generation complete!`);
  console.log(`[SigmaGen] ====================================`);
  console.log(`[SigmaGen] Generated ${totalRulesGenerated} intelligent Sigma rules`);
  console.log(`[SigmaGen] From ${techniquesProcessed} techniques`);
  console.log(`[SigmaGen] For ${allActors.size} threat actors`);
  console.log(`[SigmaGen] Across ${logsources.length} logsources`);
  console.log(`[SigmaGen]`);
  console.log(`[SigmaGen] Skip summary:`);
  console.log(`[SigmaGen]   - Skipped (no conditions): ${skippedNoConditions}`);
  console.log(`[SigmaGen]   - Skipped (invalid technique): ${skippedInvalidTech}`);
  console.log(`[SigmaGen]   - Skipped (write error): ${skippedWriteError}`);
  console.log(`[SigmaGen]`);
  console.log(`[SigmaGen] Directory structure:`);
  console.log(`[SigmaGen]   sigma-rules-intelligent/`);
  
  // Dynamically show actual logsource structure
  const productServices = {};
  logsources.forEach(ls => {
    if (!productServices[ls.product]) {
      productServices[ls.product] = [];
    }
    if (!productServices[ls.product].includes(ls.service)) {
      productServices[ls.product].push(ls.service);
    }
  });
  
  const products = Object.keys(productServices).sort();
  products.forEach((product, idx) => {
    const isLast = idx === products.length - 1;
    const prefix = isLast ? '└─' : '├─';
    console.log(`[SigmaGen]   ${prefix} ${product}/`);
    
    const services = productServices[product].sort();
    services.forEach((service, sIdx) => {
      const isLastService = sIdx === services.length - 1;
      const servicePrefix = isLast ? '   ' : '│  ';
      const serviceSymbol = isLastService ? '└─' : '├─';
      console.log(`[SigmaGen]   ${servicePrefix}${serviceSymbol} ${service}/[actor]/[T####.yml]`);
    });
  });
  
  console.log(`[SigmaGen]`);
  console.log(`[SigmaGen] Rules saved to: ${baseDir}`);
}

main().catch(err => {
  console.error('[SigmaGen] FATAL ERROR:', err.message);
  process.exit(1);
});
