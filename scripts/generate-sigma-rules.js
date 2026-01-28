#!/usr/bin/env node

/**
 * Intelligent Sigma Rule Generator
 * 
 * Uses external-rules-index.json to pull real detection logic from
 * Elastic, SigmaHQ, and Splunk repos, then generates rules per
 * actor/technique/logsource combination.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'GapMATRIX-SigmaGen/1.0' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode === 200) {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(new Error(`JSON parse error: ${e.message}`));
          }
        } else {
          reject(new Error(`HTTP ${res.statusCode}`));
        }
      });
    }).on('error', reject);
  });
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Find matching external rules for a technique + logsource
 */
function findMatchingRules(externalRules, techniqueId, logsource) {
  const techRules = externalRules[techniqueId] || [];
  
  // Filter by product and category match
  const matches = techRules.filter(rule => {
    // Product must match
    if (rule.product && rule.product !== 'unknown' && rule.product !== logsource.product) {
      return false;
    }
    
    // Category match (if rule specifies one)
    if (rule.category && rule.category !== logsource.category) {
      return false;
    }
    
    return true;
  });
  
  // Prefer rules that match service specifically
  const serviceMatches = matches.filter(r => r.service === logsource.service);
  if (serviceMatches.length > 0) {
    return serviceMatches;
  }
  
  return matches;
}

/**
 * Extract detection fields from external rule query
 */
function parseDetectionFromQuery(query, source) {
  if (!query) return null;
  
  const detection = {};
  
  if (source === 'elastic') {
    // Elastic EQL/KQL format - extract field conditions
    // e.g., process.name : ("cmd.exe", "powershell.exe")
    const fieldMatches = query.matchAll(/(\w+(?:\.\w+)*)\s*:\s*\(?\s*"([^"]+)"(?:\s*,\s*"([^"]+)")*\s*\)?/g);
    for (const match of fieldMatches) {
      const field = match[1];
      const values = [match[2]];
      if (match[3]) values.push(match[3]);
      detection[field] = values;
    }
    
    // Also catch single value matches: field : "value"
    const singleMatches = query.matchAll(/(\w+(?:\.\w+)*)\s*:\s*"([^"]+)"/g);
    for (const match of singleMatches) {
      if (!detection[match[1]]) {
        detection[match[1]] = [match[2]];
      }
    }
  } else if (source === 'sigma' || source === 'splunk') {
    // YAML detection format - already structured
    // Try to extract field: value patterns
    const lines = query.split('\n');
    for (const line of lines) {
      const match = line.match(/^\s*(\w+)(?:\|[\w]+)?:\s*(.+)$/);
      if (match) {
        const field = match[1];
        let value = match[2].trim();
        
        // Handle lists
        if (value.startsWith('-')) {
          continue; // Skip list markers, they'll be on separate lines
        }
        
        // Handle quoted strings
        value = value.replace(/^['"]|['"]$/g, '');
        
        if (value && field !== 'condition' && field !== 'selection') {
          if (!detection[field]) detection[field] = [];
          detection[field].push(value);
        }
      }
      
      // Handle list items
      const listMatch = line.match(/^\s*-\s*['"]?([^'"]+)['"]?\s*$/);
      if (listMatch) {
        // Add to most recent field (simplified)
        const lastField = Object.keys(detection).pop();
        if (lastField) {
          detection[lastField].push(listMatch[1]);
        }
      }
    }
  }
  
  return Object.keys(detection).length > 0 ? detection : null;
}

/**
 * Build YAML detection block from parsed detection
 */
function buildDetectionYAML(detection, logsource) {
  if (!detection || Object.keys(detection).length === 0) {
    // Fallback placeholder
    return `    placeholder: true  # No detection logic available`;
  }
  
  const lines = [];
  const fieldMappings = logsource.fieldMappings?.[logsource.category] || {};
  
  for (const [field, values] of Object.entries(detection)) {
    // Try to map field to logsource-specific field name
    const mappedField = fieldMappings[field] || field;
    
    if (values.length === 1) {
      lines.push(`    ${mappedField}|contains: '${values[0]}'`);
    } else {
      lines.push(`    ${mappedField}|contains:`);
      for (const v of values.slice(0, 5)) { // Limit to 5 values
        lines.push(`      - '${v}'`);
      }
    }
  }
  
  return lines.join('\n');
}

/**
 * Generate a Sigma rule
 */
function generateSigmaRule(techniqueId, techName, logsource, actor, externalRule) {
  const uuid = generateUUID();
  const now = new Date().toISOString().split('T')[0];
  
  // Parse detection from external rule
  let detection = null;
  let sourceRef = '';
  
  if (externalRule && externalRule.query) {
    detection = parseDetectionFromQuery(externalRule.query, externalRule.source);
    sourceRef = `\n  - ${externalRule.url}`;
  }
  
  const detectionYAML = buildDetectionYAML(detection, logsource);
  
  return `title: ${techName} - ${actor} (${logsource.service})
id: ${uuid}
status: experimental
description: |
  Detects activity consistent with MITRE ATT&CK technique ${techniqueId} (${techName}).
  Associated threat actor: ${actor}
references:
  - https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/${sourceRef}
author: GapMATRIX Sigma Generator
date: ${now}
tags:
  - attack.${techniqueId.toLowerCase()}
  - actor.${actor.toLowerCase().replace(/\s+/g, '_')}
logsource:
  product: ${logsource.product}
  service: ${logsource.service}
  category: ${logsource.category}
detection:
  selection:
${detectionYAML}
  condition: selection
falsepositives:
  - Legitimate administrative activity
  - Authorised security testing
level: medium
`;
}

async function main() {
  console.log('='.repeat(60));
  console.log('Intelligent Sigma Rule Generator');
  console.log('='.repeat(60));
  
  // Load logsources
  console.log('\n[1/5] Loading logsources.json...');
  let logsources = [];
  try {
    const data = JSON.parse(fs.readFileSync('logsources.json', 'utf8'));
    logsources = data.logsources || [];
    console.log(`  ✓ Loaded ${logsources.length} logsources`);
  } catch (err) {
    console.error('  ✗ Failed to load logsources.json:', err.message);
    process.exit(1);
  }
  
  // Load external rules index
  console.log('\n[2/5] Loading external-rules-index.json...');
  let externalRules = {};
  try {
    const data = JSON.parse(fs.readFileSync('external-rules-index.json', 'utf8'));
    externalRules = data.rules || {};
    console.log(`  ✓ Loaded ${Object.keys(externalRules).length} techniques with external rules`);
  } catch (err) {
    console.error('  ✗ Failed to load external-rules-index.json:', err.message);
    process.exit(1);
  }
  
  // Fetch MITRE technique names
  console.log('\n[3/5] Fetching MITRE technique names...');
  let techniqueNames = {};
  try {
    const mitreIndex = await fetchJSON('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/index.json');
    techniqueNames = mitreIndex.techniques || {};
    console.log(`  ✓ Loaded ${Object.keys(techniqueNames).length} technique names`);
  } catch (err) {
    console.warn('  ⚠ Could not fetch MITRE index:', err.message);
  }
  
  // Fetch actor-technique mappings
  console.log('\n[4/5] Fetching actor-technique mappings...');
  const actorTechMap = {};
  
  // MITRE actors
  try {
    const mitreIndex = await fetchJSON('https://raw.githubusercontent.com/EssexRich/mitre_attack/main/data/index.json');
    if (mitreIndex.actors) {
      // This needs the relationships data - simplified for now
      console.log(`  ✓ Found ${Object.keys(mitreIndex.actors).length} MITRE actors`);
    }
  } catch (err) {
    console.warn('  ⚠ Could not fetch MITRE actors');
  }
  
  // Ransomware gangs
  try {
    const ttpIndex = await fetchJSON('https://raw.githubusercontent.com/EssexRich/ThreatActors-TTPs/main/ttp-index.json');
    if (ttpIndex.actors && Array.isArray(ttpIndex.actors)) {
      for (const actor of ttpIndex.actors) {
        if (actor.name && actor.techniques) {
          for (const tech of actor.techniques) {
            if (tech.match(/^T\d+(\.\d+)?$/)) {
              if (!actorTechMap[tech]) actorTechMap[tech] = [];
              if (!actorTechMap[tech].includes(actor.name)) {
                actorTechMap[tech].push(actor.name);
              }
            }
          }
        }
      }
      console.log(`  ✓ Loaded ${ttpIndex.actors.length} ransomware gangs`);
    }
  } catch (err) {
    console.warn('  ⚠ Could not fetch ransomware TTPs:', err.message);
  }
  
  console.log(`  ✓ Total: ${Object.keys(actorTechMap).length} techniques mapped to actors`);
  
  // Generate rules
  console.log('\n[5/5] Generating Sigma rules...');
  const baseDir = path.join(process.cwd(), 'sigma-rules');
  if (fs.existsSync(baseDir)) {
    fs.rmSync(baseDir, { recursive: true });
  }
  fs.mkdirSync(baseDir, { recursive: true });
  
  let totalRules = 0;
  let rulesWithDetection = 0;
  let rulesPlaceholder = 0;
  
  for (const [techniqueId, actors] of Object.entries(actorTechMap)) {
    const techName = techniqueNames[techniqueId] || techniqueId;
    
    for (const logsource of logsources) {
      // Find matching external rules for this technique + logsource
      const matchingRules = findMatchingRules(externalRules, techniqueId, logsource);
      const bestRule = matchingRules[0] || null; // Use first match
      
      for (const actor of actors) {
        const rule = generateSigmaRule(techniqueId, techName, logsource, actor, bestRule);
        
        // Organise by product/service/actor
        const ruleDir = path.join(baseDir, logsource.product, logsource.service, 
          actor.toLowerCase().replace(/\s+/g, '_'));
        
        if (!fs.existsSync(ruleDir)) {
          fs.mkdirSync(ruleDir, { recursive: true });
        }
        
        const filename = `${techniqueId.toLowerCase()}.yml`;
        fs.writeFileSync(path.join(ruleDir, filename), rule);
        
        totalRules++;
        if (bestRule && bestRule.query) {
          rulesWithDetection++;
        } else {
          rulesPlaceholder++;
        }
      }
    }
  }
  
  console.log('\n' + '='.repeat(60));
  console.log('Summary');
  console.log('='.repeat(60));
  console.log(`Total rules generated: ${totalRules}`);
  console.log(`  - With real detection logic: ${rulesWithDetection}`);
  console.log(`  - Placeholder: ${rulesPlaceholder}`);
  console.log(`\nOutput directory: ${baseDir}`);
}

main().catch(err => {
  console.error('FATAL:', err.message);
  process.exit(1);
});
