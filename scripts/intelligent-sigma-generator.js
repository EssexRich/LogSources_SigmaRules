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

function isTechniqueRelevantToLogsource(techniqueId, techName, logsource) {
  // Comprehensive mapping of techniques to relevant logsource categories
  // Based on MITRE ATT&CK technique detection methods
  
  const techniqueToLogsource = {
    // PROCESS CREATION - Observable: process execution, command line arguments
    'process_creation': [
      // Command Execution & Scripting
      /T1059|T1651|T1648|T1059\.001|T1059\.002|T1059\.003|T1059\.004|T1059\.005|T1059\.006|T1059\.007|T1059\.008/,
      // Living off the Land Binaries
      /T1218|T1218\.001|T1218\.002|T1218\.003|T1218\.004|T1218\.005|T1218\.007|T1218\.008|T1218\.009|T1218\.010|T1218\.011|T1218\.012|T1218\.013/,
      // Execution
      /T1047|T1106|T1053|T1129|T1559|T1559\.001|T1559\.002/,
      // Process Hollowing & Code Injection
      /T1622|T1574|T1574\.001|T1574\.002|T1574\.004|T1574\.008|T1574\.010|T1574\.011|T1574\.012|T1574\.013/,
      // Lateral Movement via process
      /T1570|T1021|T1021\.001|T1021\.002|T1021\.003|T1021\.004|T1021\.005|T1021\.006/,
      // Privilege Escalation via process
      /T1547|T1547\.001|T1547\.002|T1547\.003|T1547\.004|T1547\.005|T1547\.006|T1547\.007|T1547\.008|T1547\.009|T1547\.010|T1547\.011|T1547\.012|T1547\.013|T1547\.014/,
      // Persistence via execution
      /T1543|T1543\.001|T1543\.002|T1543\.003|T1543\.004/,
      // Defense Evasion via process
      /T1140|T1036|T1036\.001|T1036\.002|T1036\.003|T1036\.004|T1036\.005|T1036\.006|T1036\.007|T1036\.008|T1036\.009/,
      // Process Access & Injection
      /T1057|T1556|T1003|T1003\.001|T1003\.002|T1003\.003|T1003\.004|T1003\.005|T1003\.006|T1003\.007|T1003\.008/,
      // Parent PID Spoofing
      /T1134|T1134\.001|T1134\.002|T1134\.003|T1134\.004|T1134\.005/,
      // Scheduled Tasks & Cron
      /T1053|T1053\.001|T1053\.002|T1053\.005|T1053\.006/,
      // Exploitation for Privilege Escalation
      /T1548|T1548\.001|T1548\.002|T1548\.003|T1548\.004/,
    ],
    
    // AUTHENTICATION - Observable: login attempts, failed auth, privilege elevation
    'authentication': [
      // Credential Access
      /T1110|T1110\.001|T1110\.002|T1110\.003|T1110\.004/,  // Brute Force
      /T1187|T1040|T1056|T1056\.001|T1056\.002|T1056\.003|T1056\.004/,  // Spearphishing, Sniffing, Keylogging
      /T1056|T1598|T1598\.001|T1598\.002|T1598\.003|T1598\.004/,  // Phishing
      /T1111|T1040|T1557|T1557\.001|T1557\.002/,  // Screen Capture, Sniffing, MITM
      /T1040|T1187|T1040/,  // Network Sniffing, Spearphishing
      /T1557|T1557\.001|T1557\.002|T1040/,  // Man in the Middle
      // Valid Accounts / Credential Use
      /T1078|T1078\.001|T1078\.002|T1078\.003|T1078\.004/,  // Valid Accounts
      /T1556|T1550|T1550\.001|T1550\.002|T1550\.003|T1550\.004/,  // Use Alternate Auth
      /T1552|T1552\.001|T1552\.002|T1552\.005|T1552\.007/,  // Unsecured Credentials
      // Multi-factor Failures
      /T1621|T1111|T1056\.004/,  // MFA Failures
    ],
    
    // ADMIN ACTIVITY - Observable: M365/Cloud admin actions, privilege changes
    'admin_activity': [
      // Account Manipulation
      /T1098|T1098\.001|T1098\.002|T1098\.003|T1098\.004|T1098\.005/,
      // Privilege Escalation (domain/cloud level)
      /T1547|T1548|T1134|T1484|T1484\.001|T1484\.002/,  // Bootkit, UAC Bypass, Domain Trust Modification
      // Cloud / Azure specific
      /T1556|T1537|T1538|T1526|T1526\.001|T1199/,  // OAuth, Lateral Movement cloud, Data from Cloud
      // Permission Groups Discovery
      /T1069|T1069\.001|T1069\.002|T1069\.003/,
      // Domain Trust Discovery
      /T1482|T1087|T1087\.001|T1087\.002|T1087\.003|T1087\.004/,
      // Password Policy Discovery
      /T1201|T1526|T1580/,
      // Modify Authentication Process
      /T1556|T1098|T1556\.001|T1556\.002|T1556\.003|T1556\.004|T1556\.005/,
    ],
    
    // NETWORK CONNECTION - Observable: outbound connections, C2 traffic, DNS
    'network_connection': [
      // Command & Control
      /T1071|T1071\.001|T1071\.002|T1071\.003|T1071\.004/,  // Application Layer Protocol
      /T1008|T1001|T1568|T1568\.001|T1568\.002|T1568\.003/,  // Fallback Channels, Data Obfuscation, Dynamic Resolution
      /T1573|T1573\.001|T1573\.002/,  // Encrypted Channel
      /T1090|T1090\.001|T1090\.002|T1090\.003|T1090\.004/,  // Proxy
      /T1205|T1205\.001|T1205\.002/,  // Traffic Signaling
      // Exfiltration
      /T1041|T1048|T1048\.001|T1048\.002|T1048\.003/,  // Exfiltration over C2, Over Alternative Protocol
      /T1020|T1030|T1537/,  // Automated Exfiltration, Data Transfer
      /T1567|T1567\.001|T1567\.002/,  // Exfiltration Over Web Service
      // Lateral Movement
      /T1570|T1021|T1021\.001|T1021\.002|T1021\.004|T1021\.005|T1021\.006|T1021\.007/,
      // Discovery
      /T1046|T1040|T1087|T1010|T1217|T1580|T1538|T1526|T1592|T1590|T1598|T1597/,  // Network Service Discovery, Network Sniffing
    ],
    
    // DNS QUERY - Observable: DNS queries, domain resolution
    'dns_query': [
      // C2 via DNS
      /T1071\.004|T1568\.002|T1008|T1090|T1090\.001|T1090\.002/,
      // Domain Fronting
      /T1172|T1008|T1568/,
      // Data Exfiltration via DNS
      /T1041|T1048|T1020/,
      // Discovery
      /T1046|T1087|T1217|T1580|T1526/,
    ],
    
    // FILE CREATION - Observable: file writes, encryption, staging
    'file_event': [
      // Ransomware / Data Destruction
      /T1486|T1565|T1565\.001|T1565\.002|T1565\.003|T1561|T1561\.001|T1561\.002|T1487/,
      // Staging / Exfiltration Prep
      /T1074|T1074\.001|T1074\.002|T1537|T1020/,
      // Persistence
      /T1543|T1547|T1037|T1547\.001|T1547\.014|T1136|T1543\.001|T1543\.003/,
      // Defense Evasion
      /T1140|T1036|T1036\.001|T1036\.005|T1036\.009|T1027|T1027\.001|T1027\.002|T1027\.003|T1027\.004|T1027\.005|T1027\.006|T1027\.007|T1027\.008|T1027\.009|T1027\.010|T1027\.011/,
      // Hidden Files
      /T1564|T1564\.001|T1564\.004|T1564\.010|T1564\.012/,
      // Data from Local System
      /T1005|T1123|T1119|T1115|T1530|T1602|T1213|T1005/,
    ],
    
    // IMAGE LOAD - Observable: DLL loading, code injection, driver loading
    'image_load': [
      // Code Injection & Process Hollowing
      /T1574|T1574\.001|T1574\.002|T1574\.004|T1574\.008|T1574\.010|T1574\.011|T1574\.012|T1574\.013/,
      // Persistence via DLL
      /T1547|T1547\.003|T1103/,
      // Defense Evasion
      /T1036|T1574|T1036\.005|T1036\.009|T1027|T1027\.001|T1027\.002|T1027\.003|T1027\.004|T1027\.005|T1027\.006|T1027\.007|T1027\.008|T1027\.009|T1027\.010|T1027\.011/,
      // Driver Loading / Rootkit
      /T1547\.006|T1547\.008/,
    ],
  };

  const logsourceCategory = logsource.category;
  const patterns = techniqueToLogsource[logsourceCategory];
  
  if (!patterns || !Array.isArray(patterns)) {
    // Unknown logsource category - don't skip
    return true;
  }

  // Check if technique matches ANY of the patterns for this logsource
  return patterns.some(pattern => pattern.test(techniqueId));
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
      // Skip if technique isn't relevant to this logsource type
      if (!isTechniqueRelevantToLogsource(techniqueId, techName, logsource)) {
        return;
      }

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
