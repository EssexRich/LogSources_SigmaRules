#!/usr/bin/env node

/**
 * Sigma Rule Organiser v3
 * Organises rules from external-rules-index.json into folder structure
 * No logsources.json needed - infers structure from rule content
 */

const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = process.env.OUTPUT_DIR || './sigma-rules';

/**
 * Classify a rule into product/service based on name, path, query content
 */
function classifyRule(rule) {
  const name = (rule.name || '').toLowerCase();
  const rulePath = (rule.path || '').toLowerCase();
  const query = (rule.query || '').toLowerCase();
  const product = (rule.product || '').toLowerCase();
  const service = (rule.service || '').toLowerCase();
  
  // === MICROSOFT 365 / OFFICE 365 ===
  if (name.includes('o365') || name.includes('office 365') || name.includes('m365') ||
      rulePath.includes('/cloud/o365') || rulePath.includes('/m365/')) {
    
    if (name.includes('exchange') || name.includes('mailbox')) {
      return { product: 'm365', service: 'exchange' };
    }
    if (name.includes('sharepoint')) {
      return { product: 'm365', service: 'sharepoint' };
    }
    if (name.includes('teams')) {
      return { product: 'm365', service: 'teams' };
    }
    if (name.includes('onedrive')) {
      return { product: 'm365', service: 'onedrive' };
    }
    return { product: 'm365', service: 'general' };
  }
  
  // === ENTRA ID / AZURE AD ===
  if (name.includes('entra') || name.includes('azure ad') || name.includes('aad ') ||
      name.includes('azure active directory') || rulePath.includes('azure_ad') ||
      query.includes('signinlogs') || query.includes('auditlogs')) {
    return { product: 'azure', service: 'entra_id' };
  }
  
  // === MICROSOFT DEFENDER PRODUCTS ===
  if (name.includes('defender for endpoint') || name.includes('mde ') || 
      query.includes('deviceprocessevents') || query.includes('devicefilecertificateinfo')) {
    return { product: 'defender', service: 'endpoint' };
  }
  if (name.includes('defender for cloud') || rulePath.includes('defender_for_cloud')) {
    return { product: 'defender', service: 'cloud' };
  }
  if (name.includes('defender for identity') || name.includes('azure atp')) {
    return { product: 'defender', service: 'identity' };
  }
  if (name.includes('microsoft defender') || name.includes('windows defender') ||
      query.includes('alertinfo') || query.includes('alertevidence')) {
    return { product: 'defender', service: 'xdr' };
  }
  
  // === INTUNE ===
  if (name.includes('intune') || rulePath.includes('intune')) {
    return { product: 'azure', service: 'intune' };
  }
  
  // === AZURE (general) ===
  if (product === 'azure' || name.includes('azure') || rulePath.includes('/azure/') ||
      query.includes('azureactivity') || query.includes('azurediagnostics')) {
    return { product: 'azure', service: 'activity_logs' };
  }
  
  // === AWS ===
  if (product === 'aws' || name.includes('aws ') || name.includes('amazon') ||
      rulePath.includes('/aws/') || query.includes('cloudtrail') || query.includes('eventname')) {
    if (query.includes('cloudtrail') || name.includes('cloudtrail')) {
      return { product: 'aws', service: 'cloudtrail' };
    }
    if (name.includes('guardduty')) {
      return { product: 'aws', service: 'guardduty' };
    }
    if (name.includes('s3')) {
      return { product: 'aws', service: 's3' };
    }
    return { product: 'aws', service: 'general' };
  }
  
  // === GCP ===
  if (product === 'gcp' || product === 'cloud' && (name.includes('gcp') || name.includes('google cloud')) ||
      rulePath.includes('/gcp/') || query.includes('protoPayload')) {
    return { product: 'gcp', service: 'audit' };
  }
  
  // === GOOGLE WORKSPACE ===
  if (name.includes('google workspace') || name.includes('gmail') || 
      name.includes('google drive') && !name.includes('windows') ||
      name.includes('google calendar') || rulePath.includes('google_workspace') ||
      query.includes('gmail') || query.includes('workspace_')) {
    return { product: 'google_workspace', service: 'admin' };
  }
  
  // === OKTA ===
  if (product === 'okta' || name.includes('okta') || rulePath.includes('/okta/') ||
      query.includes('eventtype') && query.includes('okta')) {
    return { product: 'okta', service: 'system' };
  }
  
  // === NETWORK ===
  if (product === 'network' || name.includes('firewall') || name.includes('network ') ||
      rulePath.includes('/network/') || service === 'firewall') {
    return { product: 'network', service: 'firewall' };
  }
  
  // === WEB / PROXY ===
  if (product === 'web' || product === 'application' || name.includes('proxy') ||
      name.includes('web server') || rulePath.includes('/web/') || rulePath.includes('/application/')) {
    return { product: 'web', service: 'proxy' };
  }
  
  // === LINUX ===
  if (product === 'linux' || rulePath.includes('/linux/') || 
      query.includes('auditd') || query.includes('syslog') ||
      query.includes('host.os.type') && query.includes('linux')) {
    if (query.includes('auditd') || service === 'auditd') {
      return { product: 'linux', service: 'auditd' };
    }
    if (query.includes('syslog') || service === 'syslog') {
      return { product: 'linux', service: 'syslog' };
    }
    return { product: 'linux', service: 'general' };
  }
  
  // === MACOS ===
  if (product === 'macos' || product === 'osx' || rulePath.includes('/macos/') ||
      query.includes('host.os.type') && query.includes('macos')) {
    return { product: 'macos', service: 'general' };
  }
  
  // === WINDOWS (default for many rules) ===
  if (product === 'windows' || rulePath.includes('/windows/') ||
      query.includes('eventcode') || query.includes('wineventlog') ||
      query.includes('host.os.type') && query.includes('windows')) {
    
    if (query.includes('sysmon') || service === 'sysmon' || rulePath.includes('sysmon')) {
      return { product: 'windows', service: 'sysmon' };
    }
    if (query.includes('powershell') || service === 'powershell' || name.includes('powershell')) {
      return { product: 'windows', service: 'powershell' };
    }
    if (service === 'security' || query.includes('security')) {
      return { product: 'windows', service: 'security' };
    }
    return { product: 'windows', service: 'general' };
  }
  
  // === FALLBACK: try to use existing product/service ===
  if (product && product !== 'unknown') {
    return { product: product, service: service || 'general' };
  }
  
  return null; // Can't classify
}

/**
 * Generate Sigma rule YAML content
 */
function generateSigmaYAML(technique, rule, classification) {
  const yaml = `title: ${rule.name || 'Detection for ' + technique}
id: ${generateUUID(technique + rule.name + rule.source)}
status: stable
description: Detection rule for MITRE ATT&CK technique ${technique}
references:
  - ${rule.url || 'https://attack.mitre.org/techniques/' + technique.replace('.', '/')}
author: ${rule.source} (via IncidentBuddy)
date: ${new Date().toISOString().split('T')[0]}
tags:
  - attack.${technique.toLowerCase()}
logsource:
  product: ${classification.product}
  service: ${classification.service}
detection:
  selection:
    # Original ${rule.source} detection logic
${formatQuery(rule.query)}
  condition: selection
level: medium
`;
  return yaml;
}

/**
 * Format query for YAML (indent and comment)
 */
function formatQuery(query) {
  if (!query) return '    # No detection logic available';
  
  // Truncate very long queries
  if (query.length > 2000) {
    query = query.substring(0, 2000) + '\n... [truncated]';
  }
  
  return query.split('\n')
    .map(line => '    # ' + line)
    .join('\n');
}

/**
 * Generate deterministic UUID from string
 */
function generateUUID(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `${hex.slice(0, 8)}-${hex.slice(0, 4)}-4${hex.slice(1, 4)}-a${hex.slice(1, 4)}-${hex.slice(0, 12).padEnd(12, '0')}`;
}

/**
 * Main function
 */
function main() {
  console.log('='.repeat(60));
  console.log('Sigma Rule Organiser v3');
  console.log('='.repeat(60));
  
  // Load index
  console.log('\n[1/3] Loading external-rules-index.json...');
  const indexPath = path.join(process.cwd(), 'external-rules-index.json');
  if (!fs.existsSync(indexPath)) {
    console.error('ERROR: external-rules-index.json not found');
    process.exit(1);
  }
  const index = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
  const rules = index.rules || {};
  console.log(`  ✓ Loaded ${Object.keys(rules).length} techniques`);
  
  // Process rules
  console.log('\n[2/3] Classifying and organising rules...');
  
  const stats = {
    total: 0,
    byProduct: {},
    byService: {},
    bySource: { elastic: 0, sigma: 0, splunk: 0 },
    unclassified: 0
  };
  
  // Clean output directory
  if (fs.existsSync(OUTPUT_DIR)) {
    fs.rmSync(OUTPUT_DIR, { recursive: true });
  }
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  
  // Process each technique
  for (const [technique, ruleList] of Object.entries(rules)) {
    // Group rules by classification
    const classified = {};
    
    for (const rule of ruleList) {
      const classification = classifyRule(rule);
      if (!classification) {
        stats.unclassified++;
        continue;
      }
      
      const key = `${classification.product}/${classification.service}`;
      if (!classified[key]) {
        classified[key] = { classification, rules: [] };
      }
      classified[key].rules.push(rule);
    }
    
    // Write one rule per product/service for this technique
    for (const [key, data] of Object.entries(classified)) {
      const { classification, rules: matchedRules } = data;
      
      // Pick best rule (prefer sigma, then elastic, then splunk)
      const bestRule = matchedRules.find(r => r.source === 'sigma') ||
                       matchedRules.find(r => r.source === 'elastic') ||
                       matchedRules[0];
      
      // Create directory
      const dir = path.join(OUTPUT_DIR, classification.product, classification.service);
      fs.mkdirSync(dir, { recursive: true });
      
      // Write rule file
      const filename = `${technique.toLowerCase()}.yml`;
      const filepath = path.join(dir, filename);
      const yaml = generateSigmaYAML(technique, bestRule, classification);
      fs.writeFileSync(filepath, yaml);
      
      // Update stats
      stats.total++;
      stats.byProduct[classification.product] = (stats.byProduct[classification.product] || 0) + 1;
      stats.byService[key] = (stats.byService[key] || 0) + 1;
      stats.bySource[bestRule.source] = (stats.bySource[bestRule.source] || 0) + 1;
    }
  }
  
  // Print summary
  console.log('\n[3/3] Done!');
  console.log('\n' + '='.repeat(60));
  console.log('Summary');
  console.log('='.repeat(60));
  console.log(`Total rules created: ${stats.total}`);
  console.log(`Unclassified rules skipped: ${stats.unclassified}`);
  
  console.log('\nBy source:');
  console.log(`  - Elastic: ${stats.bySource.elastic}`);
  console.log(`  - SigmaHQ: ${stats.bySource.sigma}`);
  console.log(`  - Splunk:  ${stats.bySource.splunk}`);
  
  console.log('\nBy product:');
  Object.entries(stats.byProduct)
    .sort((a, b) => b[1] - a[1])
    .forEach(([prod, count]) => {
      console.log(`  - ${prod}: ${count}`);
    });
  
  console.log('\nBy product/service:');
  Object.entries(stats.byService)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .forEach(([svc, count]) => {
      console.log(`  - ${svc}: ${count}`);
    });
  
  console.log(`\nOutput: ${path.resolve(OUTPUT_DIR)}`);
}

main();
