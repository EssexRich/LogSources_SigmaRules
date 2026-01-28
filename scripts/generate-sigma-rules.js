#!/usr/bin/env node

/**
 * Sigma Rule Organiser
 * 
 * Copies the best matching external rule for each technique/logsource combination
 * into an organised folder structure: /[product]/[service]/[t-number].yml
 */

const fs = require('fs');
const path = require('path');

function main() {
  console.log('='.repeat(60));
  console.log('Sigma Rule Organiser');
  console.log('='.repeat(60));
  
  // Load logsources
  console.log('\n[1/3] Loading logsources.json...');
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
  console.log('\n[2/3] Loading external-rules-index.json...');
  let externalRules = {};
  try {
    const data = JSON.parse(fs.readFileSync('external-rules-index.json', 'utf8'));
    externalRules = data.rules || {};
    console.log(`  ✓ Loaded ${Object.keys(externalRules).length} techniques`);
  } catch (err) {
    console.error('  ✗ Failed to load external-rules-index.json:', err.message);
    process.exit(1);
  }
  
  // Organise rules
  console.log('\n[3/3] Organising rules...');
  const baseDir = path.join(process.cwd(), 'sigma-rules');
  if (fs.existsSync(baseDir)) {
    fs.rmSync(baseDir, { recursive: true });
  }
  fs.mkdirSync(baseDir, { recursive: true });
  
  const stats = {
    total: 0,
    bySource: { elastic: 0, sigma: 0, splunk: 0 },
    byProduct: {},
    noMatch: 0
  };
  
  // For each logsource
  for (const logsource of logsources) {
    const productDir = path.join(baseDir, logsource.product, logsource.service);
    fs.mkdirSync(productDir, { recursive: true });
    
    if (!stats.byProduct[logsource.product]) {
      stats.byProduct[logsource.product] = 0;
    }
    
    // For each technique
    for (const [techniqueId, rules] of Object.entries(externalRules)) {
      // Find best matching rule for this logsource
      const match = findBestMatch(rules, logsource);
      
      if (match) {
        // Build the rule file
        const ruleContent = buildRuleFile(techniqueId, match, logsource);
        const filename = `${techniqueId.toLowerCase()}.yml`;
        fs.writeFileSync(path.join(productDir, filename), ruleContent);
        
        stats.total++;
        stats.bySource[match.source]++;
        stats.byProduct[logsource.product]++;
      }
    }
  }
  
  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('Summary');
  console.log('='.repeat(60));
  console.log(`Total rules created: ${stats.total}`);
  console.log('\nBy source:');
  console.log(`  - Elastic: ${stats.bySource.elastic}`);
  console.log(`  - SigmaHQ: ${stats.bySource.sigma}`);
  console.log(`  - Splunk:  ${stats.bySource.splunk}`);
  console.log('\nBy product:');
  for (const [product, count] of Object.entries(stats.byProduct)) {
    console.log(`  - ${product}: ${count}`);
  }
  console.log(`\nOutput: ${baseDir}`);
}

/**
 * Find the best matching rule for a logsource
 */
function findBestMatch(rules, logsource) {
  // Strict match: product + category must match
  const matches = rules.filter(rule => {
    // Must have explicit product
    if (!rule.product || rule.product === 'unknown') return false;
    
    // Product must match
    if (rule.product !== logsource.product) return false;
    
    // Category must match if specified
    if (rule.category && rule.category !== logsource.category) return false;
    
    // Sanity check: rule query shouldn't reference wrong products
    if (rule.query) {
      const q = rule.query.toLowerCase();
      // Skip rules that are clearly for wrong product
      if (logsource.product === 'linux' && (q.includes('google_workspace') || q.includes('windows'))) return false;
      if (logsource.product === 'windows' && q.includes('google_workspace')) return false;
      if (logsource.product === 'macos' && (q.includes('google_workspace') || q.includes('windows'))) return false;
    }
    
    return true;
  });
  
  if (matches.length === 0) return null;
  
  // Prefer service match
  const serviceMatch = matches.find(r => r.service === logsource.service);
  if (serviceMatch) return serviceMatch;
  
  // Prefer Sigma rules (native format), then Elastic, then Splunk
  const sigmaMatch = matches.find(r => r.source === 'sigma');
  if (sigmaMatch) return sigmaMatch;
  
  const elasticMatch = matches.find(r => r.source === 'elastic');
  if (elasticMatch) return elasticMatch;
  
  return matches[0];
}

/**
 * Build a Sigma rule file from the external rule
 */
function buildRuleFile(techniqueId, rule, logsource) {
  const now = new Date().toISOString().split('T')[0];
  
  // If it's a Sigma rule, we can use the query directly as detection
  // Otherwise we need to convert
  let detection = buildDetection(rule);
  
  return `title: ${rule.name}
id: ${generateUUID()}
status: experimental
description: |
  Detection for MITRE ATT&CK technique ${techniqueId}.
  Original source: ${rule.source}
references:
  - https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/
  - ${rule.url}
author: GapMATRIX (sourced from ${rule.source})
date: ${now}
tags:
  - attack.${techniqueId.toLowerCase()}
logsource:
  product: ${logsource.product}
  service: ${logsource.service}
  category: ${logsource.category}
detection:
${detection}
  condition: selection
falsepositives:
  - Legitimate administrative activity
level: medium
`;
}

/**
 * Build detection block from rule query
 */
function buildDetection(rule) {
  if (!rule.query) {
    return '  selection:\n    placeholder: true';
  }
  
  // For Sigma rules, query is already YAML-ish detection block
  if (rule.source === 'sigma') {
    // Indent and return
    const lines = rule.query.split('\n').map(l => '  ' + l);
    return lines.join('\n');
  }
  
  // For Elastic/Splunk, parse the query into Sigma format
  const fields = parseQuery(rule.query, rule.source);
  
  if (Object.keys(fields).length === 0) {
    return '  selection:\n    placeholder: true';
  }
  
  let yaml = '  selection:\n';
  for (const [field, values] of Object.entries(fields)) {
    if (values.length === 1) {
      yaml += `    ${field}: '${escapeYaml(values[0])}'\n`;
    } else {
      yaml += `    ${field}:\n`;
      for (const v of values) {
        yaml += `      - '${escapeYaml(v)}'\n`;
      }
    }
  }
  
  return yaml.trimEnd();
}

/**
 * Parse Elastic/Splunk query into field:value pairs
 */
function parseQuery(query, source) {
  const fields = {};
  
  if (source === 'elastic') {
    // Match: field : "value" or field : ("val1", "val2")
    const matches = query.matchAll(/(\w+(?:\.\w+)*)\s*:\s*(?:\(\s*)?["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])*(?:\s*\))?/g);
    for (const match of matches) {
      const field = match[1];
      if (!fields[field]) fields[field] = [];
      fields[field].push(match[2]);
      if (match[3]) fields[field].push(match[3]);
    }
    
    // Match wildcards: field : *pattern*
    const wildcardMatches = query.matchAll(/(\w+(?:\.\w+)*)\s*:\s*\*?([^"'\s\)]+)\*?/g);
    for (const match of wildcardMatches) {
      const field = match[1];
      const value = match[2];
      if (value && !value.includes(':') && !fields[field]) {
        fields[field] = [value];
      }
    }
  } else if (source === 'splunk') {
    // Match: field=value or field="value"
    const matches = query.matchAll(/(\w+)\s*=\s*["']?([^"'\s|]+)["']?/g);
    for (const match of matches) {
      const field = match[1];
      if (!fields[field]) fields[field] = [];
      fields[field].push(match[2]);
    }
  }
  
  return fields;
}

function escapeYaml(str) {
  return str.replace(/'/g, "''");
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

main();
