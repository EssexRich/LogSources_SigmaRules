#!/usr/bin/env node

/**
 * Parse detection rules from locally cloned repos
 * Usage: node fetch-external-rules.js /path/to/cloned/repos
 */

const fs = require('fs');
const path = require('path');

const reposDir = process.argv[2] || '/tmp/external-repos';

/**
 * Recursively find files matching a pattern
 */
function findFiles(dir, pattern, results = []) {
  if (!fs.existsSync(dir)) return results;
  
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      findFiles(fullPath, pattern, results);
    } else if (pattern.test(entry.name)) {
      results.push(fullPath);
    }
  }
  return results;
}

/**
 * Extract technique IDs from Elastic TOML content
 */
function extractFromTOML(content, filePath) {
  const techniques = [];
  
  // Match technique IDs
  const techMatches = content.matchAll(/\[\[rule\.threat\.technique\]\][^[]*?id\s*=\s*"(T\d+(?:\.\d+)?)"/gs);
  for (const match of techMatches) {
    techniques.push(match[1]);
  }
  
  // Subtechniques
  const subMatches = content.matchAll(/\[\[rule\.threat\.technique\.subtechnique\]\][^[]*?id\s*=\s*"(T\d+\.\d+)"/gs);
  for (const match of subMatches) {
    techniques.push(match[1]);
  }
  
  // Extract query
  const queryMatch = content.match(/query\s*=\s*'''([\s\S]*?)'''/);
  const query = queryMatch ? queryMatch[1].trim() : null;
  
  // Extract name
  const nameMatch = content.match(/name\s*=\s*"([^"]+)"/);
  const name = nameMatch ? nameMatch[1] : path.basename(filePath);
  
  // Determine product from path
  let product = 'unknown';
  if (filePath.includes('/windows/')) product = 'windows';
  else if (filePath.includes('/linux/')) product = 'linux';
  else if (filePath.includes('/macos/')) product = 'macos';
  else if (filePath.includes('/cloud/') || filePath.includes('/azure/') || filePath.includes('/gcp/') || filePath.includes('/aws/')) product = 'cloud';
  
  return { techniques: [...new Set(techniques)], query, name, product };
}

/**
 * Extract technique IDs from Sigma/Splunk YAML content
 */
function extractFromYAML(content, filePath) {
  const techniques = [];
  
  // Match attack.tXXXX tags
  const tagMatches = content.matchAll(/attack\.t(\d+(?:\.\d+)?)/gi);
  for (const match of tagMatches) {
    techniques.push(`T${match[1].toUpperCase()}`);
  }
  
  // Direct T-number references in tags section
  const directMatches = content.matchAll(/[^a-zA-Z](T\d{4}(?:\.\d{3})?)[^0-9]/g);
  for (const match of directMatches) {
    techniques.push(match[1]);
  }
  
  // Extract detection block
  const detectionMatch = content.match(/detection:\s*\n((?:[ \t]+[^\n]*\n?)*)/);
  const query = detectionMatch ? detectionMatch[1] : null;
  
  // Extract title
  const titleMatch = content.match(/title:\s*['"]?([^'"\n]+)['"]?/i);
  const name = titleMatch ? titleMatch[1].trim() : path.basename(filePath);
  
  // Extract logsource
  const productMatch = content.match(/product:\s*(\w+)/i);
  const product = productMatch ? productMatch[1].toLowerCase() : 'unknown';
  
  const serviceMatch = content.match(/service:\s*(\w+)/i);
  const service = serviceMatch ? serviceMatch[1].toLowerCase() : null;
  
  const categoryMatch = content.match(/category:\s*(\w+)/i);
  const category = categoryMatch ? categoryMatch[1].toLowerCase() : null;
  
  return { techniques: [...new Set(techniques)], query, name, product, service, category };
}

/**
 * Process Elastic rules
 */
function processElastic(reposDir) {
  console.log('\n[Elastic] Processing detection-rules...');
  const rules = {};
  
  const rulesDir = path.join(reposDir, 'detection-rules', 'rules');
  const files = findFiles(rulesDir, /\.toml$/);
  console.log(`[Elastic] Found ${files.length} TOML files`);
  
  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const parsed = extractFromTOML(content, file);
      const relativePath = file.replace(reposDir + '/detection-rules/', '');
      
      for (const tech of parsed.techniques) {
        if (!rules[tech]) rules[tech] = [];
        rules[tech].push({
          source: 'elastic',
          name: parsed.name,
          product: parsed.product,
          path: relativePath,
          url: `https://github.com/elastic/detection-rules/blob/main/${relativePath}`,
          query: parsed.query
        });
      }
    } catch (err) {
      // Skip unreadable files
    }
  }
  
  console.log(`[Elastic] ✓ ${Object.keys(rules).length} techniques`);
  return rules;
}

/**
 * Process SigmaHQ rules
 */
function processSigma(reposDir) {
  console.log('\n[SigmaHQ] Processing sigma rules...');
  const rules = {};
  
  const rulesDir = path.join(reposDir, 'sigma', 'rules');
  const files = findFiles(rulesDir, /\.yml$/);
  console.log(`[SigmaHQ] Found ${files.length} YAML files`);
  
  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const parsed = extractFromYAML(content, file);
      const relativePath = file.replace(reposDir + '/sigma/', '');
      
      for (const tech of parsed.techniques) {
        if (!rules[tech]) rules[tech] = [];
        rules[tech].push({
          source: 'sigma',
          name: parsed.name,
          product: parsed.product,
          service: parsed.service,
          category: parsed.category,
          path: relativePath,
          url: `https://github.com/SigmaHQ/sigma/blob/master/${relativePath}`,
          query: parsed.query
        });
      }
    } catch (err) {
      // Skip
    }
  }
  
  console.log(`[SigmaHQ] ✓ ${Object.keys(rules).length} techniques`);
  return rules;
}

/**
 * Process Splunk rules
 */
function processSplunk(reposDir) {
  console.log('\n[Splunk] Processing security_content...');
  const rules = {};
  
  const detectionsDir = path.join(reposDir, 'security_content', 'detections');
  const files = findFiles(detectionsDir, /\.yml$/);
  console.log(`[Splunk] Found ${files.length} YAML files`);
  
  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const parsed = extractFromYAML(content, file);
      const relativePath = file.replace(reposDir + '/security_content/', '');
      
      for (const tech of parsed.techniques) {
        if (!rules[tech]) rules[tech] = [];
        rules[tech].push({
          source: 'splunk',
          name: parsed.name,
          product: parsed.product,
          service: parsed.service,
          category: parsed.category,
          path: relativePath,
          url: `https://github.com/splunk/security_content/blob/develop/${relativePath}`,
          query: parsed.query
        });
      }
    } catch (err) {
      // Skip
    }
  }
  
  console.log(`[Splunk] ✓ ${Object.keys(rules).length} techniques`);
  return rules;
}

/**
 * Merge and sort rules
 */
function mergeRules(...ruleSets) {
  const merged = {};
  
  for (const rules of ruleSets) {
    for (const [tech, ruleList] of Object.entries(rules)) {
      if (!merged[tech]) merged[tech] = [];
      merged[tech].push(...ruleList);
    }
  }
  
  // Sort by technique ID
  const sorted = {};
  Object.keys(merged).sort().forEach(key => {
    sorted[key] = merged[key];
  });
  
  return sorted;
}

function main() {
  console.log('='.repeat(60));
  console.log('External Detection Rules Parser');
  console.log('='.repeat(60));
  console.log(`Repos directory: ${reposDir}`);
  
  const elasticRules = processElastic(reposDir);
  const sigmaRules = processSigma(reposDir);
  const splunkRules = processSplunk(reposDir);
  
  const allRules = mergeRules(elasticRules, sigmaRules, splunkRules);
  
  // Stats
  let totalRules = 0;
  for (const ruleList of Object.values(allRules)) {
    totalRules += ruleList.length;
  }
  
  const output = {
    _meta: {
      generated: new Date().toISOString(),
      techniques: Object.keys(allRules).length,
      totalRules,
      sources: {
        elastic: Object.keys(elasticRules).length,
        sigma: Object.keys(sigmaRules).length,
        splunk: Object.keys(splunkRules).length
      }
    },
    rules: allRules
  };
  
  console.log('\n' + '='.repeat(60));
  console.log('Summary');
  console.log('='.repeat(60));
  console.log(`Total techniques: ${output._meta.techniques}`);
  console.log(`Total rules: ${output._meta.totalRules}`);
  console.log(`  - Elastic: ${output._meta.sources.elastic} techniques`);
  console.log(`  - SigmaHQ: ${output._meta.sources.sigma} techniques`);
  console.log(`  - Splunk: ${output._meta.sources.splunk} techniques`);
  
  const outputPath = path.join(process.cwd(), 'external-rules-index.json');
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));
  console.log(`\n✓ Saved to ${outputPath}`);
}

main();
