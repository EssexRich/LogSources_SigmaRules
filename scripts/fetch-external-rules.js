#!/usr/bin/env node

/**
 * Fetch detection rules from external repos using GitHub Tree API
 * Maps technique IDs to actual detection logic from:
 * - Elastic detection-rules (TOML)
 * - Splunk security_content (YAML)
 * - SigmaHQ sigma (YAML)
 * 
 * Outputs: external-rules-index.json
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';

function fetchURL(url) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const headers = {
      'User-Agent': 'GapMATRIX-SigmaGen/1.0'
    };
    
    // Add auth for api.github.com requests if token available
    if (urlObj.hostname === 'api.github.com' && GITHUB_TOKEN) {
      headers['Authorization'] = `Bearer ${GITHUB_TOKEN}`;
    }
    
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      headers
    };

    https.get(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode === 200) {
          resolve(data);
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${url}`));
        }
      });
    }).on('error', reject);
  });
}

async function fetchJSON(url) {
  const data = await fetchURL(url);
  return JSON.parse(data);
}

// Rate limit helper
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Get all files from a GitHub repo using the Tree API (single request)
 */
async function getRepoTree(owner, repo, branch = 'main') {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;
  console.log(`[Tree] Fetching ${owner}/${repo}...`);
  
  const tree = await fetchJSON(url);
  return tree.tree || [];
}

/**
 * Extract technique IDs from Elastic TOML content
 */
function extractFromTOML(content, filePath) {
  const techniques = [];
  
  // Match technique IDs: id = "T1190"
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
  
  // Extract logsource info from index patterns
  const indexMatch = content.match(/index\s*=\s*\[([\s\S]*?)\]/);
  let product = 'unknown';
  if (indexMatch) {
    const indices = indexMatch[1].toLowerCase();
    if (indices.includes('windows') || indices.includes('winlog')) product = 'windows';
    else if (indices.includes('linux') || indices.includes('auditbeat')) product = 'linux';
    else if (indices.includes('macos')) product = 'macos';
    else if (indices.includes('cloud') || indices.includes('azure') || indices.includes('gcp') || indices.includes('aws')) product = 'cloud';
  }
  
  return {
    techniques: [...new Set(techniques)],
    query,
    name,
    product,
    path: filePath
  };
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
  
  // Direct T-number references
  const directMatches = content.matchAll(/[^a-zA-Z](T\d{4}(?:\.\d{3})?)[^0-9]/g);
  for (const match of directMatches) {
    techniques.push(match[1]);
  }
  
  // Extract detection block
  const detectionMatch = content.match(/detection:\s*\n((?:[ \t]+[^\n]*\n?)*)/);
  const query = detectionMatch ? detectionMatch[1] : null;
  
  // Extract title
  const titleMatch = content.match(/title:\s*(.+)/i);
  const name = titleMatch ? titleMatch[1].trim().replace(/^['"]|['"]$/g, '') : path.basename(filePath);
  
  // Extract logsource product
  const productMatch = content.match(/product:\s*(\w+)/i);
  const product = productMatch ? productMatch[1].toLowerCase() : 'unknown';
  
  // Extract logsource service
  const serviceMatch = content.match(/service:\s*(\w+)/i);
  const service = serviceMatch ? serviceMatch[1].toLowerCase() : null;
  
  // Extract logsource category
  const categoryMatch = content.match(/category:\s*(\w+)/i);
  const category = categoryMatch ? categoryMatch[1].toLowerCase() : null;
  
  return {
    techniques: [...new Set(techniques)],
    query,
    name,
    product,
    service,
    category,
    path: filePath
  };
}

/**
 * Fetch rules from Elastic detection-rules repo
 */
async function fetchElasticRules() {
  console.log('\n[Elastic] Fetching detection-rules...');
  const rules = {};
  
  try {
    const tree = await getRepoTree('elastic', 'detection-rules', 'main');
    const tomlFiles = tree.filter(f => 
      f.path.startsWith('rules/') && 
      f.path.endsWith('.toml') &&
      f.type === 'blob'
    );
    
    console.log(`[Elastic] Found ${tomlFiles.length} rule files`);
    
    let processed = 0;
    for (const file of tomlFiles) {
      try {
        const url = `https://raw.githubusercontent.com/elastic/detection-rules/main/${file.path}`;
        const content = await fetchURL(url);
        const parsed = extractFromTOML(content, file.path);
        
        for (const tech of parsed.techniques) {
          if (!rules[tech]) rules[tech] = [];
          rules[tech].push({
            source: 'elastic',
            name: parsed.name,
            product: parsed.product,
            path: file.path,
            url: `https://github.com/elastic/detection-rules/blob/main/${file.path}`,
            query: parsed.query
          });
        }
        
        processed++;
        if (processed % 50 === 0) {
          console.log(`[Elastic] Processed ${processed}/${tomlFiles.length}`);
          await delay(100); // Small delay to be nice
        }
      } catch (err) {
        // Skip failed files silently
      }
    }
    
    console.log(`[Elastic] ✓ ${Object.keys(rules).length} techniques, ${processed} rules`);
  } catch (err) {
    console.error(`[Elastic] Error: ${err.message}`);
  }
  
  return rules;
}

/**
 * Fetch rules from SigmaHQ repo
 */
async function fetchSigmaRules() {
  console.log('\n[SigmaHQ] Fetching sigma rules...');
  const rules = {};
  
  try {
    const tree = await getRepoTree('SigmaHQ', 'sigma', 'master');
    const yamlFiles = tree.filter(f => 
      f.path.startsWith('rules/') && 
      f.path.endsWith('.yml') &&
      f.type === 'blob'
    );
    
    console.log(`[SigmaHQ] Found ${yamlFiles.length} rule files`);
    
    let processed = 0;
    for (const file of yamlFiles) {
      try {
        const url = `https://raw.githubusercontent.com/SigmaHQ/sigma/master/${file.path}`;
        const content = await fetchURL(url);
        const parsed = extractFromYAML(content, file.path);
        
        for (const tech of parsed.techniques) {
          if (!rules[tech]) rules[tech] = [];
          rules[tech].push({
            source: 'sigma',
            name: parsed.name,
            product: parsed.product,
            service: parsed.service,
            category: parsed.category,
            path: file.path,
            url: `https://github.com/SigmaHQ/sigma/blob/master/${file.path}`,
            query: parsed.query
          });
        }
        
        processed++;
        if (processed % 100 === 0) {
          console.log(`[SigmaHQ] Processed ${processed}/${yamlFiles.length}`);
          await delay(50);
        }
      } catch (err) {
        // Skip failed files
      }
    }
    
    console.log(`[SigmaHQ] ✓ ${Object.keys(rules).length} techniques, ${processed} rules`);
  } catch (err) {
    console.error(`[SigmaHQ] Error: ${err.message}`);
  }
  
  return rules;
}

/**
 * Fetch rules from Splunk security_content repo
 */
async function fetchSplunkRules() {
  console.log('\n[Splunk] Fetching security_content...');
  const rules = {};
  
  try {
    const tree = await getRepoTree('splunk', 'security_content', 'develop');
    const yamlFiles = tree.filter(f => 
      f.path.startsWith('detections/') && 
      f.path.endsWith('.yml') &&
      f.type === 'blob'
    );
    
    console.log(`[Splunk] Found ${yamlFiles.length} rule files`);
    
    let processed = 0;
    for (const file of yamlFiles) {
      try {
        const url = `https://raw.githubusercontent.com/splunk/security_content/develop/${file.path}`;
        const content = await fetchURL(url);
        const parsed = extractFromYAML(content, file.path);
        
        for (const tech of parsed.techniques) {
          if (!rules[tech]) rules[tech] = [];
          rules[tech].push({
            source: 'splunk',
            name: parsed.name,
            product: parsed.product,
            service: parsed.service,
            category: parsed.category,
            path: file.path,
            url: `https://github.com/splunk/security_content/blob/develop/${file.path}`,
            query: parsed.query
          });
        }
        
        processed++;
        if (processed % 50 === 0) {
          console.log(`[Splunk] Processed ${processed}/${yamlFiles.length}`);
          await delay(100);
        }
      } catch (err) {
        // Skip failed files
      }
    }
    
    console.log(`[Splunk] ✓ ${Object.keys(rules).length} techniques, ${processed} rules`);
  } catch (err) {
    console.error(`[Splunk] Error: ${err.message}`);
  }
  
  return rules;
}

/**
 * Merge all rule sets
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

async function main() {
  console.log('='.repeat(60));
  console.log('External Detection Rules Fetcher');
  console.log('='.repeat(60));
  console.log(`GitHub Token: ${GITHUB_TOKEN ? 'present' : 'not set (using unauthenticated)'}`);
  
  const elasticRules = await fetchElasticRules();
  const sigmaRules = await fetchSigmaRules();
  const splunkRules = await fetchSplunkRules();
  
  const allRules = mergeRules(elasticRules, sigmaRules, splunkRules);
  
  // Stats
  let totalRules = 0;
  for (const ruleList of Object.values(allRules)) {
    totalRules += ruleList.length;
  }
  
  const stats = {
    generated: new Date().toISOString(),
    techniques: Object.keys(allRules).length,
    totalRules,
    sources: {
      elastic: Object.keys(elasticRules).length,
      sigma: Object.keys(sigmaRules).length,
      splunk: Object.keys(splunkRules).length
    }
  };
  
  console.log('\n' + '='.repeat(60));
  console.log('Summary');
  console.log('='.repeat(60));
  console.log(`Total techniques: ${stats.techniques}`);
  console.log(`Total rules: ${stats.totalRules}`);
  console.log(`  - Elastic: ${stats.sources.elastic} techniques`);
  console.log(`  - SigmaHQ: ${stats.sources.sigma} techniques`);
  console.log(`  - Splunk: ${stats.sources.splunk} techniques`);
  
  // Output
  const output = {
    _meta: stats,
    rules: allRules
  };
  
  const outputPath = path.join(process.cwd(), 'external-rules-index.json');
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));
  console.log(`\n✓ Saved to ${outputPath}`);
}

main().catch(err => {
  console.error('FATAL:', err.message);
  process.exit(1);
});
