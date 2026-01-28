#!/usr/bin/env node

/**
 * scripts/generate-logsources.js
 * 
 * Generates logsources.json from product documentation via Claude AI
 * and creates Sigma detection rules for all MITRE ATT&CK techniques
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

const LOGSOURCES_FILE = path.join(__dirname, '..', 'logsources.json');
const SIGMA_RULES_DIR = path.join(__dirname, '..', 'sigma-rules');

// Ensure sigma-rules directory exists
if (!fs.existsSync(SIGMA_RULES_DIR)) {
  fs.mkdirSync(SIGMA_RULES_DIR, { recursive: true });
}

/**
 * Fetch product documentation and extract field mappings via Claude
 */
async function generateLogsourcesFromDocs(anthropicToken) {
  console.log('[LogSources] Starting logsource generation...');
  
  const products = [
    'Windows Event Log Security',
    'Sysmon',
    'Linux auditd',
    'macOS Unified Logging',
    'Microsoft Defender',
    'Microsoft Entra ID',
    'Google Workspace',
    'CrowdStrike Falcon',
    'SentinelOne',
    'Elastic EDR'
  ];
  
  const logsources = [];
  let skipped = 0;
  
  for (const product of products) {
    try {
      console.log(`[LogSources] Processing: ${product}`);
      
      const logsource = await fetchAndParseLogsource(product, anthropicToken);
      
      if (logsource) {
        logsources.push(logsource);
      } else {
        skipped++;
      }
    } catch (error) {
      console.error(`[LogSources] Error processing ${product}:`, error.message);
      skipped++;
    }
  }
  
  console.log(`[LogSources] Generated ${logsources.length} logsources, skipped ${skipped}`);
  return logsources;
}

/**
 * Call Claude API to fetch and parse a product's documentation
 */
async function fetchAndParseLogsource(productName, anthropicToken) {
  const prompt = `Extract field mappings for ${productName} log source.

Return ONLY valid JSON with this structure:
{
  "name": "Product Display Name",
  "product": "product_key",
  "service": "service_key",
  "category": "process_creation|authentication|file_creation|network|...",
  "description": "Brief description of this log source",
  "fieldMappings": {
    "process_creation": {
      "Image": "actual_field_name_in_logs",
      "CommandLine": "actual_field_name",
      ...
    }
  }
}

Map common Sigma fields (Image, CommandLine, ParentImage, User, ProcessId, etc.) to actual field names in ${productName}.

If you cannot find reliable information, respond with null.`;

  const body = JSON.stringify({
    model: 'claude-opus-4-5-20251101',
    max_tokens: 1000,
    messages: [
      {
        role: 'user',
        content: prompt
      }
    ]
  });
  
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': anthropicToken,
        'anthropic-version': '2023-06-01'
      }
    };
    
    const req = https.request(options, (res) => {
      let data = '';
      
      res.on('data', chunk => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          
          if (response.error) {
            reject(new Error(response.error.message));
            return;
          }
          
          const content = response.content[0].text;
          
          // Extract JSON from response
          const jsonMatch = content.match(/\{[\s\S]*\}/);
          if (!jsonMatch) {
            resolve(null);
            return;
          }
          
          const logsource = JSON.parse(jsonMatch[0]);
          
          if (logsource === null) {
            resolve(null);
            return;
          }
          
          logsource.lastUpdated = new Date().toISOString().split('T')[0];
          resolve(logsource);
        } catch (error) {
          reject(error);
        }
      });
    });
    
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * Generate Sigma rules from techniques and logsources
 */
async function generateSigmaRules(techniques, logsources) {
  console.log('[Sigma] Generating detection rules...');
  
  for (const technique of techniques) {
    try {
      const rule = await generateSigmaRule(technique, logsources);
      
      if (rule) {
        const filename = path.join(SIGMA_RULES_DIR, `${technique.tNumber}.txt`);
        fs.writeFileSync(filename, rule);
      }
    } catch (error) {
      console.error(`[Sigma] Error generating rule for ${technique.tNumber}:`, error.message);
    }
  }
  
  console.log(`[Sigma] Generated ${techniques.length} rules`);
}

/**
 * Generate a single Sigma rule
 */
async function generateSigmaRule(technique, logsources) {
  // For now, return a template. In production, call Claude to generate rule.
  
  const rule = `title: ${technique.name}
id: ${generateUUID()}
description: >
  Detects ${technique.name.toLowerCase()}.
  ${technique.description}
references:
  - https://attack.mitre.org/techniques/${technique.tNumber}/
  - https://incidentbuddy.ai/gapmatrix/techniques/${technique.tNumber}
author: GapMATRIX Sigma Generator
date: ${new Date().toISOString().split('T')[0]}

logsource:
  product: windows
  service: security
  category: process_creation

detection:
  selection:
    EventID: 4688
  condition: selection

falsepositives:
  - Legitimate system administration

level: medium

tags:
  - attack.${technique.tactic}
  - attack.${technique.tNumber}`;

  return rule;
}

/**
 * Generate UUID v4
 */
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Load existing logsources and keep if generation fails
 */
function loadExistingLogsources() {
  try {
    if (fs.existsSync(LOGSOURCES_FILE)) {
      const content = fs.readFileSync(LOGSOURCES_FILE, 'utf-8');
      return JSON.parse(content);
    }
  } catch (error) {
    console.warn('[LogSources] Could not load existing logsources:', error.message);
  }
  return null;
}

/**
 * Save logsources to file
 */
function saveLogsources(logsources) {
  const output = {
    generated: new Date().toISOString(),
    version: '1.0.0',
    logsources: logsources
  };
  
  fs.writeFileSync(LOGSOURCES_FILE, JSON.stringify(output, null, 2));
  console.log(`[LogSources] Saved ${logsources.length} logsources to ${LOGSOURCES_FILE}`);
}

/**
 * Main execution
 */
async function main() {
  const anthropicToken = process.env.ANTHROPIC_API_KEY;
  
  if (!anthropicToken) {
    console.error('[Error] ANTHROPIC_API_KEY environment variable not set');
    process.exit(1);
  }
  
  try {
    // Load existing logsources as fallback
    const existingLogsources = loadExistingLogsources();
    
    // Generate new logsources
    const newLogsources = await generateLogsourcesFromDocs(anthropicToken);
    
    // Use new if available, fallback to existing
    const logsourcesToUse = newLogsources.length > 0 ? newLogsources : (existingLogsources?.logsources || []);
    
    if (logsourcesToUse.length === 0) {
      console.error('[Error] No logsources generated and no fallback available');
      process.exit(1);
    }
    
    // Save logsources
    saveLogsources(logsourcesToUse);
    
    // TODO: Generate Sigma rules (requires technique data from MITRE/ThreatActors-TTPs)
    console.log('[Complete] Logsource generation complete');
    
  } catch (error) {
    console.error('[Fatal Error]', error);
    process.exit(1);
  }
}

main();
