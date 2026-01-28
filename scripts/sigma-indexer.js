#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

async function main() {
  console.log('[SigmaIndexer] Building SigmaHQ technique-to-detection mapping...\n');

  const sigmaRulesDir = '/home/claude/sigma-master/rules';
  const techniqueMap = {}; // T#### -> [{ rule, detections, logsources }, ...]

  // Walk all YAML files
  function walkRules(dir) {
    const files = fs.readdirSync(dir);
    
    files.forEach(file => {
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory()) {
        walkRules(fullPath);
      } else if (file.endsWith('.yml') && !file.startsWith('.')) {
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          const rule = yaml.load(content);
          
          if (!rule || !rule.tags) return;
          
          // Extract ATT&CK technique tags (attack.T#### or attack.t#### format)
          const techniques = rule.tags
            .filter(tag => typeof tag === 'string' && (tag.startsWith('attack.t') || tag.startsWith('attack.T')))
            .map(tag => tag.replace('attack.', '').toUpperCase());
          
          if (techniques.length === 0) return;
          
          // Extract logsource
          const logsource = rule.logsource || {};
          const logsourceKey = `${logsource.product}/${logsource.service || logsource.category}`;
          
          // Extract detection patterns
          const detections = extractDetections(rule.detection);
          
          // Map to techniques
          techniques.forEach(tech => {
            if (!techniqueMap[tech]) {
              techniqueMap[tech] = [];
            }
            techniqueMap[tech].push({
              title: rule.title,
              logsource: logsourceKey,
              product: logsource.product,
              service: logsource.service,
              category: logsource.category,
              detections: detections,
              file: fullPath.replace(sigmaRulesDir, ''),
              tags: rule.tags
            });
          });
        } catch (error) {
          // Skip files that can't be parsed
        }
      }
    });
  }

  walkRules(sigmaRulesDir);

  console.log(`[SigmaIndexer] ✓ Found ${Object.keys(techniqueMap).length} techniques with rules`);
  
  // Show some stats
  let totalRules = 0;
  Object.values(techniqueMap).forEach(rules => {
    totalRules += rules.length;
  });
  console.log(`[SigmaIndexer] ✓ Total rule mappings: ${totalRules}\n`);

  // Show top techniques
  const sorted = Object.entries(techniqueMap)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 20);

  console.log('[SigmaIndexer] Top 20 techniques by rule count:');
  sorted.forEach(([tech, rules]) => {
    console.log(`[SigmaIndexer]   ${tech}: ${rules.length} rules`);
  });

  // Save the mapping
  const output = JSON.stringify(techniqueMap, null, 2);
  fs.writeFileSync('/mnt/user-data/outputs/sigma-technique-map.json', output);
  console.log(`\n[SigmaIndexer] ✓ Saved mapping to sigma-technique-map.json`);
}

function extractDetections(detection) {
  const patterns = [];
  
  if (!detection || typeof detection !== 'object') return patterns;

  // Walk the detection structure
  function walkDetection(obj, parentKey = '') {
    Object.entries(obj).forEach(([key, value]) => {
      if (key === 'condition') return;
      
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        // Nested object - recurse
        walkDetection(value, key);
      } else if (Array.isArray(value) || typeof value === 'string' || typeof value === 'number') {
        // This is a field with values
        patterns.push({
          field: key,
          values: Array.isArray(value) ? value : [value],
          type: typeof value === 'string' ? 'string' : typeof value === 'number' ? 'number' : 'array'
        });
      }
    });
  }

  walkDetection(detection);
  return patterns;
}

main().catch(err => {
  console.error('[SigmaIndexer] Error:', err.message);
  process.exit(1);
});
