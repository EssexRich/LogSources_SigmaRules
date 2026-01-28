#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const threatActorsData = require('./threat-actors.json');
const mitreData = require('./mitre.json');

// Get unique techniques
const techniques = new Set();
if (threatActorsData.actors) {
    for (const actor of threatActorsData.actors) {
        if (actor.techniques) {
            actor.techniques.forEach((t) => {
                if (t.match(/^T\d{4}(?:\.\d{3})?$/)) {
                    techniques.add(t);
                }
            });
        }
    }
}

console.log(`Found ${techniques.size} unique techniques`);

// Generate rule for each technique with multiple products
const products = ['windows', 'linux', 'macos', 'm365'];
let totalRules = 0;

for (const tNumber of Array.from(techniques).sort()) {
    for (const product of products) {
        const rule = generateSigmaRule(tNumber, product);
        const dir = path.join('sigma-rules', product);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(path.join(dir, `${tNumber}.txt`), rule);
        totalRules++;
    }
}

console.log(`Generated ${totalRules} Sigma rules`);

function generateSigmaRule(tNumber, product = 'windows') {
    const uuid = generateUUID();
    const now = new Date().toISOString().split('T')[0];

    let logsourceConfig = {
        product: 'windows',
        service: 'security',
        category: 'process_creation',
    };

    switch (product) {
        case 'linux':
            logsourceConfig = { product: 'linux', service: 'auditd', category: 'process_creation' };
            break;
        case 'macos':
            logsourceConfig = { product: 'macos', service: 'unified_logging', category: 'process_creation' };
            break;
        case 'm365':
            logsourceConfig = { product: 'm365', service: 'entra_id', category: 'authentication' };
            break;
    }

    return `title: MITRE ATT&CK ${tNumber} Detection (${product})
id: ${uuid}
description: >
  Detects techniques consistent with MITRE ATT&CK technique ${tNumber}.
  Adversaries may use a variety of techniques throughout the attack lifecycle.
  This rule provides baseline detection for security monitoring and threat hunting.
references:
  - https://attack.mitre.org/techniques/${tNumber}/
  - https://incidentbuddy.ai/gapmatrix/techniques/${tNumber}
author: GapMATRIX Sigma Generator
date: ${now}

logsource:
  product: ${logsourceConfig.product}
  service: ${logsourceConfig.service}
  category: ${logsourceConfig.category}

detection:
  selection:
    EventID: 4688
  condition: selection

falsepositives:
  - Legitimate system administration

level: medium

tags:
  - attack.${tNumber}
`;
}

function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = (Math.random() * 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    });
}
