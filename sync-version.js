#!/usr/bin/env node

/**
 * Script to sync version from package.json to index.html
 * Run this after updating the version in package.json
 */

const fs = require('fs');
const path = require('path');

try {
    // Read package.json
    const packageJsonPath = path.join(__dirname, 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    const version = packageJson.version;
    
    console.log(`📦 Found version ${version} in package.json`);
    
    // Read index.html
    const indexHtmlPath = path.join(__dirname, 'index.html');
    let indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');
    
    // Update APP_VERSION constant
    const versionRegex = /const APP_VERSION = '[^']*';/;
    const newVersionLine = `const APP_VERSION = '${version}';`;
    
    if (versionRegex.test(indexHtml)) {
        indexHtml = indexHtml.replace(versionRegex, newVersionLine);
        console.log(`✅ Updated APP_VERSION to '${version}' in index.html`);
    } else {
        console.error('❌ Could not find APP_VERSION constant in index.html');
        process.exit(1);
    }
    
    // Write back to index.html
    fs.writeFileSync(indexHtmlPath, indexHtml, 'utf8');
    console.log(`💾 Saved changes to index.html`);
    
    console.log(`🎉 Version sync completed: v${version}`);
    
} catch (error) {
    console.error('❌ Error syncing version:', error.message);
    process.exit(1);
}
