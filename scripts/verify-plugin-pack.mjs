import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

const metadataPath = process.argv[2];
if (!metadataPath) {
  console.error('Usage: node scripts/verify-plugin-pack.mjs <npm-pack-json>');
  process.exit(2);
}

let metadata;
try {
  metadata = JSON.parse(readFileSync(metadataPath, 'utf8'));
} catch (error) {
  console.error(`Could not parse npm pack metadata: ${error.message}`);
  process.exit(1);
}

const pack = Array.isArray(metadata) ? metadata[0] : metadata;
if (!pack?.filename || !Array.isArray(pack.files)) {
  console.error('npm pack metadata does not contain a package filename and file list');
  process.exit(1);
}

const requiredFiles = [
  '.codex-plugin/plugin.json',
  'README.md',
  'cordis.patch.yml',
  'package.json',
  'src/index.ts',
  'panel-ui/index.html',
  'panel-ui/panel.js',
  'panel-ui/panel.css',
  'panel-ui/vendor/qrcode.js',
];

const packagedFiles = new Set(pack.files.map((file) => file.path));
const missingFiles = requiredFiles.filter((file) => !packagedFiles.has(file));
if (missingFiles.length > 0) {
  console.error(`Plugin package is missing required files: ${missingFiles.join(', ')}`);
  process.exit(1);
}

console.log(`Verified ${basename(pack.filename)} (${pack.files.length} files, ${pack.unpackedSize} bytes unpacked)`);
