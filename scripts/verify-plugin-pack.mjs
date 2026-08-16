import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

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
  'dist/index.js',
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

const archivePath = resolve(pack.filename);
const unpackDir = mkdtempSync(join(tmpdir(), 'dsh-mobile-plugin-pack-'));
try {
  execFileSync('tar', ['-xzf', archivePath, '-C', unpackDir]);
  const packageDir = join(unpackDir, 'package');
  const manifest = JSON.parse(readFileSync(join(packageDir, 'package.json'), 'utf8'));
  if (manifest.main !== 'dist/index.js') {
    throw new Error(`packaged main must be dist/index.js, got ${String(manifest.main)}`);
  }

  const entry = await import(pathToFileURL(join(packageDir, manifest.main)).href);
  for (const exportedName of ['name', 'inject', 'apply']) {
    if (!(exportedName in entry)) {
      throw new Error(`packaged plugin entry is missing export ${exportedName}`);
    }
  }
} catch (error) {
  console.error(`Packaged plugin cannot load independently: ${error.message}`);
  process.exitCode = 1;
} finally {
  rmSync(unpackDir, { recursive: true, force: true });
}

if (process.exitCode !== 1) {
  console.log(
    `Verified standalone ${basename(pack.filename)} (${pack.files.length} files, ${pack.unpackedSize} bytes unpacked)`,
  );
}
