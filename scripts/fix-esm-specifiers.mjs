import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.argv[2] ?? 'dist');

const REWRITABLE_FILE_RE = /(?:\.js|\.d\.ts)$/;
const SPECIFIER_RE = /(\bfrom\s*|import\s*\(\s*)(['"])(\.[^'"`]+)\2/g;

function rewriteSpecifier(filePath, specifier) {
  if (specifier.endsWith('.js') || specifier.endsWith('.mjs') || specifier.endsWith('.cjs') || specifier.endsWith('.json') || specifier.endsWith('.node')) {
    return specifier;
  }

  const basePath = path.resolve(path.dirname(filePath), specifier);
  if (fs.existsSync(`${basePath}.js`)) {
    return `${specifier}.js`;
  }

  if (fs.existsSync(path.join(basePath, 'index.js'))) {
    return `${specifier}/index.js`;
  }

  return specifier;
}

function processFile(filePath) {
  const original = fs.readFileSync(filePath, 'utf8');
  const rewritten = original.replace(
    SPECIFIER_RE,
    (match, prefix, quote, specifier) => `${prefix}${quote}${rewriteSpecifier(filePath, specifier)}${quote}`
  );

  if (rewritten !== original) {
    fs.writeFileSync(filePath, rewritten);
  }
}

function walk(dirPath) {
  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    const entryPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      walk(entryPath);
      continue;
    }

    if (REWRITABLE_FILE_RE.test(entry.name)) {
      processFile(entryPath);
    }
  }
}

if (fs.existsSync(root)) {
  walk(root);
}
