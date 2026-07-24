import {
  existsSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const apiRoot = resolve(scriptDir, '..', 'docs', 'api');
const scopeRoot = join(apiRoot, '@open-e2ee');
const generatedNamespaceRoot = join(scopeRoot, 'namespaces');
const canonicalNamespaceRoot = join(apiRoot, 'namespaces');

if (!existsSync(generatedNamespaceRoot)) {
  throw new Error(
    `Expected TypeDoc namespace output at ${generatedNamespaceRoot}`
  );
}

const unexpectedScopeEntries = readdirSync(scopeRoot).filter(
  (entry) => entry !== 'namespaces'
);
if (unexpectedScopeEntries.length > 0) {
  throw new Error(
    `Refusing to remove a non-empty TypeDoc scope directory: ${unexpectedScopeEntries.join(', ')}`
  );
}

function collectMarkdownFiles(directory) {
  const files = [];

  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) {
      files.push(...collectMarkdownFiles(path));
    } else if (path.endsWith('.md')) {
      files.push(path);
    }
  }

  return files;
}

function isWithin(path, directory) {
  const pathFromDirectory = relative(directory, path);
  return (
    pathFromDirectory === '' ||
    (!pathFromDirectory.startsWith(`..${sep}`) && pathFromDirectory !== '..')
  );
}

function canonicalPath(path) {
  if (!isWithin(path, generatedNamespaceRoot)) {
    return path;
  }

  return join(
    canonicalNamespaceRoot,
    relative(generatedNamespaceRoot, path)
  );
}

function rewriteLinkTarget(rawTarget, sourcePath, destinationPath) {
  if (
    rawTarget.startsWith('#') ||
    rawTarget.startsWith('/') ||
    /^[a-z][a-z\d+.-]*:/iu.test(rawTarget)
  ) {
    return rawTarget;
  }

  const hashIndex = rawTarget.indexOf('#');
  const pathPart =
    hashIndex === -1 ? rawTarget : rawTarget.slice(0, hashIndex);
  const fragment = hashIndex === -1 ? '' : rawTarget.slice(hashIndex);

  if (pathPart.length === 0) {
    return rawTarget;
  }

  const currentTargetPath = resolve(dirname(sourcePath), pathPart);
  const destinationTargetPath = canonicalPath(currentTargetPath);
  let rewrittenPath = relative(
    dirname(destinationPath),
    destinationTargetPath
  ).split(sep).join('/');

  if (rewrittenPath.length === 0) {
    rewrittenPath = '.';
  }

  return `${rewrittenPath}${fragment}`;
}

const rewrittenFiles = collectMarkdownFiles(apiRoot).map((sourcePath) => {
  const destinationPath = canonicalPath(sourcePath);
  const contents = readFileSync(sourcePath, 'utf8').replace(
    /(\]\()([^)]+)(\))/gu,
    (_match, prefix, target, suffix) =>
      `${prefix}${rewriteLinkTarget(
        target,
        sourcePath,
        destinationPath
      )}${suffix}`
  );

  return { contents, destinationPath };
});

if (existsSync(canonicalNamespaceRoot)) {
  rmSync(canonicalNamespaceRoot, { recursive: true });
}
renameSync(generatedNamespaceRoot, canonicalNamespaceRoot);
rmSync(scopeRoot, { recursive: true });

for (const { contents, destinationPath } of rewrittenFiles) {
  writeFileSync(destinationPath, contents);
}
