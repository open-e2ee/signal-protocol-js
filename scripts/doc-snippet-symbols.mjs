/**
 * Extracts the SDK symbols a documentation snippet claims exist.
 *
 * A snippet that cannot run still makes checkable promises: every name it
 * imports from the SDK, and every member it reads off one of those names, must
 * exist in the published package. Those promises are what goes stale when an
 * export is renamed or deleted, and prose carries no compiler to catch it.
 *
 * The analysis is deliberately syntactic. It reports what a snippet references;
 * `tsc` decides whether each reference resolves, against the packed tarball
 * rather than the working tree. Splitting it that way keeps the judgment with
 * the compiler and leaves this module with one testable job.
 */

import { createRequire } from 'node:module';

const { parseSync } = createRequire(import.meta.url)('@swc/core');

export const SDK_PACKAGE = '@open-e2ee/signal-protocol-sdk';

export function isSdkSpecifier(specifier) {
  return specifier === SDK_PACKAGE || specifier.startsWith(`${SDK_PACKAGE}/`);
}

function walk(node, visit) {
  if (node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) walk(item, visit);
    return;
  }
  if (typeof node.type === 'string') visit(node);
  for (const key of Object.keys(node)) {
    if (key === 'span') continue;
    walk(node[key], visit);
  }
}

function patternNames(pattern, into) {
  walk(pattern, (node) => {
    if (node.type === 'Identifier') into.add(node.value);
  });
}

const DECLARATION_TYPES = new Set([
  'FunctionDeclaration',
  'ClassDeclaration',
  'TsInterfaceDeclaration',
  'TsTypeAliasDeclaration',
  'TsEnumDeclaration',
  'TsModuleDeclaration',
]);

const FUNCTION_TYPES = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression',
  'MethodProperty',
  'ClassMethod',
  'PrivateMethod',
]);

/**
 * Reports the SDK symbols one snippet references.
 *
 * Identifier collection is intentionally loose: it gathers every identifier and
 * subtracts the ones the snippet declares or imports. Callers narrow what is
 * left against the package's real export list, so a stray property name or
 * object key costs nothing. Erring the other way -- resolving scopes here --
 * would trade a harmless surplus for missed references.
 */
export function analyseSnippet(code) {
  const module = parseSync(code, {
    syntax: 'typescript',
    tsx: false,
    target: 'es2022',
  });

  const imports = [];
  const importedLocals = new Set();
  const localNames = new Set();
  const memberProperties = new Set();
  const identifiers = new Set();
  const memberAccesses = [];

  walk(module, (node) => {
    switch (node.type) {
      case 'ImportDeclaration': {
        const bindings = [];
        for (const specifier of node.specifiers ?? []) {
          const local = specifier.local?.value;
          if (!local) continue;
          importedLocals.add(local);
          bindings.push({
            local,
            imported: specifier.imported?.value ?? local,
            kind:
              specifier.type === 'ImportNamespaceSpecifier'
                ? 'namespace'
                : specifier.type === 'ImportDefaultSpecifier'
                  ? 'default'
                  : 'named',
            typeOnly: Boolean(node.typeOnly || specifier.isTypeOnly),
          });
        }
        imports.push({
          specifier: node.source.value,
          typeOnly: Boolean(node.typeOnly),
          bindings,
        });
        break;
      }
      case 'VariableDeclarator':
        patternNames(node.id, localNames);
        break;
      case 'CatchClause':
        if (node.param) patternNames(node.param, localNames);
        break;
      case 'MemberExpression':
        // `a.b` in value position. A qualified name in type position parses as
        // TsQualifiedName, so every base reaching here is a value -- which is
        // what makes `typeof base.member` a legal probe.
        if (node.property?.type === 'Identifier' && !node.computed) {
          memberProperties.add(node.property.value);
          if (node.object?.type === 'Identifier') {
            memberAccesses.push({
              base: node.object.value,
              member: node.property.value,
            });
          }
        }
        break;
      case 'KeyValueProperty':
        if (node.key?.type === 'Identifier') memberProperties.add(node.key.value);
        break;
      case 'Identifier':
        identifiers.add(node.value);
        break;
      default:
        break;
    }

    if (DECLARATION_TYPES.has(node.type) && node.id?.value) {
      localNames.add(node.id.value);
    }
    if (node.type === 'FunctionDeclaration' && node.identifier?.value) {
      localNames.add(node.identifier.value);
    }
    if (node.type === 'ClassDeclaration' && node.identifier?.value) {
      localNames.add(node.identifier.value);
    }
    if (FUNCTION_TYPES.has(node.type)) {
      for (const parameter of node.params ?? []) patternNames(parameter, localNames);
      if (node.function) {
        for (const parameter of node.function.params ?? []) {
          patternNames(parameter, localNames);
        }
      }
    }
  });

  const freeIdentifiers = new Set();
  for (const name of identifiers) {
    if (importedLocals.has(name)) continue;
    if (localNames.has(name)) continue;
    if (memberProperties.has(name)) continue;
    freeIdentifiers.add(name);
  }

  return {
    imports,
    importedLocals,
    localNames,
    freeIdentifiers,
    memberAccesses,
  };
}

/**
 * Builds a type-level module that asserts every referenced symbol exists.
 *
 * The module imports nothing it does not check and executes nothing at all:
 * an import statement fails compilation when the name is not exported, and
 * `typeof base.member` fails when the member is gone. Non-SDK imports are
 * dropped because the fixture installs only the SDK.
 *
 * `rootValueExports` names what the package's root entry point exports at
 * runtime. It resolves the bare identifiers in fragments that show a call
 * without repeating its import, and bounds the loose identifier collection in
 * `analyseSnippet` to names the package actually publishes.
 *
 * `excludeSpecifiers` drops the subpaths a snippet declares as not yet shipped.
 * Their bindings are still locals, so they raise no free identifier and take no
 * member probe -- which leaves the shipped half of a forward-looking snippet
 * under exactly the same verification as any other.
 */
export function buildProbeModule(analysis, rootValueExports, excludeSpecifiers = new Set()) {
  const lines = [];
  const probeBases = new Map();
  let referenced = 0;

  for (const declaration of analysis.imports) {
    if (!isSdkSpecifier(declaration.specifier)) continue;
    if (excludeSpecifiers.has(declaration.specifier)) continue;
    const named = declaration.bindings.filter((binding) => binding.kind === 'named');
    const namespaces = declaration.bindings.filter((binding) => binding.kind === 'namespace');
    const defaults = declaration.bindings.filter((binding) => binding.kind === 'default');

    for (const binding of defaults) {
      referenced += 1;
      lines.push(`import ${binding.local} from '${declaration.specifier}';`);
      if (!binding.typeOnly) probeBases.set(binding.local, true);
    }
    for (const binding of namespaces) {
      referenced += 1;
      lines.push(`import * as ${binding.local} from '${declaration.specifier}';`);
      if (!binding.typeOnly) probeBases.set(binding.local, true);
    }
    if (named.length > 0) {
      referenced += named.length;
      const clause = named
        .map((binding) => {
          const alias = binding.imported === binding.local
            ? binding.local
            : `${binding.imported} as ${binding.local}`;
          return binding.typeOnly && !declaration.typeOnly ? `type ${alias}` : alias;
        })
        .join(', ');
      const prefix = declaration.typeOnly ? 'import type' : 'import';
      lines.push(`${prefix} { ${clause} } from '${declaration.specifier}';`);
      for (const binding of named) {
        if (!binding.typeOnly && !declaration.typeOnly) probeBases.set(binding.local, true);
      }
    }
  }

  const free = [...analysis.freeIdentifiers]
    .filter((name) => rootValueExports.has(name))
    .sort();
  if (free.length > 0) {
    referenced += free.length;
    lines.push(`import { ${free.join(', ')} } from '${SDK_PACKAGE}';`);
    for (const name of free) probeBases.set(name, true);
  }

  const probes = [];
  const seen = new Set();
  for (const access of analysis.memberAccesses) {
    if (!probeBases.has(access.base)) continue;
    const key = `${access.base}.${access.member}`;
    if (seen.has(key)) continue;
    seen.add(key);
    probes.push(key);
  }
  for (const [index, key] of probes.entries()) {
    lines.push(`type __member_${index + 1} = typeof ${key};`);
  }

  if (referenced === 0) return null;
  return {
    source: `${lines.join('\n')}\n`,
    referencedSymbols: referenced,
    memberProbes: probes.length,
  };
}

/**
 * Builds a module whose compilation must fail.
 *
 * A snippet that previews an unshipped API makes the negative claim: this
 * subpath does not exist yet. That claim decays the moment the subpath ships,
 * and it decays silently, because nothing about a working example looks wrong.
 * Importing each declared subpath and requiring `TS2307` turns the negative
 * claim into a check that goes red on the release that makes it false.
 *
 * The import is a type-only namespace rather than a side-effect import: a
 * side-effect import that does not resolve reports `TS2882`, and reusing one
 * error code for both this probe and an ordinary missing module keeps the
 * reader of a failure from having to know which shape produced it.
 */
export function buildUnshippedProbe(specifiers) {
  const lines = specifiers.map(
    (specifier, index) => `import type * as __unshipped_${index + 1} from '${specifier}';`
  );
  return `${lines.join('\n')}\n`;
}

/** Reads back the specifiers `tsc` reported as unresolvable. */
export function parseUnresolvedSpecifiers(compilerOutput) {
  const unresolved = new Set();
  for (const match of compilerOutput.matchAll(
    /error TS2307: Cannot find module '([^']+)'/g
  )) {
    unresolved.add(match[1]);
  }
  return unresolved;
}
