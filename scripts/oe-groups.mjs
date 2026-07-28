#!/usr/bin/env node

import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const SECRET_ENV_VAR = 'OE_GROUPS_SERVER_SECRET';

function usage(message) {
  if (message) process.stderr.write(`${message}\n\n`);
  process.stderr.write(
    'Usage: oe-groups trust-root [--prod | --deployment <deployment>]\n'
  );
  process.exitCode = 2;
}

function deploymentArgs(args) {
  if (args.length === 0) return [];
  if (args.length === 1 && args[0] === '--prod') return ['--prod'];
  if (
    args.length === 2 &&
    args[0] === '--deployment' &&
    args[1].trim().length > 0
  ) {
    return args;
  }
  usage('Invalid deployment arguments');
  return null;
}

function runConvex(args, options = {}) {
  const command = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  const result = spawnSync(command, ['convex', 'env', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    input: options.input,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = result.stderr?.trim();
    throw new Error(
      detail
        ? `Convex environment command failed: ${detail}`
        : `Convex environment command exited with status ${result.status}`
    );
  }
  return result.stdout ?? '';
}

function requireSeed(encoded) {
  const normalized = encoded.trim();
  const seed = Buffer.from(normalized, 'base64');
  if (
    seed.length !== 32 ||
    seed.toString('base64') !== normalized
  ) {
    throw new Error(
      `${SECRET_ENV_VAR} must be canonical base64 encoding exactly 32 bytes`
    );
  }
  return new Uint8Array(seed);
}

async function printTrustRoot(args) {
  const selectedDeployment = deploymentArgs(args);
  if (!selectedDeployment) return;

  const names = runConvex([
    'list',
    '--names-only',
    ...selectedDeployment,
  ])
    .split(/\r?\n/)
    .map((name) => name.trim())
    .filter(Boolean);

  let seed;
  if (names.includes(SECRET_ENV_VAR)) {
    seed = requireSeed(
      runConvex(['get', SECRET_ENV_VAR, ...selectedDeployment])
    );
  } else {
    seed = new Uint8Array(randomBytes(32));
    const encoded = Buffer.from(seed).toString('base64');
    runConvex(
      ['set', SECRET_ENV_VAR, ...selectedDeployment],
      { input: `${encoded}\n` }
    );
  }

  const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
  const [
    { generateServerSecretParams, getServerPublicParams },
    { encodeGroupTrustRoot },
    { deriveSealedSenderRootPublicKey },
  ] = await Promise.all([
    // pathToFileURL: dynamic import of a bare absolute path fails on
    // Windows, where the ESM loader requires a file:// URL.
    import(
      pathToFileURL(
        path.join(
          scriptDirectory,
          '../dist/internal/protocol/zk/groups/server-params.js'
        )
      ).href
    ),
    import(
      pathToFileURL(
        path.join(
          scriptDirectory,
          '../dist/internal/groups/trust-root.js'
        )
      ).href
    ),
    import(
      pathToFileURL(
        path.join(
          scriptDirectory,
          '../dist/internal/protocol/sealed-sender/trust-root.js'
        )
      ).href
    ),
  ]);
  const secretParams = generateServerSecretParams(seed);
  seed.fill(0);
  const publicParams = getServerPublicParams(secretParams);
  const trustRoot = encodeGroupTrustRoot({
    credentialPublicKey: publicParams.credentialPublicKey,
    serverSigningPublicKey: publicParams.signingPublicKey,
    profileKeyCredentialPublicKey:
      publicParams.profileKeyCredentialPublicKey,
    endorsementRootPublicKey: publicParams.endorsementPublicKey,
  });
  const sealedSenderRoot = await deriveSealedSenderRootPublicKey(
    secretParams.signingKeyPair.signingKey
  );

  // Two independently pinned roots, printed with labels because they go to
  // different places in the client build and are not interchangeable.
  process.stdout.write(
    `group trust root: ${Buffer.from(trustRoot).toString('base64')}\n`
  );
  process.stdout.write(
    `sealed sender trust root: ${Buffer.from(sealedSenderRoot).toString('base64')}\n`
  );
}

const [command, ...args] = process.argv.slice(2);
if (command !== 'trust-root') {
  usage(command ? `Unknown command: ${command}` : undefined);
} else {
  try {
    await printTrustRoot(args);
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : String(error)}\n`
    );
    process.exitCode = 1;
  }
}
