/*
 * Pins the vendored SQLite3 Multiple Ciphers Wasm engine to its signed release.
 *
 * `local/store/sqlite/web/sqlite3mc/pins.json` records the release archive, its
 * sha256, the signer of the release `SHA256SUMS`, and for each vendored file
 * the sha256 of the released file, the patches from `PATCHES` below that the
 * vendored file carries, and the sha256 of the vendored file.
 *
 * Usage:
 *   node ./scripts/sqlite-engine.mjs copy <dist>     # check the files, copy them into the build
 *   node ./scripts/sqlite-engine.mjs verify-release  # download the release and check it with cosign
 *   node ./scripts/sqlite-engine.mjs vendor          # write the patched release files and their pins
 *
 * `copy` runs in every build. It fails when a vendored file does not match its
 * pin, or when removing its recorded patches does not give the released file.
 * So neither a changed engine file nor an unrecorded edit can reach `dist`.
 * `tsc` does not emit the `.mjs` and `.wasm` files, so this step puts them
 * next to the compiled worker.
 *
 * `verify-release` and `vendor` need network access, `cosign`, and `unzip`.
 * Both check the Sigstore signature of `SHA256SUMS` against the pinned signer,
 * the archive sha256 against `SHA256SUMS` and the pin, and each released file
 * against its pin. `verify-release` then checks that the recorded patches turn
 * each released file into the vendored file. `vendor` writes the patched files
 * and updates their pins.
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ENGINE_DIRECTORY = 'local/store/sqlite/web/sqlite3mc';

/**
 * The changes to the released engine files. Each patch replaces text that
 * occurs exactly once in its file, and its replacement also occurs exactly
 * once, so the patch applies and reverses without doubt. The files are read
 * as latin1, so each byte stays one character.
 */
const PATCHES = [
  {
    id: 'keep-pool-on-failed-install',
    file: 'sqlite3.mjs',
    reason:
      'When the opfs-sahpool install fails, for example because another context still holds ' +
      'an access handle, the release deletes the whole pool directory with the databases in it. ' +
      'The patch unregisters the VFS and releases the handles, and keeps the directory.',
    find: `      }).catch(async (e)=>{
        await thePool.removeVfs().catch(()=>{});
        throw e;
      });`,
    replace: `      }).catch(async (e)=>{
        // open-e2ee: keep the pool directory. It holds the databases.
        const cVfs = thePool.getVfs();
        if(cVfs.pointer){
          capi.sqlite3_vfs_unregister(cVfs.pointer);
          cVfs.dispose();
        }
        thePool.releaseAccessHandles();
        throw e;
      });`,
  },
  {
    id: 'settle-handles-before-release',
    file: 'sqlite3.mjs',
    reason:
      'When one access handle of the pool fails to open, the release closes the open handles ' +
      'while other opens are still in flight. A handle that opens later stays in the pool, so ' +
      'the pool holds the file while it reports itself paused. The patch waits for every open ' +
      'to settle before it releases the handles.',
    find: `      return Promise.all(files.map(async([name,h])=>{
        try{
          const ah = await h.createSyncAccessHandle()
          this.#mapSAHToName.set(ah, name);
          if(clearFiles){
            ah.truncate(HEADER_OFFSET_DATA);
            this.setAssociatedPath(ah, '', 0);
          }else{
            const path = this.getAssociatedPath(ah);
            if(path){
              this.#mapFilenameToSAH.set(path, ah);
            }else{
              this.#availableSAH.add(ah);
            }
          }
        }catch(e){
          this.storeErr(e);
          this.releaseAccessHandles();
          throw e;
        }
      }));`,
    replace: `      // open-e2ee: release the handles only after every open has settled.
      const settled = await Promise.allSettled(files.map(async([name,h])=>{
        const ah = await h.createSyncAccessHandle()
        this.#mapSAHToName.set(ah, name);
        if(clearFiles){
          ah.truncate(HEADER_OFFSET_DATA);
          this.setAssociatedPath(ah, '', 0);
        }else{
          const path = this.getAssociatedPath(ah);
          if(path){
            this.#mapFilenameToSAH.set(path, ah);
          }else{
            this.#availableSAH.add(ah);
          }
        }
      }));
      const failed = settled.find((result)=>'rejected'===result.status);
      if(failed){
        this.storeErr(failed.reason);
        this.releaseAccessHandles();
        throw failed.reason;
      }`,
  },
  {
    id: 'report-quota-as-full',
    file: 'sqlite3.mjs',
    reason:
      'When a write to the origin private file system exceeds the storage quota, the release ' +
      'reports SQLITE_IOERR, so the store cannot tell a full quota from a failed disk. The ' +
      'patch reports a QuotaExceededError as SQLITE_FULL, the code of a full disk.',
    find: `    storeErr(e,code){
      if(e){
        e.sqlite3Rc = code || capi.SQLITE_IOERR;`,
    replace: `    storeErr(e,code){
      if(e){
        // open-e2ee: a full storage quota is a full disk.
        if(code && 'QuotaExceededError'===e.name) code = capi.SQLITE_FULL;
        e.sqlite3Rc = code || capi.SQLITE_IOERR;`,
  },
];

function readPins(root = repoRoot) {
  return JSON.parse(readFileSync(join(root, ENGINE_DIRECTORY, 'pins.json'), 'utf8'));
}

function writePins(pins) {
  writeFileSync(join(repoRoot, ENGINE_DIRECTORY, 'pins.json'), `${JSON.stringify(pins, null, 2)}\n`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function patchesFor(name) {
  return PATCHES.filter((patch) => patch.file === name);
}

/** Replaces the one occurrence of `from` in `text`. */
function replaceOnce(text, from, to, what) {
  const first = text.indexOf(from);
  if (first === -1 || text.indexOf(from, first + 1) !== -1) {
    throw new Error(`${what}: the text to replace must occur exactly once`);
  }
  return text.slice(0, first) + to + text.slice(first + from.length);
}

/** The released bytes of `name` with its recorded patches applied. */
function applyPatches(name, released) {
  let text = released.toString('latin1');
  for (const patch of patchesFor(name)) {
    text = replaceOnce(text, patch.find, patch.replace, `${name} patch ${patch.id}`);
  }
  return Buffer.from(text, 'latin1');
}

/** The vendored bytes of `name` with its recorded patches removed. */
function removePatches(name, vendored) {
  let text = vendored.toString('latin1');
  for (const patch of patchesFor(name).reverse()) {
    text = replaceOnce(text, patch.replace, patch.find, `${name} patch ${patch.id} (reversed)`);
  }
  return Buffer.from(text, 'latin1');
}

/** Returns one message for each vendored file that does not match its pin. */
function vendoredFileMismatches(root = repoRoot) {
  const pins = readPins(root);
  const mismatches = [];
  for (const [name, pin] of Object.entries(pins.files)) {
    const where = `${ENGINE_DIRECTORY}/${name}`;
    const vendored = readFileSync(join(root, ENGINE_DIRECTORY, name));
    const actual = sha256(vendored);
    if (actual !== pin.sha256) {
      mismatches.push(`${where}: sha256 ${actual}, pinned ${pin.sha256}`);
      continue;
    }
    const recorded = patchesFor(name).map((patch) => patch.id);
    if (JSON.stringify(recorded) !== JSON.stringify(pin.patches)) {
      mismatches.push(`${where}: patches ${JSON.stringify(recorded)}, pinned ${JSON.stringify(pin.patches)}`);
      continue;
    }
    try {
      const unpatched = sha256(removePatches(name, vendored));
      if (unpatched !== pin.releaseSha256) {
        mismatches.push(`${where} without its patches: sha256 ${unpatched}, released ${pin.releaseSha256}`);
      }
    } catch (error) {
      mismatches.push(`${where}: ${error.message}`);
    }
  }
  return mismatches;
}

function assertVendoredFiles(root) {
  const mismatches = vendoredFileMismatches(root);
  if (mismatches.length > 0) {
    throw new Error(`Vendored SQLite engine does not match pins.json:\n${mismatches.join('\n')}`);
  }
}

function copy(distArgument) {
  if (!distArgument) throw new Error('Usage: sqlite-engine.mjs copy <dist>');
  assertVendoredFiles(repoRoot);
  const target = join(resolve(distArgument), ENGINE_DIRECTORY);
  mkdirSync(target, { recursive: true });
  for (const name of Object.keys(readPins().files)) {
    copyFileSync(join(repoRoot, ENGINE_DIRECTORY, name), join(target, name));
  }
}

async function download(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`GET ${url}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Downloads the release, checks its signature and its pins, and returns the
 * released bytes of each pinned file.
 */
async function releasedFiles(pins) {
  const workDirectory = mkdtempSync(join(tmpdir(), 'sqlite-engine-'));
  try {
    const sums = join(workDirectory, 'SHA256SUMS');
    const signature = join(workDirectory, 'SHA256SUMS.sig');
    const certificate = join(workDirectory, 'SHA256SUMS.pem');
    const archive = join(workDirectory, 'engine.zip');
    writeFileSync(sums, await download(pins.checksums.url));
    writeFileSync(signature, await download(pins.checksums.signatureUrl));
    writeFileSync(certificate, await download(pins.checksums.certificateUrl));
    writeFileSync(archive, await download(pins.archive.url));

    execFileSync(
      'cosign',
      [
        'verify-blob',
        '--certificate', certificate,
        '--signature', signature,
        '--certificate-identity', pins.signer.identity,
        '--certificate-oidc-issuer', pins.signer.issuer,
        sums,
      ],
      { stdio: 'inherit' }
    );

    const archiveName = new URL(pins.archive.url).pathname.split('/').pop();
    const listed = readFileSync(sums, 'utf8')
      .split('\n')
      .map((line) => line.trim().split(/\s+\*?/))
      .find(([, name]) => name === archiveName);
    if (!listed) throw new Error(`SHA256SUMS does not list ${archiveName}`);
    if (listed[0] !== pins.archive.sha256) {
      throw new Error(`SHA256SUMS lists ${listed[0]} for ${archiveName}, pinned ${pins.archive.sha256}`);
    }
    const archiveHash = sha256(readFileSync(archive));
    if (archiveHash !== pins.archive.sha256) {
      throw new Error(`${archiveName}: sha256 ${archiveHash}, pinned ${pins.archive.sha256}`);
    }

    const files = new Map();
    for (const [name, pin] of Object.entries(pins.files)) {
      const released = execFileSync('unzip', ['-p', archive, pin.archivePath], {
        maxBuffer: 64 * 1024 * 1024,
      });
      const releasedHash = sha256(released);
      if (releasedHash !== pin.releaseSha256) {
        throw new Error(`${pin.archivePath} in the archive: sha256 ${releasedHash}, pinned ${pin.releaseSha256}`);
      }
      files.set(name, released);
    }
    return files;
  } finally {
    rmSync(workDirectory, { recursive: true, force: true });
  }
}

async function verifyRelease() {
  const pins = readPins();
  for (const [name, released] of await releasedFiles(pins)) {
    const vendored = readFileSync(join(repoRoot, ENGINE_DIRECTORY, name));
    if (!applyPatches(name, released).equals(vendored)) {
      throw new Error(`${ENGINE_DIRECTORY}/${name} is not the released file with its recorded patches`);
    }
  }
  assertVendoredFiles(repoRoot);
  console.log(
    `sqlite-engine: ${pins.release} signed by ${pins.signer.identity}; ` +
      'the vendored files are the released files with their recorded patches'
  );
}

async function vendor() {
  const pins = readPins();
  for (const [name, released] of await releasedFiles(pins)) {
    const patched = applyPatches(name, released);
    writeFileSync(join(repoRoot, ENGINE_DIRECTORY, name), patched);
    pins.files[name].patches = patchesFor(name).map((patch) => patch.id);
    pins.files[name].sha256 = sha256(patched);
  }
  writePins(pins);
  assertVendoredFiles(repoRoot);
  console.log(`sqlite-engine: wrote the ${pins.release} files with their recorded patches`);
}

const [command, argument] = process.argv.slice(2);
if (command === 'copy') {
  copy(argument);
} else if (command === 'verify-release') {
  await verifyRelease();
} else if (command === 'vendor') {
  await vendor();
} else {
  console.error('Usage: sqlite-engine.mjs copy <dist> | verify-release | vendor');
  process.exit(2);
}
