/*
 * Installs the Android SDK packages that a Gradle build downloads on demand,
 * before the build runs, and tries each part again after a failed download.
 *
 * The Android Gradle plugin downloads a missing SDK package once, when the
 * build first needs it, and fails the build after a failed or corrupt
 * download. It installs the NDK, the platform, and the build tools when it
 * configures the projects, and CMake when a `configureCMake` task runs. The
 * first part runs `gradlew help`, which configures every project. When the
 * command names a build task, the second part runs the `configureCMake` tasks
 * that a dry run of that build task lists. The build then finds each package
 * in place.
 *
 * Each part uses the Gradle arguments of the build, so the build uses the
 * same Gradle daemon, and the tasks have the same inputs. Before the next try
 * of a part, the script deletes each SDK package directory that an install
 * did not complete, and the download directories of the SDK manager. A
 * failure that is not a download fails again, so the part fails after three
 * tries.
 *
 * Usage:
 *   node ./scripts/prefetch-android-sdk.mjs <android-project-dir> [<build-task> <gradle-argument>...]
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';

const usage =
  'Usage: node scripts/prefetch-android-sdk.mjs <android-project-dir> [<build-task> <gradle-argument>...]';
const tries = 3;

/** The SDK directories where the Android Gradle plugin installs packages on demand. */
const packageGroups = ['build-tools', 'cmake', 'ndk', 'platforms'];

const [projectArgument, buildTask, ...gradleArguments] = process.argv.slice(2);
if (!projectArgument) throw new Error(usage);
const projectDir = resolve(projectArgument);
const sdk = process.env.ANDROID_HOME;
if (!sdk) throw new Error('ANDROID_HOME is not set.');

function gradle(args, stdout = 'inherit') {
  console.log(`$ ./gradlew ${args.join(' ')}`);
  const result = spawnSync('./gradlew', args, {
    cwd: projectDir,
    encoding: 'utf8',
    stdio: ['ignore', stdout, 'inherit'],
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  return result;
}

/** Deletes each package directory without `package.xml` or `source.properties`, and the download directories. */
function deleteIncompletePackages() {
  for (const group of packageGroups) {
    const groupDir = join(sdk, group);
    if (!existsSync(groupDir)) continue;
    for (const entry of readdirSync(groupDir, { withFileTypes: true })) {
      const dir = join(groupDir, entry.name);
      if (!entry.isDirectory()) continue;
      if (existsSync(join(dir, 'package.xml')) && existsSync(join(dir, 'source.properties'))) continue;
      console.log(`Deleting the incomplete package ${dir}`);
      rmSync(dir, { recursive: true, force: true });
    }
  }
  for (const name of ['.temp', '.downloadIntermediates']) {
    rmSync(join(sdk, name), { recursive: true, force: true });
  }
}

function withTries(part, run) {
  for (let attempt = 1; attempt <= tries; attempt += 1) {
    if (run()) return;
    console.log(`Try ${attempt} of ${tries} to ${part} failed.`);
    if (attempt < tries) deleteIncompletePackages();
  }
  throw new Error(`Every try to ${part} failed.`);
}

/** The `configureCMake` tasks that the build task runs, from a dry run, or null when the dry run fails. */
function configureCMakeTasks() {
  const dryRun = gradle([buildTask, '--dry-run', ...gradleArguments], 'pipe');
  if (dryRun.status !== 0) {
    process.stdout.write(dryRun.stdout);
    return null;
  }
  const tasks = [...dryRun.stdout.matchAll(/^(\S*:configureCMake\S*) SKIPPED$/gm)].map((match) => match[1]);
  if (tasks.length === 0) throw new Error(`A dry run of ${buildTask} lists no configureCMake task.\n${dryRun.stdout}`);
  console.log(`The build runs ${tasks.length} configureCMake tasks: ${tasks.join(' ')}`);
  return tasks;
}

withTries('configure every project', () => gradle(['help', ...gradleArguments]).status === 0);

if (buildTask) {
  withTries('run the configureCMake tasks', () => {
    const tasks = configureCMakeTasks();
    return tasks !== null && gradle([...tasks, ...gradleArguments]).status === 0;
  });
}
