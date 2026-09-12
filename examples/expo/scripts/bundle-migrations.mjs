import { readFile, writeFile } from 'node:fs/promises';

const root = new URL('../drizzle/', import.meta.url);
const journal = JSON.parse(await readFile(new URL('meta/_journal.json', root), 'utf8'));
const migrations = {};
for (const entry of journal.entries) {
  migrations[`m${String(entry.idx).padStart(4, '0')}`] = await readFile(new URL(`${entry.tag}.sql`, root), 'utf8');
}
await writeFile(new URL('migrations.json', root), `${JSON.stringify({ journal, migrations }, null, 2)}\n`);
