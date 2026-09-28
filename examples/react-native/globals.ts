// Logcat cuts a line at about 4,000 bytes, so the list goes out in parts.
const PART_CHARACTERS = 900;

/**
 * Log every global name that the app has when the SDK runs, sorted, and the
 * members of `crypto`. Each part is one `Globals <part>/<parts>:` line.
 */
export function logGlobals(log: (line: string) => void): void {
  const names = Object.getOwnPropertyNames(globalThis).sort();
  const parts: string[] = [];
  let part = '';
  for (const name of names) {
    if (part.length > 0 && part.length + name.length + 1 > PART_CHARACTERS) {
      parts.push(part);
      part = '';
    }
    part = part.length === 0 ? name : `${part} ${name}`;
  }
  if (part.length > 0) parts.push(part);
  parts.forEach((line, index) => log(`Globals ${index + 1}/${parts.length}: ${line}`));
  log(`Global names: ${names.length}`);

  const crypto = (globalThis as { crypto?: object }).crypto;
  const members = crypto === undefined ? [] : Object.getOwnPropertyNames(crypto).sort();
  log(`Global crypto members: ${members.length === 0 ? 'none' : members.join(' ')}`);
}
