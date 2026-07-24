/**
 * Username Nickname Generation
 *
 * Generates random nicknames using adjective + animal word combinations.
 * Used during user registration for Signal-compliant username assignment.
 */

import { uniqueNamesGenerator, adjectives, animals } from 'unique-names-generator';
export {};
export function generateNickname(): string {
  return uniqueNamesGenerator({
    dictionaries: [adjectives, animals],
    separator: '_',
    length: 2,
    style: 'lowerCase',
  });
}
