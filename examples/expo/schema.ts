export * from '@open-e2ee/signal-protocol-sdk/local/store/expo/schema';
import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';

export const exampleState = sqliteTable('example_state', {
  id: integer('id').primaryKey(),
  attempts: integer('attempts').notNull().default(0),
  completed: integer('completed').notNull().default(0),
  identityPublic: text('identity_public'),
});
