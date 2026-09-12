CREATE TABLE `example_state` (
	`id` integer PRIMARY KEY NOT NULL,
	`attempts` integer DEFAULT 0 NOT NULL,
	`completed` integer DEFAULT 0 NOT NULL,
	`identity_public` text
);
