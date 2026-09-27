CREATE TABLE `__new_kyber_prekeys` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`instance_id` text NOT NULL,
	`identity_type` text DEFAULT 'aci' NOT NULL,
	`prekey_id` integer NOT NULL,
	`public_key` text NOT NULL,
	`private_key` text NOT NULL,
	`signature` text,
	`timestamp` integer NOT NULL,
	`created_at` integer NOT NULL,
	`replaced_at` integer
);
--> statement-breakpoint
INSERT INTO `__new_kyber_prekeys`("id", "instance_id", "identity_type", "prekey_id", "public_key", "private_key", "signature", "timestamp", "created_at", "replaced_at") SELECT "id", lower(hex(randomblob(32))), "identity_type", "prekey_id", "public_key", "private_key", "signature", "timestamp", "created_at", "replaced_at" FROM `kyber_prekeys`;--> statement-breakpoint
DROP TABLE `kyber_prekeys`;--> statement-breakpoint
ALTER TABLE `__new_kyber_prekeys` RENAME TO `kyber_prekeys`;--> statement-breakpoint
UPDATE `kyber_prekeys` SET "replaced_at" = "created_at" WHERE "replaced_at" IS NULL AND "id" NOT IN (SELECT max("id") FROM `kyber_prekeys` WHERE "replaced_at" IS NULL GROUP BY "identity_type");--> statement-breakpoint
CREATE UNIQUE INDEX `kyber_prekey_instance` ON `kyber_prekeys` (`instance_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `kyber_prekey_identity` ON `kyber_prekeys` (`identity_type`,`prekey_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `kyber_prekey_current_identity` ON `kyber_prekeys` (`identity_type`) WHERE "kyber_prekeys"."replaced_at" IS NULL;--> statement-breakpoint
CREATE INDEX `idx_kyber_prekeys_timestamp` ON `kyber_prekeys` (`timestamp`);--> statement-breakpoint
CREATE TABLE `__new_kyber_prekey_used` (
	`kyber_prekey_row_id` integer NOT NULL,
	`signed_prekey_identity` text NOT NULL,
	`signed_prekey_id` integer NOT NULL,
	`base_key` text NOT NULL,
	PRIMARY KEY(`kyber_prekey_row_id`, `signed_prekey_identity`, `signed_prekey_id`, `base_key`),
	FOREIGN KEY (`kyber_prekey_row_id`) REFERENCES `kyber_prekeys`(`id`) ON UPDATE cascade ON DELETE cascade
);
--> statement-breakpoint
INSERT INTO `__new_kyber_prekey_used`("kyber_prekey_row_id", "signed_prekey_identity", "signed_prekey_id", "base_key") SELECT `kyber_prekeys`."id", `kyber_prekey_used`."signed_prekey_identity", `kyber_prekey_used`."signed_prekey_id", `kyber_prekey_used`."base_key" FROM `kyber_prekey_used` INNER JOIN `kyber_prekeys` ON `kyber_prekeys`."identity_type" = `kyber_prekey_used`."signed_prekey_identity" AND `kyber_prekeys`."prekey_id" = `kyber_prekey_used`."kyber_prekey_id";--> statement-breakpoint
DROP TABLE `kyber_prekey_used`;--> statement-breakpoint
ALTER TABLE `__new_kyber_prekey_used` RENAME TO `kyber_prekey_used`;
