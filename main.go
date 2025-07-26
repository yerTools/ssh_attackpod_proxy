package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Migration struct {
	Version int
	SQL     string
}

// migrations is a list of database migrations. The version number should be incremental.
var migrations = []Migration{
	{
		Version: 1,
		SQL: `
		CREATE TABLE IF NOT EXISTS attacks (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"source_ip" TEXT,
			"destination_ip" TEXT,
			"username" TEXT,
			"password" TEXT,
			"attack_timestamp" INTEGER,
			"evidence" TEXT,
			"attack_type" TEXT
		);
		
		CREATE INDEX IF NOT EXISTS idx_attacks_source_ip ON attacks (source_ip, attack_timestamp);
		CREATE INDEX IF NOT EXISTS idx_attacks_destination_ip ON attacks (destination_ip, attack_timestamp);
		CREATE INDEX IF NOT EXISTS idx_attacks_source_destination ON attacks (source_ip, destination_ip, attack_timestamp);
	
		CREATE INDEX IF NOT EXISTS idx_attacks_attack_type ON attacks (attack_type, attack_timestamp);
		CREATE INDEX IF NOT EXISTS idx_attacks_evidence ON attacks (evidence, attack_timestamp);
	
		CREATE INDEX IF NOT EXISTS idx_attacks_attack_timestamp ON attacks (attack_timestamp);
	
		CREATE INDEX IF NOT EXISTS idx_attacks_username ON attacks (username, attack_timestamp);
		CREATE INDEX IF NOT EXISTS idx_attacks_password ON attacks (password, attack_timestamp);
		CREATE INDEX IF NOT EXISTS idx_attacks_username_password ON attacks (username, password, attack_timestamp);
		
		DROP VIEW IF EXISTS "view_usernames";
		CREATE VIEW "view_usernames" AS
			SELECT 
				"username",
				COUNT(1) AS "count"
			FROM "attacks" 
			GROUP BY "username" 
			ORDER BY 
				"count" DESC,
				"username" ASC;
	
		DROP VIEW IF EXISTS "view_passwords";
		CREATE VIEW "view_passwords" AS
			SELECT 
				"password",
				COUNT(1) AS "count"
			FROM "attacks" 
			GROUP BY "password" 
			ORDER BY 
				"count" DESC,
				"password" ASC;
	
		DROP VIEW IF EXISTS "view_source_ips";
		CREATE VIEW "view_source_ips" AS
			SELECT 
				"source_ip",
				COUNT(1) AS "count"
			FROM "attacks" 
			GROUP BY "source_ip" 
			ORDER BY 
				"count" DESC,
				"source_ip" ASC;
	
		DROP VIEW IF EXISTS "view_log";
		CREATE VIEW "view_log" AS
			SELECT
				strftime('%F %T', strftime('%F %T', "attack_timestamp" / 1000, 'unixepoch'), 'localtime') AS "time",
				"source_ip" AS "source",
				"username",
				"password"
			FROM "attacks"
			ORDER BY "attack_timestamp" DESC;
	
		DROP VIEW IF EXISTS "view_daily_attacks";
		CREATE VIEW "view_daily_attacks" AS
			SELECT
				strftime('%F', strftime('%F %T', "attack_timestamp" / 1000, 'unixepoch'), 'localtime') AS "date",
				COUNT(*) AS "count"
			FROM "attacks"
			GROUP BY "date"
			ORDER BY "date" DESC;
	
		DROP VIEW IF EXISTS "view_daily_usernames";
		CREATE VIEW "view_daily_usernames" AS
			SELECT
				strftime('%F', strftime('%F %T', "attack_timestamp" / 1000, 'unixepoch'), 'localtime') AS "date",
				"username",
				COUNT(*) AS "count"
			FROM "attacks"
			GROUP BY 
				"date",
				"username"
			ORDER BY 
				"date" DESC,
				"count" DESC,
				"username" ASC;
	
		DROP VIEW IF EXISTS "view_daily_passwords";
		CREATE VIEW "view_daily_passwords" AS
			SELECT
				strftime('%F', strftime('%F %T', "attack_timestamp" / 1000, 'unixepoch'), 'localtime') AS "date",
				"password",
				COUNT(*) AS "count"
			FROM "attacks"
			GROUP BY 
				"date",
				"password"
			ORDER BY 
				"date" DESC,
				"count" DESC,
				"password" ASC;
	
		DROP VIEW IF EXISTS "view_daily_source_ips";
		CREATE VIEW "view_daily_source_ips" AS
			SELECT
				strftime('%F', strftime('%F %T', "attack_timestamp" / 1000, 'unixepoch'), 'localtime') AS "date",
				"source_ip",
				COUNT(*) AS "count"
			FROM "attacks"
			GROUP BY 
				"date",
				"source_ip"
			ORDER BY 
				"date" DESC,
				"count" DESC,
				"source_ip" ASC;
		`,
	},
	{
		Version: 2,
		SQL: `
		-- Delete duplicate entries, keeping the one with the lowest ID.
		DELETE FROM attacks
		WHERE id NOT IN (
			SELECT MIN(id)
			FROM attacks
			GROUP BY source_ip, destination_ip, username, password, attack_timestamp, evidence, attack_type
		);

		-- Create a unique index to prevent future duplicates.
		CREATE UNIQUE INDEX IF NOT EXISTS idx_attacks_unique_attack ON attacks (
			source_ip,
			destination_ip,
			username,
			password,
			attack_timestamp,
			evidence,
			attack_type
		);
		`,
	},
	{
		Version: 3,
		SQL: `
		-- View: Aggregiert Angriffe pro Minute und stellt diverse Zeit-Komponenten für flexible Analysen bereit.
		-- Damit lassen sich leicht Abfragen für Muster nach Wochentag, Tageszeit etc. erstellen.
		DROP VIEW IF EXISTS "view_attacks_by_time";
		CREATE VIEW "view_attacks_by_time" AS
			SELECT
				strftime('%Y-%m-%d', "attack_timestamp" / 1000, 'unixepoch', 'localtime') AS "date",
				strftime('%m', "attack_timestamp" / 1000, 'unixepoch', 'localtime') AS "month",
				strftime('%W', "attack_timestamp" / 1000, 'unixepoch', 'localtime') AS "week_of_year",
				strftime('%w', "attack_timestamp" / 1000, 'unixepoch', 'localtime') AS "weekday",
				strftime('%d', "attack_timestamp" / 1000, 'unixepoch', 'localtime') AS "day_of_month",
				strftime('%H', "attack_timestamp" / 1000, 'unixepoch', 'localtime') AS "hour_of_day",
				strftime('%M', "attack_timestamp" / 1000, 'unixepoch', 'localtime') AS "minute_of_hour",
				COUNT(1) AS "count"
			FROM "attacks"
			GROUP BY
				"date",
				"hour_of_day",
				"minute_of_hour"
			ORDER BY
				"date" ASC,
				"hour_of_day" ASC,
				"minute_of_hour" ASC;

		-- View: Top-Kombinationen aus Benutzername und Passwort.
		-- Zeigt, welche Credentials am häufigsten zusammen verwendet werden.
		DROP VIEW IF EXISTS "view_logins";
		CREATE VIEW "view_logins" AS
			SELECT 
				"username",
				"password",
				COUNT(1) AS "count"
			FROM "attacks" 
			GROUP BY 
				"username", 
				"password" 
			ORDER BY 
				"count" DESC,
				"username" ASC,
				"password" ASC;

		-- View: Analysiert Angriffsmuster pro Angreifer-IP.
		-- Zeigt den ersten und letzten Angriff, die Gesamtzahl und die Anzahl der einzigartigen Benutzernamen.
		-- Hilft, automatisierte Scans von gezielteren Angriffen zu unterscheiden.
		DROP VIEW IF EXISTS "view_attack_patterns_by_source";
		CREATE VIEW "view_attack_patterns_by_source" AS
			SELECT
				"source_ip",
				COUNT(1) AS "total_attacks",
				COUNT(DISTINCT "username") AS "unique_usernames",
				COUNT(DISTINCT "password") AS "unique_passwords",
				COUNT(DISTINCT ("username" || ' <-| username @ password |-> ' || "password")) AS "unique_logins",
				MIN(strftime('%Y-%m-%d %H:%M:%S', "attack_timestamp" / 1000, 'unixepoch', 'localtime')) AS "first_seen",
				MAX(strftime('%Y-%m-%d %H:%M:%S', "attack_timestamp" / 1000, 'unixepoch', 'localtime')) AS "last_seen"
			FROM "attacks"
			GROUP BY
				"source_ip"
			ORDER BY
				"total_attacks" DESC,
				"source_ip" ASC;

		-- View: Erstellt "Fingerabdrücke" von Passwortlisten oder Angreifern.
		-- Analysiert, wie verbreitet eine Username/Passwort-Kombination ist.
		-- Ein Paar, das von nur einer IP genutzt wird (distinct_source_ips = 1), ist ein starker Indikator für eine spezifische Liste oder einen gezielten Angriff.
		DROP VIEW IF EXISTS "view_credential_fingerprints";
		CREATE VIEW "view_credential_fingerprints" AS
			SELECT
				"username",
				"password",
				COUNT(1) AS "total_uses",
				COUNT(DISTINCT "source_ip") AS "distinct_source_ips",
				MIN(strftime('%Y-%m-%d %H:%M:%S', "attack_timestamp" / 1000, 'unixepoch', 'localtime')) AS "first_seen",
				MAX(strftime('%Y-%m-%d %H:%M:%S', "attack_timestamp" / 1000, 'unixepoch', 'localtime')) AS "last_seen",
				GROUP_CONCAT(DISTINCT "source_ip") AS "source_ips"
			FROM "attacks"
			GROUP BY
				"username",
				"password"
			ORDER BY
				"distinct_source_ips" ASC,
				"total_uses" DESC,
				"last_seen" DESC,
				"username" ASC,
				"password" ASC;

		-- Report: Top 20 Angreifer der letzten 24 Stunden.
		DROP VIEW IF EXISTS "report_top_attackers_last_24_hours";
		CREATE VIEW "report_top_attackers_last_24_hours" AS
			SELECT 
				"source_ip",
				COUNT(1) AS "count"
			FROM "attacks" 
			WHERE "attack_timestamp" >= (strftime('%s', 'now', '-1 day') * 1000)
			GROUP BY "source_ip" 
			ORDER BY
				"count" DESC,
				"source_ip" ASC
			LIMIT 20;

		-- Report: Top 20 der in den letzten 7 Tagen am häufigsten getesteten Benutzernamen.
		DROP VIEW IF EXISTS "report_top_usernames_last_7_days";
		CREATE VIEW "report_top_usernames_last_7_days" AS
			SELECT 
				"username",
				COUNT(1) AS "count"
			FROM "attacks" 
			WHERE "attack_timestamp" >= (strftime('%s', 'now', '-7 days') * 1000)
			GROUP BY "username" 
			ORDER BY 
				"count" DESC,
				"username" ASC
			LIMIT 20;

		-- Report: Top 20 der in den letzten 7 Tagen am häufigsten verwendeten Passwörter.
		DROP VIEW IF EXISTS "report_top_passwords_last_7_days";
		CREATE VIEW "report_top_passwords_last_7_days" AS
			SELECT 
				"password",
				COUNT(1) AS "count"
			FROM "attacks" 
			WHERE "attack_timestamp" >= (strftime('%s', 'now', '-7 days') * 1000)
			GROUP BY "password" 
			ORDER BY 
				"count" DESC,
				"password" ASC
			LIMIT 20;

		-- Report: Neue, "einzigartige" Anmeldeinformationen, die in den letzten 7 Tagen zum ersten Mal gesehen wurden.
		-- Dies filtert die Fingerprint-Ansicht, um nur kürzlich erschienene, seltene Anmeldeinformationen anzuzeigen.
		DROP VIEW IF EXISTS "report_new_credential_fingerprints_last_7_days";
		CREATE VIEW "report_new_credential_fingerprints_last_7_days" AS
			SELECT
				*
			FROM "view_credential_fingerprints"
			WHERE 
				"distinct_source_ips" = 1 AND
				"first_seen" >= strftime('%Y-%m-%d %H:%M:%S', 'now', '-7 days', 'localtime');

		-- View: Analysiert die "Streuung" von Angriffen pro Benutzername.
		-- Vergleicht die Gesamtzahl der Versuche mit der Anzahl der einzigartigen Angreifer.
		-- Ideal für ein Streudiagramm (Scatter Plot), um die Verbreitung von Usernames in Passwortlisten zu bewerten.
		DROP VIEW IF EXISTS "view_attack_spread_by_username";
		CREATE VIEW "view_attack_spread_by_username" AS
			SELECT
				"username",
				COUNT(1) AS "total_attempts",
				COUNT(DISTINCT "source_ip") AS "distinct_attackers"
			FROM "attacks"
			GROUP BY
				"username"
			ORDER BY
				"total_attempts" DESC,
				"distinct_attackers" DESC,
				"username" ASC;

		-- Report: Stündliche Angriffe der letzten 7 Tage.
		DROP VIEW IF EXISTS "report_hourly_attacks_last_7_days";
		CREATE VIEW "report_hourly_attacks_last_7_days" AS
			SELECT
				"time" as "from_time",
				strftime('%F %T', "time", '+1 hour') AS "to_time",
				"total_attacks"
			FROM (
				SELECT
					"date" || ' ' || "hour_of_day" || ':00:00' AS "time",
					SUM("count") AS "total_attacks"
				FROM "view_attacks_by_time"
				WHERE 
					"time" >= strftime('%F %H:00:00', 'now', '-7 days', 'localtime')
				GROUP BY
					"date",
					"hour_of_day"
				ORDER BY
					"time" ASC
			) AS hourly_data;

		-- Report: Tägliche Angriffe der letzten 90 Tage.
		DROP VIEW IF EXISTS "report_daily_attacks_last_90_days";
		CREATE VIEW "report_daily_attacks_last_90_days" AS
			SELECT
				"time" as "from_time",
				strftime('%F %T', "time", '+1 day') AS "to_time",
				"total_attacks"
			FROM (
				SELECT
					"date" || ' 00:00:00' AS "time",
					SUM("count") AS "total_attacks"
				FROM "view_attacks_by_time"
				WHERE
					"time" >= strftime('%F 00:00:00', 'now', '-90 days', 'localtime')
				GROUP BY
					"date"
				ORDER BY
					"time" ASC
			) AS daily_data;
		`,
	},
	{
		Version: 4,
		SQL: `
		-- Report: Top 20 der in den letzten 7 Tagen am häufigsten verwendeten Logins.
		DROP VIEW IF EXISTS "report_top_logins_last_7_days";
		CREATE VIEW "report_top_logins_last_7_days" AS
			SELECT
				"username",
				"password",
				COUNT(1) AS "count"
			FROM "attacks"
			WHERE "attack_timestamp" >= (strftime('%s', 'now', '-7 days') * 1000)
			GROUP BY "username", "password"
			ORDER BY 
				"count" DESC,
				"username" ASC,
				"password" ASC
			LIMIT 20;
		`,
	},
	{
		Version: 5,
		SQL: `
		-- Trim whitespace, tabs, and newlines from the beginning and end of the evidence field.
		UPDATE attacks
		SET evidence = TRIM(evidence, ' ' || CHAR(9) || CHAR(10) || CHAR(13))
		WHERE evidence IS NOT NULL;
		`,
	},
	{
		Version: 6,
		SQL: `
			-- Drop every index.
			DROP INDEX IF EXISTS "idx_attacks_source_ip";
			DROP INDEX IF EXISTS "idx_attacks_destination_ip";
			DROP INDEX IF EXISTS "idx_attacks_source_destination";
			DROP INDEX IF EXISTS "idx_attacks_attack_type";
			DROP INDEX IF EXISTS "idx_attacks_evidence";
			DROP INDEX IF EXISTS "idx_attacks_attack_timestamp";
			DROP INDEX IF EXISTS "idx_attacks_username";
			DROP INDEX IF EXISTS "idx_attacks_password";
			DROP INDEX IF EXISTS "idx_attacks_username_password";
			DROP INDEX IF EXISTS "idx_attacks_unique_attack";

			-- Drop every view.
			DROP VIEW IF EXISTS "view_usernames";
			DROP VIEW IF EXISTS "view_passwords";
			DROP VIEW IF EXISTS "view_source_ips";
			DROP VIEW IF EXISTS "view_log";
			DROP VIEW IF EXISTS "view_daily_attacks";
			DROP VIEW IF EXISTS "view_daily_usernames";
			DROP VIEW IF EXISTS "view_daily_passwords";
			DROP VIEW IF EXISTS "view_daily_source_ips";
			DROP VIEW IF EXISTS "view_attacks_by_time";
			DROP VIEW IF EXISTS "view_logins";
			DROP VIEW IF EXISTS "view_attack_patterns_by_source";
			DROP VIEW IF EXISTS "view_credential_fingerprints";
			DROP VIEW IF EXISTS "report_top_attackers_last_24_hours";
			DROP VIEW IF EXISTS "report_top_usernames_last_7_days";
			DROP VIEW IF EXISTS "report_top_passwords_last_7_days";
			DROP VIEW IF EXISTS "report_new_credential_fingerprints_last_7_days";
			DROP VIEW IF EXISTS "view_attack_spread_by_username";
			DROP VIEW IF EXISTS "report_hourly_attacks_last_7_days";
			DROP VIEW IF EXISTS "report_daily_attacks_last_90_days";
			DROP VIEW IF EXISTS "report_top_logins_last_7_days";

			-- Rename the old attacks table to attacks_old.
			ALTER TABLE "attacks" RENAME TO "attacks_old";

			-- Create universal sentence tables.
			CREATE TABLE "_sentence_words" (
				"id" INTEGER NOT NULL UNIQUE,
				"word" TEXT NOT NULL UNIQUE,
				PRIMARY KEY("id" AUTOINCREMENT)
			);
			CREATE TABLE "_sentences" (
				"id" INTEGER NOT NULL,
				"index" INTEGER NOT NULL,
				"word_id" INTEGER NOT NULL,
				FOREIGN KEY("word_id") REFERENCES "_sentence_words"("id"),
				PRIMARY KEY("id", "index")
			);

			-- Create dictionary tables.
			CREATE TABLE "_dict_source_ips" (
				"id"	INTEGER NOT NULL UNIQUE,
				"value"	TEXT NOT NULL UNIQUE,
				PRIMARY KEY("id" AUTOINCREMENT)
			);
			CREATE TABLE "_dict_destination_ips" (
				"id"	INTEGER NOT NULL UNIQUE,
				"value"	TEXT NOT NULL UNIQUE,
				PRIMARY KEY("id" AUTOINCREMENT)
			);
			CREATE TABLE "_dict_usernames" (
				"id"	INTEGER NOT NULL UNIQUE,
				"value"	TEXT NOT NULL UNIQUE,
				PRIMARY KEY("id" AUTOINCREMENT)
			);
			CREATE TABLE "_dict_passwords" (
				"id"	INTEGER NOT NULL UNIQUE,
				"value"	TEXT NOT NULL UNIQUE,
				PRIMARY KEY("id" AUTOINCREMENT)
			);
			CREATE TABLE "_dict_attack_types" (
				"id"	INTEGER NOT NULL UNIQUE,
				"value"	TEXT NOT NULL UNIQUE,
				PRIMARY KEY("id" AUTOINCREMENT)
			);
			CREATE TABLE "_dict_evidences" (
				"id"	INTEGER NOT NULL UNIQUE,
				"value"	TEXT NOT NULL UNIQUE,
				PRIMARY KEY("id" AUTOINCREMENT)
			);

			-- Create the new _attacks table with foreign keys to the dictionaries.
			CREATE TABLE "_attacks" (
				"id"	INTEGER NOT NULL UNIQUE,
				"timestamp"	INTEGER NOT NULL,
				"source_ip"	INTEGER NOT NULL,
				"destination_ip"	INTEGER NOT NULL,
				"username"	INTEGER NOT NULL,
				"password"	INTEGER NOT NULL,
				"attack_type"	INTEGER NOT NULL,
				"evidence"	INTEGER NOT NULL,
				FOREIGN KEY("source_ip") REFERENCES "_dict_source_ips"("id"),
				FOREIGN KEY("destination_ip") REFERENCES "_dict_destination_ips"("id"),
				FOREIGN KEY("username") REFERENCES "_dict_usernames"("id"),
				FOREIGN KEY("password") REFERENCES "_dict_passwords"("id"),
				FOREIGN KEY("attack_type") REFERENCES "_dict_attack_types"("id"),
				FOREIGN KEY("evidence") REFERENCES "_dict_evidences"("id"),
				PRIMARY KEY("id" AUTOINCREMENT)
			);

			-- Create the new attacks view.
			CREATE VIEW "attacks" AS
				SELECT
					"_attacks"."id",
					"_attacks"."timestamp",
					"_dict_source_ips"."value" AS "source_ip",
					"_dict_destination_ips"."value" AS "destination_ip",
					"_dict_usernames"."value" AS "username",
					"_dict_passwords"."value" AS "password",
					"_dict_attack_types"."value" AS "attack_type",
					"_dict_evidences"."value" AS "evidence"
				FROM "_attacks"
				JOIN "_dict_source_ips" ON "_attacks"."source_ip" = "_dict_source_ips"."id"
				JOIN "_dict_destination_ips" ON "_attacks"."destination_ip" = "_dict_destination_ips"."id"
				JOIN "_dict_usernames" ON "_attacks"."username" = "_dict_usernames"."id"
				JOIN "_dict_passwords" ON "_attacks"."password" = "_dict_passwords"."id"
				JOIN "_dict_attack_types" ON "_attacks"."attack_type" = "_dict_attack_types"."id"
				JOIN "_dict_evidences" ON "_attacks"."evidence" = "_dict_evidences"."id";

			-- Create unique index to prevent duplicate attacks.
			CREATE UNIQUE INDEX "idx_attacks_unique" ON "_attacks" (
				"timestamp",
				"source_ip",
				"destination_ip",
				"username",
				"password",
				"attack_type",
				"evidence"
			);

			-- Delete invalid entries from the old attacks table.
			DELETE FROM "attacks_old"
			WHERE 
				"source_ip" IS NULL OR
				"destination_ip" IS NULL OR
				"username" IS NULL OR
				"password" IS NULL OR
				"attack_type" IS NULL OR
				"evidence" IS NULL;

			-- Populate the dictionaries with unique values from the old attacks table.
			INSERT INTO "_dict_source_ips" ("value")
			SELECT DISTINCT "source_ip" FROM "attacks_old";
			INSERT INTO "_dict_destination_ips" ("value")
			SELECT DISTINCT "destination_ip" FROM "attacks_old";
			INSERT INTO "_dict_usernames" ("value")
			SELECT DISTINCT "username" FROM "attacks_old";
			INSERT INTO "_dict_passwords" ("value")
			SELECT DISTINCT "password" FROM "attacks_old";
			INSERT INTO "_dict_attack_types" ("value")
			SELECT DISTINCT "attack_type" FROM "attacks_old";
			INSERT INTO "_dict_evidences" ("value")
			SELECT DISTINCT "evidence" FROM "attacks_old";

			-- Populate the new _attacks table with foreign keys from the dictionaries.
			INSERT INTO "_attacks" (
				"timestamp",
				"source_ip",
				"destination_ip",
				"username",
				"password",
				"attack_type",
				"evidence"
			)
			SELECT
				"attack_timestamp",
				(SELECT "id" FROM "_dict_source_ips" WHERE "value" = "source_ip"),
				(SELECT "id" FROM "_dict_destination_ips" WHERE "value" = "destination_ip"),
				(SELECT "id" FROM "_dict_usernames" WHERE "value" = "username"),
				(SELECT "id" FROM "_dict_passwords" WHERE "value" = "password"),
				(SELECT "id" FROM "_dict_attack_types" WHERE "value" = "attack_type"),
				(SELECT "id" FROM "_dict_evidences" WHERE "value" = "evidence")
			FROM "attacks_old";

			-- Drop the old attacks table.
			DROP TABLE "attacks_old";

			-- Recreate the views with the new attacks view.
			CREATE VIEW "view_usernames" AS
				SELECT 
					"username",
					COUNT(1) AS "count"
				FROM "attacks" 
				GROUP BY "username" 
				ORDER BY 
					"count" DESC,
					"username" ASC;
		
			CREATE VIEW "view_passwords" AS
				SELECT 
					"password",
					COUNT(1) AS "count"
				FROM "attacks" 
				GROUP BY "password" 
				ORDER BY 
					"count" DESC,
					"password" ASC;
		
			CREATE VIEW "view_source_ips" AS
				SELECT 
					"source_ip",
					COUNT(1) AS "count"
				FROM "attacks" 
				GROUP BY "source_ip" 
				ORDER BY 
					"count" DESC,
					"source_ip" ASC;
		
			CREATE VIEW "view_log" AS
				SELECT
					strftime('%F %T', strftime('%F %T', "timestamp" / 1000, 'unixepoch'), 'localtime') AS "time",
					"source_ip" AS "source",
					"username",
					"password"
				FROM "attacks"
				ORDER BY "timestamp" DESC;
		
			CREATE VIEW "view_daily_attacks" AS
				SELECT
					strftime('%F', strftime('%F %T', "timestamp" / 1000, 'unixepoch'), 'localtime') AS "date",
					COUNT(*) AS "count"
				FROM "attacks"
				GROUP BY "date"
				ORDER BY "date" DESC;
		
			CREATE VIEW "view_daily_usernames" AS
				SELECT
					strftime('%F', strftime('%F %T', "timestamp" / 1000, 'unixepoch'), 'localtime') AS "date",
					"username",
					COUNT(*) AS "count"
				FROM "attacks"
				GROUP BY 
					"date",
					"username"
				ORDER BY 
					"date" DESC,
					"count" DESC,
					"username" ASC;
		
			CREATE VIEW "view_daily_passwords" AS
				SELECT
					strftime('%F', strftime('%F %T', "timestamp" / 1000, 'unixepoch'), 'localtime') AS "date",
					"password",
					COUNT(*) AS "count"
				FROM "attacks"
				GROUP BY 
					"date",
					"password"
				ORDER BY 
					"date" DESC,
					"count" DESC,
					"password" ASC;
		
			CREATE VIEW "view_daily_source_ips" AS
				SELECT
					strftime('%F', strftime('%F %T', "timestamp" / 1000, 'unixepoch'), 'localtime') AS "date",
					"source_ip",
					COUNT(*) AS "count"
				FROM "attacks"
				GROUP BY 
					"date",
					"source_ip"
				ORDER BY 
					"date" DESC,
					"count" DESC,
					"source_ip" ASC;

			CREATE VIEW "view_attacks_by_time" AS
				SELECT
					strftime('%Y-%m-%d', "timestamp" / 1000, 'unixepoch', 'localtime') AS "date",
					strftime('%m', "timestamp" / 1000, 'unixepoch', 'localtime') AS "month",
					strftime('%W', "timestamp" / 1000, 'unixepoch', 'localtime') AS "week_of_year",
					strftime('%w', "timestamp" / 1000, 'unixepoch', 'localtime') AS "weekday",
					strftime('%d', "timestamp" / 1000, 'unixepoch', 'localtime') AS "day_of_month",
					strftime('%H', "timestamp" / 1000, 'unixepoch', 'localtime') AS "hour_of_day",
					strftime('%M', "timestamp" / 1000, 'unixepoch', 'localtime') AS "minute_of_hour",
					COUNT(1) AS "count"
				FROM "attacks"
				GROUP BY
					"date",
					"hour_of_day",
					"minute_of_hour"
				ORDER BY
					"date" ASC,
					"hour_of_day" ASC,
					"minute_of_hour" ASC;

			CREATE VIEW "view_logins" AS
				SELECT 
					"username",
					"password",
					COUNT(1) AS "count"
				FROM "attacks" 
				GROUP BY 
					"username", 
					"password" 
				ORDER BY 
					"count" DESC,
					"username" ASC,
					"password" ASC;

			CREATE VIEW "view_attack_patterns_by_source" AS
				SELECT
					"source_ip",
					COUNT(1) AS "total_attacks",
					COUNT(DISTINCT "username") AS "unique_usernames",
					COUNT(DISTINCT "password") AS "unique_passwords",
					COUNT(DISTINCT ("username" || ' <-| username @ password |-> ' || "password")) AS "unique_logins",
					MIN(strftime('%Y-%m-%d %H:%M:%S', "timestamp" / 1000, 'unixepoch', 'localtime')) AS "first_seen",
					MAX(strftime('%Y-%m-%d %H:%M:%S', "timestamp" / 1000, 'unixepoch', 'localtime')) AS "last_seen"
				FROM "attacks"
				GROUP BY
					"source_ip"
				ORDER BY
					"total_attacks" DESC,
					"source_ip" ASC;

			CREATE VIEW "view_credential_fingerprints" AS
				SELECT
					"username",
					"password",
					COUNT(1) AS "total_uses",
					COUNT(DISTINCT "source_ip") AS "distinct_source_ips",
					MIN(strftime('%Y-%m-%d %H:%M:%S', "timestamp" / 1000, 'unixepoch', 'localtime')) AS "first_seen",
					MAX(strftime('%Y-%m-%d %H:%M:%S', "timestamp" / 1000, 'unixepoch', 'localtime')) AS "last_seen",
					GROUP_CONCAT(DISTINCT "source_ip") AS "source_ips"
				FROM "attacks"
				GROUP BY
					"username",
					"password"
				ORDER BY
					"distinct_source_ips" ASC,
					"total_uses" DESC,
					"last_seen" DESC,
					"username" ASC,
					"password" ASC;

			CREATE VIEW "report_top_attackers_last_24_hours" AS
				SELECT 
					"source_ip",
					COUNT(1) AS "count"
				FROM "attacks" 
				WHERE "timestamp" >= (strftime('%s', 'now', '-1 day') * 1000)
				GROUP BY "source_ip" 
				ORDER BY
					"count" DESC,
					"source_ip" ASC
				LIMIT 20;

			CREATE VIEW "report_top_usernames_last_7_days" AS
				SELECT 
					"username",
					COUNT(1) AS "count"
				FROM "attacks" 
				WHERE "timestamp" >= (strftime('%s', 'now', '-7 days') * 1000)
				GROUP BY "username" 
				ORDER BY 
					"count" DESC,
					"username" ASC
				LIMIT 20;

			CREATE VIEW "report_top_passwords_last_7_days" AS
				SELECT 
					"password",
					COUNT(1) AS "count"
				FROM "attacks" 
				WHERE "timestamp" >= (strftime('%s', 'now', '-7 days') * 1000)
				GROUP BY "password" 
				ORDER BY 
					"count" DESC,
					"password" ASC
				LIMIT 20;

			CREATE VIEW "report_new_credential_fingerprints_last_7_days" AS
				SELECT
					*
				FROM "view_credential_fingerprints"
				WHERE 
					"distinct_source_ips" = 1 AND
					"first_seen" >= strftime('%Y-%m-%d %H:%M:%S', 'now', '-7 days', 'localtime');

			CREATE VIEW "view_attack_spread_by_username" AS
				SELECT
					"username",
					COUNT(1) AS "total_attempts",
					COUNT(DISTINCT "source_ip") AS "distinct_attackers"
				FROM "attacks"
				GROUP BY
					"username"
				ORDER BY
					"total_attempts" DESC,
					"distinct_attackers" DESC,
					"username" ASC;

			CREATE VIEW "report_hourly_attacks_last_7_days" AS
				SELECT
					"time" as "from_time",
					strftime('%F %T', "time", '+1 hour') AS "to_time",
					"total_attacks"
				FROM (
					SELECT
						"date" || ' ' || "hour_of_day" || ':00:00' AS "time",
						SUM("count") AS "total_attacks"
					FROM "view_attacks_by_time"
					WHERE 
						"time" >= strftime('%F %H:00:00', 'now', '-7 days', 'localtime')
					GROUP BY
						"date",
						"hour_of_day"
					ORDER BY
						"time" ASC
				) AS hourly_data;

			CREATE VIEW "report_daily_attacks_last_90_days" AS
				SELECT
					"time" as "from_time",
					strftime('%F %T', "time", '+1 day') AS "to_time",
					"total_attacks"
				FROM (
					SELECT
						"date" || ' 00:00:00' AS "time",
						SUM("count") AS "total_attacks"
					FROM "view_attacks_by_time"
					WHERE
						"time" >= strftime('%F 00:00:00', 'now', '-90 days', 'localtime')
					GROUP BY
						"date"
					ORDER BY
						"time" ASC
				) AS daily_data;

			CREATE VIEW "report_top_logins_last_7_days" AS
				SELECT
					"username",
					"password",
					COUNT(1) AS "count"
				FROM "attacks"
				WHERE "timestamp" >= (strftime('%s', 'now', '-7 days') * 1000)
				GROUP BY "username", "password"
				ORDER BY 
					"count" DESC,
					"username" ASC,
					"password" ASC
				LIMIT 20;
		`,
	},
}

var ErrDuplicateAttack = fmt.Errorf("duplicate attack entry")

type FlexibleTime time.Time

// UnmarshalJSON implements the json.Unmarshaler interface.
// It tries to parse the time string with multiple layouts.
func (ft *FlexibleTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), "\"")
	if s == "null" {
		return nil
	}

	// Layout for timestamps without timezone info, like Python's datetime.isoformat()
	const layoutWithoutTimezone = "2006-01-02T15:04:05.999999"

	// First, try the standard RFC3339 format.
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		// If that fails, try our custom layout without timezone.
		t, err = time.ParseInLocation(layoutWithoutTimezone, s, time.Local)
		if err != nil {
			return fmt.Errorf("failed to parse time %q with any known layout: %w", s, err)
		}
	}

	*ft = FlexibleTime(t.Local())
	return nil
}

func (ft FlexibleTime) ToTime() time.Time {
	return time.Time(ft)
}

type KnownEndpoints string

// These are the known endpoints that the attack pod python monitor uses.
//
// https://github.com/NetWatch-team/SSH-AttackPod/blob/main/src/monitor.py
const (
	EndpointCheckIP   KnownEndpoints = "/check_ip"
	EndpointAddAttack KnownEndpoints = "/add_attack"
)

type Config struct {
	ListenAddress      string
	DatabasePath       string
	ProxiedURL         *url.URL
	LogRequests        bool
	DebugLog           bool
	DoNotSubmitAttacks bool
}

type Attack struct {
	SourceIP        string       `json:"source_ip"`
	DestinationIP   string       `json:"destination_ip"`
	Username        string       `json:"username"`
	Password        string       `json:"password"`
	AttackTimestamp FlexibleTime `json:"attack_timestamp"`
	Evidence        string       `json:"evidence"`
	AttackType      string       `json:"attack_type"`
	TestMode        bool         `json:"test_mode"`
}

var db *sql.DB
var appConfig *Config
var dbMutex = &sync.Mutex{}

func strToBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "1" ||
		s == "true" || s == "t" ||
		s == "yes" || s == "y"
}

func main() {
	log.SetFlags(0)

	proxiedURLString := getEnv("NETWATCH_COLLECTOR_PROXIED_URL", "https://api.netwatch.team")
	if proxiedURLString == "" {
		log.Fatal("[FATAL] Environment variable NETWATCH_COLLECTOR_PROXIED_URL must be set!")
	}
	parsedURL, err := url.Parse(proxiedURLString)
	if err != nil {
		log.Fatalf("[FATAL] Could not parse NETWATCH_COLLECTOR_PROXIED_URL: %v", err)
	}

	logRequests := strToBool(getEnv("NETWATCH_PROXY_LOG_REQUESTS", "false"))
	debugLog := strToBool(getEnv("NETWATCH_PROXY_DEBUG_LOG", "false"))
	doNotSubmitAttacks := strToBool(getEnv("NETWATCH_PROXY_DO_NOT_SUBMIT_ATTACKS", "false"))

	appConfig = &Config{
		ListenAddress:      getEnv("NETWATCH_PROXY_LISTEN_ADDRESS", ":8161"),
		DatabasePath:       getEnv("NETWATCH_PROXY_DB_PATH", "/app/data/attacks.db"),
		ProxiedURL:         parsedURL,
		LogRequests:        logRequests || debugLog,
		DebugLog:           debugLog,
		DoNotSubmitAttacks: doNotSubmitAttacks,
	}

	initDB(appConfig.DatabasePath)
	defer db.Close()

	// A single handler for all incoming requests.
	http.HandleFunc("/", handleProxyRequest)

	log.Printf("Attack Pod Proxy started. Listening on %s. Forwarding to %s.\n", appConfig.ListenAddress, appConfig.ProxiedURL)
	if err := http.ListenAndServe(appConfig.ListenAddress, nil); err != nil {
		log.Fatalf("[FATAL] Failed to start server: %v", err)
	}
}

// handleProxyRequest manually forwards the request to ensure minimal header modification.
func handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	// Read the entire body of the incoming request.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read request body: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	r.Body.Close()

	if r.Method == http.MethodPost && r.URL.Path == string(EndpointAddAttack) {
		var attack Attack
		err := json.Unmarshal(body, &attack)
		if err != nil {
			log.Printf("[ERROR] Failed to unmarshal attack data: %v\n", err)
		} else if errDb := saveAttackToDB(&attack); errDb != nil {
			if errDb == ErrDuplicateAttack {
				if appConfig.DebugLog {
					log.Printf("[DEBUG] Skipping duplicate attack entry from %s", attack.SourceIP)
				}
			} else {
				log.Printf("[ERROR] Failed to save attack to DB: %v\n", errDb)
			}
		} else {
			timestamp := attack.AttackTimestamp.ToTime().Format("02.01. 15:04:05")
			log.Printf("%s | From: %-15s | User: %-22s | Pass: %s\n",
				timestamp, attack.SourceIP, attack.Username, attack.Password)
		}
	}

	// Construct the full destination URL.
	r.URL.Scheme = appConfig.ProxiedURL.Scheme
	r.URL.Host = appConfig.ProxiedURL.Host
	r.Host = appConfig.ProxiedURL.Host
	targetURL := appConfig.ProxiedURL.ResolveReference(r.URL)

	// Create a new request to be forwarded.
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[ERROR] Failed to create proxy request: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	proxyReq.Header = r.Header.Clone()
	proxyReq.Host = appConfig.ProxiedURL.Host

	if appConfig.LogRequests {
		log.Printf("[INFO] Forwarding request: %s %s to %s\n", r.Method, r.URL.Path, targetURL.String())
	}
	if appConfig.DebugLog {
		headerCount := 0
		for _, values := range proxyReq.Header {
			headerCount += len(values)
		}

		log.Printf("[DEBUG] Request Headers (%d):\n", headerCount)
		for key, values := range proxyReq.Header {
			for _, value := range values {
				log.Printf("[DEBUG] - %s: %s\n", key, value)
			}
		}

		log.Printf("[DEBUG] Request Body (%d bytes):\n", len(body))
		if len(body) > 0 {
			log.Printf("[DEBUG] %s\n", string(body))
		} else {
			log.Println("[DEBUG] <empty body>")
		}
	}

	var resp *http.Response
	if appConfig.DoNotSubmitAttacks && r.URL.Path == string(EndpointAddAttack) {
		if appConfig.LogRequests {
			log.Printf("[INFO] Skipping submission of attack data due to configuration and returning mockup response.")
		}

		resp = &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Length": []string{"20"},
				"Server":         []string{"SSH-AttackPod-Proxy/1.0"},
				"Date":           []string{time.Now().UTC().Format(http.TimeFormat)},
				"Content-Type":   []string{"application/json"},
			},
			Body: io.NopCloser(bytes.NewBufferString(`{"status":"success"}`)),
		}
	} else {
		client := &http.Client{Timeout: 60 * time.Second}
		resp, err = client.Do(proxyReq)
		if err != nil {
			log.Printf("[ERROR] Failed to forward request to %s: %v\n", targetURL, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
	}

	if appConfig.LogRequests {
		log.Printf("[INFO] Received response: %d from %s\n", resp.StatusCode, targetURL.String())
	}
	if appConfig.DebugLog {
		headerCount := 0
		for _, values := range resp.Header {
			headerCount += len(values)
		}

		log.Printf("[DEBUG] Response Headers (%d):\n", headerCount)
		for key, values := range resp.Header {
			for _, value := range values {
				log.Printf("[DEBUG] - %s: %s\n", key, value)
			}
		}

		// Copy the response body to a buffer for logging.
		var responseBody bytes.Buffer
		if _, err := io.Copy(&responseBody, resp.Body); err != nil {
			log.Printf("[ERROR] Failed to read response body: %v\n", err)
		} else {
			responseBytes := responseBody.Bytes()

			log.Printf("[DEBUG] Response Body (%d bytes):\n", len(responseBytes))
			if len(responseBytes) > 0 {
				log.Printf("[DEBUG] %s\n", string(responseBytes))
			} else {
				log.Println("[DEBUG] <empty body>")
			}

			// Reset the response body to allow further reading.
			resp.Body = io.NopCloser(bytes.NewBuffer(responseBytes))
		}
	}

	// --- Copy the response back to the original client ---
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func initDB(dbFilepath string) {
	dir := filepath.Dir(dbFilepath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("[FATAL] Could not create data directory: %v", err)
		}
	}

	var err error
	db, err = sql.Open("sqlite3", dbFilepath)
	if err != nil {
		log.Fatalf("[FATAL] Could not open database: %v", err)
	}

	if err := runMigrations(db); err != nil {
		log.Fatalf("[FATAL] Database migration failed: %v", err)
	}
}

func runMigrations(db *sql.DB) error {
	var currentVersion int
	err := db.QueryRow("PRAGMA user_version;").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("could not get user_version: %w", err)
	}

	log.Printf("Current DB version: %d", currentVersion)

	migrated := false

	for _, migration := range migrations {
		if currentVersion < migration.Version {
			log.Printf("Migrating database to version %d...", migration.Version)
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("could not begin transaction for migration to version %d: %w", migration.Version, err)
			}

			if _, err := tx.Exec(migration.SQL); err != nil {
				tx.Rollback()
				return fmt.Errorf("could not execute migration to version %d: %w", migration.Version, err)
			}

			// Update user_version
			setUserVersionSQL := fmt.Sprintf("PRAGMA user_version = %d;", migration.Version)
			if _, err := tx.Exec(setUserVersionSQL); err != nil {
				tx.Rollback()
				return fmt.Errorf("could not set user_version to %d: %w", migration.Version, err)
			}

			if err := tx.Commit(); err != nil {
				return fmt.Errorf("could not commit transaction for migration to version %d: %w", migration.Version, err)
			}
			log.Printf("Successfully migrated database to version %d.", migration.Version)
			currentVersion = migration.Version

			migrated = true
		}
	}

	if migrated {
		log.Printf("Running vacuum to shrink the database file...")

		// Run VACUUM to optimize the database file size.
		_, err = db.Exec("VACUUM;")
		if err != nil {
			log.Printf("[ERROR] Failed to run VACUUM: %v", err)
		}
	}

	return nil
}

func saveAttackToDB(attack *Attack) error {
	if attack == nil || attack.TestMode {
		// Skip saving if attack is nil or in test mode.
		return nil
	}

	dbMutex.Lock()
	defer dbMutex.Unlock()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}

	// Check for duplicates first.
	checkQuery := `SELECT COUNT(*) FROM _attacks WHERE
					timestamp = ? ANS
					source_ip = (SELECT id FROM _dict_source_ips WHERE value = ?) AND
					destination_ip = (SELECT id FROM _dict_destination_ips WHERE value = ?) AND
					username = (SELECT id FROM _dict_usernames WHERE value = ?) AND
					password = (SELECT id FROM _dict_passwords WHERE value = ?) AND
					attack_type = (SELECT id FROM _dict_attack_types WHERE value = ?) AND
					evidence = (SELECT id FROM _dict_evidences WHERE value = ?)
					`
	var count int
	err = tx.QueryRow(checkQuery,
		attack.AttackTimestamp.ToTime().UnixMilli(),
		attack.SourceIP, attack.DestinationIP,
		attack.Username, attack.Password,
		attack.AttackType, attack.Evidence).Scan(&count)

	if err != nil {
		tx.Rollback()
		return fmt.Errorf("could not check for duplicate attack: %w", err)
	}

	if count > 0 {
		tx.Rollback()
		return ErrDuplicateAttack
	}

	// If no duplicate is found, insert the new attack.
	/*insertQuery := `INSERT INTO attacks (source_ip, destination_ip, username, password, attack_timestamp, evidence, attack_type)
	VALUES (?, ?, ?, ?, ?, ?, ?)`*/
	insertQuery := `INSERT INTO _attacks (timestamp, source_ip, destination_ip, username, password, attack_type, evidence)
	VALUES (?,
		(SELECT id FROM _dict_source_ips WHERE value = ?),
		(SELECT id FROM _dict_destination_ips WHERE value = ?),
		(SELECT id FROM _dict_usernames WHERE value = ?),
		(SELECT id FROM _dict_passwords WHERE value = ?),
		(SELECT id FROM _dict_attack_types WHERE value = ?),
		(SELECT id FROM _dict_evidences WHERE value = ?))`
	_, err = tx.Exec(insertQuery,
		attack.AttackTimestamp.ToTime().UnixMilli(),
		attack.SourceIP, attack.DestinationIP,
		attack.Username, attack.Password,
		attack.AttackType, strings.TrimSpace(attack.Evidence))

	if err != nil {
		tx.Rollback()
		return fmt.Errorf("could not execute insert statement: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("could not commit transaction: %w", err)
	}
	return nil
}
