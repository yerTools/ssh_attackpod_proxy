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
	"time"

	_ "github.com/mattn/go-sqlite3"
)

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

func strToBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "1" ||
		s == "true" || s == "t" ||
		s == "yes" || s == "y"
}

func main() {
	log.SetFlags(0)

	proxiedURLString := getEnv("NETWATCH_COLLECTOR_PROXIED_URL", "")
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
			log.Printf("[ERROR] Failed to save attack to DB: %v\n", errDb)
		} else {
			timestamp := attack.AttackTimestamp.ToTime().Format("02.01. 15:04:05")
			log.Printf("%s | From: %-15s | User: %-20s | Pass: %s\n",
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

	createTableSQL := `
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

	PRAGMA user_version = 1;
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("[FATAL] Could not create table: %v", err)
	}
}

func saveAttackToDB(attack *Attack) error {
	if attack == nil || attack.TestMode {
		// Skip saving if attack is nil or in test mode.
		return nil
	}

	query := `INSERT INTO attacks (source_ip, destination_ip, username, password, attack_timestamp, evidence, attack_type)
			   VALUES (?, ?, ?, ?, ?, ?, ?)`

	stmt, err := db.Prepare(query)
	if err != nil {
		return fmt.Errorf("could not prepare statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(attack.SourceIP, attack.DestinationIP, attack.Username,
		attack.Password, attack.AttackTimestamp.ToTime().UnixMilli(),
		attack.Evidence, attack.AttackType)
	if err != nil {
		return fmt.Errorf("could not execute statement: %w", err)
	}

	return err
}
