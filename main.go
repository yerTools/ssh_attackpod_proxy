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

type Config struct {
	ListenAddress string
	DatabasePath  string
	ProxiedURL    *url.URL
	LogRequests   bool
	DebugLog      bool
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

	appConfig = &Config{
		ListenAddress: getEnv("NETWATCH_PROXY_LISTEN_ADDRESS", ":8161"),
		DatabasePath:  getEnv("NETWATCH_PROXY_DB_PATH", "/app/data/attacks.db"),
		ProxiedURL:    parsedURL,
		LogRequests:   logRequests || debugLog,
		DebugLog:      debugLog,
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

	// Construct the full destination URL.
	r.URL.Scheme = appConfig.ProxiedURL.Scheme
	r.URL.Host = appConfig.ProxiedURL.Host
	r.Host = appConfig.ProxiedURL.Host
	targetURL := appConfig.ProxiedURL.ResolveReference(r.URL)

	// Create a new request to be forwarded.
	proxyReq, err := http.NewRequest(r.Method, targetURL.String(), bytes.NewBuffer(body))
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

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("[ERROR] Failed to forward request to %s: %v\n", targetURL, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

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

	if r.Method == http.MethodPost && r.URL.Path == "/add_attack" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var attack Attack
		err := json.Unmarshal(body, &attack)
		if err != nil {
			log.Printf("[ERROR] Failed to unmarshal attack data: %v\n", err)
		} else if errDb := saveAttackToDB(&attack); errDb != nil {
			log.Printf("[ERROR] Failed to save attack to DB: %v\n", errDb)
		} else {
			timestamp := attack.AttackTimestamp.ToTime().Format("02.01.2006 15:04:05")
			log.Printf("%s | %-15s | From: %-15s | To: %-15s | User: %-20s | Pass: %s\n",
				timestamp, attack.AttackType, attack.SourceIP, attack.DestinationIP, attack.Username, attack.Password)
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
		"attack_type" TEXT,
		"test_mode" INTEGER
	);
	
	CREATE INDEX IF NOT EXISTS idx_attacks_source_ip ON attacks (source_ip, attack_timestamp);
	CREATE INDEX IF NOT EXISTS idx_attacks_destination_ip ON attacks (destination_ip, attack_timestamp);
	CREATE INDEX IF NOT EXISTS idx_attacks_source_destination ON attacks (source_ip, destination_ip, attack_timestamp);

	CREATE INDEX IF NOT EXISTS idx_attacks_test_mode ON attacks (test_mode, attack_timestamp);
	CREATE INDEX IF NOT EXISTS idx_attacks_attack_type ON attacks (attack_type, attack_timestamp);
	CREATE INDEX IF NOT EXISTS idx_attacks_evidence ON attacks (evidence, attack_timestamp);

	CREATE INDEX IF NOT EXISTS idx_attacks_attack_timestamp ON attacks (attack_timestamp);

	CREATE INDEX IF NOT EXISTS idx_attacks_username ON attacks (username, attack_timestamp);
	CREATE INDEX IF NOT EXISTS idx_attacks_password ON attacks (password, attack_timestamp);
	CREATE INDEX IF NOT EXISTS idx_attacks_username_password ON attacks (username, password, attack_timestamp);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("[FATAL] Could not create table: %v", err)
	}
}

func saveAttackToDB(attack *Attack) error {
	query := `INSERT INTO attacks (source_ip, destination_ip, username, password, attack_timestamp, evidence, attack_type, test_mode)
			   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	stmt, err := db.Prepare(query)
	if err != nil {
		return fmt.Errorf("could not prepare statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(attack.SourceIP, attack.DestinationIP, attack.Username,
		attack.Password, attack.AttackTimestamp.ToTime().UnixMilli(),
		attack.Evidence, attack.AttackType, attack.TestMode)
	if err != nil {
		return fmt.Errorf("could not execute statement: %w", err)
	}

	return err
}
