package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	ListenAddress string
	DatabasePath  string
	ProxiedURL    *url.URL
}

type Attack struct {
	SourceIP        string    `json:"source_ip"`
	DestinationIP   string    `json:"destination_ip"`
	Username        string    `json:"username"`
	Password        string    `json:"password"`
	AttackTimestamp time.Time `json:"attack_timestamp"`
	Evidence        string    `json:"evidence"`
	AttackType      string    `json:"attack_type"`
	TestMode        bool      `json:"test_mode"`
}

var db *sql.DB

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

	config := Config{
		ListenAddress: getEnv("NETWATCH_PROXY_LISTEN_ADDRESS", ":8161"),
		DatabasePath:  getEnv("NETWATCH_PROXY_DB_PATH", "/app/data/attacks.db"),
		ProxiedURL:    parsedURL,
	}

	initDB(config.DatabasePath)
	defer db.Close()

	// Create a new reverse proxy.
	proxy := httputil.NewSingleHostReverseProxy(config.ProxiedURL)

	// We use ModifyResponse to read the body *after* the request has been proxied.
	// This is more robust as we are intercepting the original request from the sensor.
	proxy.ModifyResponse = func(resp *http.Response) error {
		// We only care about successful POST requests to our specific attack path.
		if resp.Request.Method == http.MethodPost && resp.Request.URL.Path == "/add_attack" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			body, err := io.ReadAll(resp.Request.Body)
			if err != nil {
				log.Printf("[ERROR] Failed to read request body for logging: %v", err)
				return nil // Don't block the proxy
			}
			// Restore the body for the actual proxying mechanism
			resp.Request.Body = io.NopCloser(bytes.NewBuffer(body))

			var attack Attack
			if err := json.Unmarshal(body, &attack); err != nil {
				log.Printf("[ERROR] Failed to parse JSON for logging: %v", err)
				return nil
			}

			if err := saveAttackToDB(&attack); err != nil {
				log.Printf("[ERROR] Failed to save attack to DB: %v", err)
			} else {
				timestamp := time.Now().Format("02.01.2006 15:04:05")
				log.Printf("%s | %-15s | From: %-15s | To: %-15s | User: %-20s | Pass: %s",
					timestamp, attack.AttackType, attack.SourceIP, attack.DestinationIP, attack.Username, attack.Password)
			}
		}
		return nil
	}

	// The Director function modifies the request before it is sent.
	// This is standard setup for a reverse proxy.
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = config.ProxiedURL.Scheme
		req.URL.Host = config.ProxiedURL.Host
		req.Host = config.ProxiedURL.Host
	}

	http.Handle("/", proxy)
	log.Printf("Attack Pod Proxy started. Listening on %s. Transparently forwarding to %s.", config.ListenAddress, config.ProxiedURL)
	if err := http.ListenAndServe(config.ListenAddress, nil); err != nil {
		log.Fatalf("[FATAL] Failed to start server: %v", err)
	}
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

	createTableSQL := `CREATE TABLE IF NOT EXISTS attacks (
		"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "source_ip" TEXT, "destination_ip" TEXT,
		"username" TEXT, "password" TEXT, "attack_timestamp" DATETIME, "evidence" TEXT,
		"attack_type" TEXT, "test_mode" BOOLEAN, "proxy_received_at" DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

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
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(attack.SourceIP, attack.DestinationIP, attack.Username, attack.Password, attack.AttackTimestamp, attack.Evidence, attack.AttackType, attack.TestMode)
	return err
}
