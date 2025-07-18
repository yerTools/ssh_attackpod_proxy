package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
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
var appConfig *Config

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

	appConfig = &Config{
		ListenAddress: getEnv("NETWATCH_PROXY_LISTEN_ADDRESS", ":8161"),
		DatabasePath:  getEnv("NETWATCH_PROXY_DB_PATH", "/app/data/attacks.db"),
		ProxiedURL:    parsedURL,
	}

	initDB(appConfig.DatabasePath)
	defer db.Close()

	// A single handler for all incoming requests.
	http.HandleFunc("/", handleProxyRequest)

	log.Printf("Attack Pod Proxy started. Listening on %s. Forwarding to %s.", appConfig.ListenAddress, appConfig.ProxiedURL)
	if err := http.ListenAndServe(appConfig.ListenAddress, nil); err != nil {
		log.Fatalf("[FATAL] Failed to start server: %v", err)
	}
}

// handleProxyRequest manually forwards the request to ensure minimal header modification.
func handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	// Read the entire body of the incoming request.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read request body: %v", err)
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
		log.Printf("[ERROR] Failed to create proxy request: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	proxyReq.Header = r.Header.Clone()
	proxyReq.Host = appConfig.ProxiedURL.Host

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("[ERROR] Failed to forward request to %s: %v", targetURL, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if r.Method == http.MethodPost && r.URL.Path == "/add_attack" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var attack Attack
		if err := json.Unmarshal(body, &attack); err == nil {
			if errDb := saveAttackToDB(&attack); errDb != nil {
				log.Printf("[ERROR] Failed to save attack to DB: %v", errDb)
			} else {
				timestamp := time.Now().Format("02.01.2006 15:04:05")
				log.Printf("%s | %-15s | From: %-15s | To: %-15s | User: %-20s | Pass: %s",
					timestamp, attack.AttackType, attack.SourceIP, attack.DestinationIP, attack.Username, attack.Password)
			}
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
