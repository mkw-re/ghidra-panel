package main

import (
	"encoding/json"
	"flag"
	"go.mkw.re/ghidra-panel/pkg/common"
	"go.mkw.re/ghidra-panel/pkg/database"
	"go.mkw.re/ghidra-panel/pkg/discord_auth"
	"go.mkw.re/ghidra-panel/pkg/token"
	"go.mkw.re/ghidra-panel/pkg/web"
	"log"
	"net/http"
	"os"
)

type Config struct {
	BaseURL string `json:"base_url"`
	Discord struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	} `json:"discord"`
	Ghidra struct {
		Endpoint common.GhidraEndpoint `json:"endpoint"`
	} `json:"ghidra"`
	Links []common.Link `json:"links"`
}

func main() {
	configPath := flag.String("config", "ghidra_panel.json", "path to config file")
	secretsPath := flag.String("secrets", "ghidra_panel.secrets.json", "path to secrets file")
	dbPath := flag.String("db", "ghidra_panel.db", "path to database file")
	flag.Parse()

	// Read config

	configJSON, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	var config Config
	if err := json.Unmarshal(configJSON, &config); err != nil {
		log.Fatal(err)
	}
	if config.Discord.ClientID == "" {
		log.Fatal("client_id not set")
	}
	if config.Discord.ClientSecret == "" {
		log.Fatal("client_secret not set")
	}
	if config.BaseURL == "" {
		log.Fatal("base_url not set")
	}

	// Read secrets

	if _, err := os.Stat(*secretsPath); os.IsNotExist(err) {
		generateSecrets(*secretsPath)
	}
	secrets, err := ReadSecrets(*secretsPath)
	if err != nil {
		log.Fatal(err)
	}

	// Open database

	db, err := database.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Setup web server

	redirectURL := config.BaseURL + "/redirect"

	auth := discord_auth.NewAuth(config.Discord.ClientID, config.Discord.ClientSecret, redirectURL)

	issuer := token.NewIssuer((*[32]byte)(secrets.HMACSecret))

	webConfig := web.Config{
		GhidraEndpoint: &config.Ghidra.Endpoint,
		Links:          config.Links,
	}
	server, err := web.NewServer(&webConfig, db, auth, &issuer)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	log.Fatal(http.ListenAndServe("localhost:8080", mux))
}
