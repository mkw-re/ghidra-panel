package main

import (
	"encoding/json"
	"flag"
	"go.mkw.re/ghidra-panel/pkg/discord_auth"
	"go.mkw.re/ghidra-panel/pkg/token"
	"go.mkw.re/ghidra-panel/pkg/web"
	"log"
	"net/http"
	"os"
)

func main() {
	configPath := flag.String("config", "ghidra_panel.json", "path to config file")
	secretsPath := flag.String("secrets", "ghidra_panel.secrets.json", "path to secrets file")
	flag.Parse()

	// Read config

	configJSON, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	var panelConfig struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		BaseURL      string `json:"base_url"`
	}
	if err := json.Unmarshal(configJSON, &panelConfig); err != nil {
		log.Fatal(err)
	}
	if panelConfig.ClientID == "" {
		log.Fatal("client_id not set")
	}
	if panelConfig.ClientSecret == "" {
		log.Fatal("client_secret not set")
	}
	if panelConfig.BaseURL == "" {
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

	redirectURL := panelConfig.BaseURL + "/redirect"

	auth := discord_auth.NewAuth(panelConfig.ClientID, panelConfig.ClientSecret, redirectURL)

	issuer := token.NewIssuer((*[32]byte)(secrets.HMACSecret))

	server, err := web.NewServer(&web.Config{BaseURL: panelConfig.BaseURL}, auth, &issuer)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	log.Fatal(http.ListenAndServe("localhost:8080", mux))
}
