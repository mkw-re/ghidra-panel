package main

import (
	"encoding/json"
	"flag"
	"go.mkw.re/ghidra-panel/pkg/discord_auth"
	"go.mkw.re/ghidra-panel/pkg/web"
	"log"
	"net/http"
)

func main() {
	configPath := flag.String("config", "ghidra_panel.json", "path to config file")
	flag.Parse()

	var panelConfig struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		BaseURL      string `json:"base_url"`
	}
	if err := json.Unmarshal([]byte(*configPath), &panelConfig); err != nil {
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

	redirectURL := panelConfig.BaseURL + "/redirect"

	auth := discord_auth.NewAuth(panelConfig.ClientID, panelConfig.ClientSecret, redirectURL)
	server, err := web.NewServer(&web.Config{BaseURL: panelConfig.BaseURL}, auth)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	log.Fatal(http.ListenAndServe(":8080", mux))
}
