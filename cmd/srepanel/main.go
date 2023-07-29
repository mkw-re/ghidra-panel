package main

import (
	"context"
	"encoding/json"
	"flag"
	"go.mkw.re/ghidra-panel/pkg/database"
	"go.mkw.re/ghidra-panel/pkg/discord_auth"
	"go.mkw.re/ghidra-panel/pkg/token"
	"go.mkw.re/ghidra-panel/pkg/web"
	"log"
	"net/http"
	"os"
)

func main() {
	// cli args
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "set-password":
			os.Args = os.Args[1:]
			dbPath := flag.String("db", "ghidra_panel.db", "path to database file")
			argUserID := flag.Uint64("user-id", 0, "user id to set password for")
			argUser := flag.String("user", "", "user to set password for")
			argPass := flag.String("pass", "", "password to set")
			flag.Parse()
			setPassword(*dbPath, *argUserID, *argUser, *argPass)
			return
		}
	}

	// prod args
	configPath := flag.String("config", "ghidra_panel.json", "path to config file")
	secretsPath := flag.String("secrets", "ghidra_panel.secrets.json", "path to secrets file")
	dbPath := flag.String("db", "ghidra_panel.db", "path to database file")
	listen := flag.String("listen", ":8080", "listen address")
	cmdInit := flag.Bool("init", false, "initialize database and exit")

	flag.Parse()

	// Read config

	configJSON, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	var cfg config
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		log.Fatal(err)
	}
	if !*cmdInit {
		cfg.validate()
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

	if *cmdInit {
		return
	}

	redirectURL := cfg.BaseURL + "/redirect"

	auth := discord_auth.NewAuth(cfg.Discord.ClientID, cfg.Discord.ClientSecret, redirectURL)

	issuer := token.NewIssuer((*[32]byte)(secrets.HMACSecret))

	webConfig := web.Config{
		GhidraEndpoint: &cfg.Ghidra.Endpoint,
		Links:          cfg.Links,
	}
	server, err := web.NewServer(&webConfig, db, auth, &issuer)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	log.Fatal(http.ListenAndServe(*listen, mux))
}

func setPassword(dbPath string, userID uint64, user, pass string) {
	db, err := database.Open(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.SetPassword(ctx, userID, user, pass); err != nil {
		log.Fatal(err)
	}
}
