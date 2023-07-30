package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"go.mkw.re/ghidra-panel/ghidra"
	"golang.org/x/sync/errgroup"
	"log"
	"net/http"
	"os"
	"os/signal"

	"go.mkw.re/ghidra-panel/database"
	"go.mkw.re/ghidra-panel/discord_auth"
	"go.mkw.re/ghidra-panel/token"
	"go.mkw.re/ghidra-panel/web"
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
	dev := flag.Bool("dev", false, "enable development mode")

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

	// Setup app context

	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	group, ctx := errgroup.WithContext(ctx)

	// Setup ACL monitor

	acls := ghidra.ACLMon{Dir: cfg.Ghidra.RepoDir}
	if acls.Dir != "" {
		group.Go(func() error {
			log.Printf("Monitoring ACLs at %s", acls.Dir)
			return acls.Run(ctx)
		})
	}

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
		Dev:            *dev,
	}
	server, err := web.NewServer(&webConfig, db, auth, &issuer, &acls)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	log.Printf("Listening on %s", *listen)

	httpServer := http.Server{
		Addr:    *listen,
		Handler: mux,
	}
	go func() {
		err := httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	group.Go(func() error {
		<-ctx.Done()
		return httpServer.Shutdown(ctx)
	})

	if err := group.Wait(); err != nil {
		log.Print(err)
	}
	log.Print("Graceful shut down")
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
