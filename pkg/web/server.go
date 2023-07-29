package web

import (
	"embed"
	"go.mkw.re/ghidra-panel/pkg/common"
	"go.mkw.re/ghidra-panel/pkg/database"
	"go.mkw.re/ghidra-panel/pkg/discord_auth"
	"go.mkw.re/ghidra-panel/pkg/token"
	"html/template"
	"net/http"
)

var (
	//go:embed templates/*
	templates embed.FS

	//go:embed assets/*
	assets embed.FS
)

var (
	homePage  *template.Template
	loginPage *template.Template
)

func init() {
	templates, err := template.ParseFS(templates, "templates/*.gohtml")
	if err != nil {
		panic(err)
	}
	homePage = templates.Lookup("home.gohtml")
	loginPage = templates.Lookup("login.gohtml")
}

type Config struct {
	GhidraEndpoint *common.GhidraEndpoint
}

type Server struct {
	Config *Config
	DB     *database.DB
	Auth   *discord_auth.Auth
	Issuer *token.Issuer
}

func NewServer(
	config *Config,
	db *database.DB,
	auth *discord_auth.Auth,
	issuer *token.Issuer,
) (*Server, error) {
	server := &Server{
		Config: config,
		DB:     db,
		Auth:   auth,
		Issuer: issuer,
	}
	return server, nil
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/redirect", s.handleOAuthRedirect)
	mux.HandleFunc("/logout", s.handleLogout)

	// Create file server for assets
	mux.Handle("/assets/", http.FileServer(http.FS(assets)))
}

// State holds server-side web page state.
type State struct {
	Identity  *common.Identity // current user, null if unauthenticated
	UserState *common.UserState
	Nav       []Nav // navigation bar
	Ghidra    *common.GhidraEndpoint
}

type Nav struct {
	Route string
	Name  string
}

func (s *Server) stateWithNav(nav ...Nav) *State {
	return &State{
		Ghidra: s.Config.GhidraEndpoint,
		Nav:    nav,
	}
}

func (s *Server) authenticateState(wr http.ResponseWriter, req *http.Request, state *State) bool {
	ident, ok := s.checkAuth(req)
	if !ok {
		http.Error(wr, "not authenticated", http.StatusUnauthorized)
		return false
	}

	state.Identity = ident

	userState, err := s.DB.GetUserState(req.Context(), ident.ID)
	if err != nil {
		http.Error(wr, "failed to get user state, please contact server admin", http.StatusInternalServerError)
		return false
	}

	state.UserState = userState
	return true
}
