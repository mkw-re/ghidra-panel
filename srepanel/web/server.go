package web

import (
	"embed"
	"html/template"
	"net/http"

	"go.mkw.re/ghidra-panel/common"
	"go.mkw.re/ghidra-panel/database"
	"go.mkw.re/ghidra-panel/discord_auth"
	"go.mkw.re/ghidra-panel/ghidra"
	"go.mkw.re/ghidra-panel/token"
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
	Links          []common.Link
	Dev            bool // developer mode
}

type Server struct {
	Config *Config
	DB     *database.DB
	Auth   *discord_auth.Auth
	Issuer *token.Issuer
	ACLs   *ghidra.ACLMon
}

func NewServer(
	config *Config,
	db *database.DB,
	auth *discord_auth.Auth,
	issuer *token.Issuer,
	acls *ghidra.ACLMon,
) (*Server, error) {
	server := &Server{
		Config: config,
		DB:     db,
		Auth:   auth,
		Issuer: issuer,
		ACLs:   acls,
	}
	return server, nil
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/redirect", s.handleOAuthRedirect)
	mux.HandleFunc("/logout", s.handleLogout)

	mux.HandleFunc("/update_password", s.handleUpdatePassword)

	// Create file server for assets
	mux.Handle("/assets/", http.FileServer(http.FS(assets)))
}

// State holds server-side web page state.
type State struct {
	Identity  *common.Identity // current user, null if unauthenticated
	UserState *common.UserState
	Nav       []Nav         // navigation bar
	Links     []common.Link // footer links
	Ghidra    *common.GhidraEndpoint
	ACL       []common.UserRepoAccess
}

type Nav struct {
	Route string
	Name  string
}

func (s *Server) stateWithNav(nav ...Nav) *State {
	return &State{
		Ghidra: s.Config.GhidraEndpoint,
		Nav:    nav,
		Links:  s.Config.Links,
	}
}

func (s *Server) authenticateState(wr http.ResponseWriter, req *http.Request, state *State) bool {
	ident, ok := s.checkAuth(req)
	if !ok {
		http.SetCookie(wr, &http.Cookie{
			Name:   "token",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		http.Redirect(wr, req, "/login", http.StatusTemporaryRedirect)
		return false
	}

	state.Identity = ident

	userState, err := s.DB.GetUserState(req.Context(), ident.ID)
	if err != nil {
		http.Error(wr, "failed to get user state, please contact server admin", http.StatusInternalServerError)
		return false
	}
	state.UserState = userState

	acl := s.ACLs.Get().QueryUser(ident.Username)
	state.ACL = make([]common.UserRepoAccess, len(acl))
	for i, v := range acl {
		state.ACL[i] = common.UserRepoAccess{
			Repo: v.Repo,
			Perm: ghidra.PermStrs[v.Perm],
		}
	}

	return true
}
