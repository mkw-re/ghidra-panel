package web

import (
	"embed"
	"go.mkw.re/ghidra-panel/pkg/common"
	"go.mkw.re/ghidra-panel/pkg/discord_auth"
	"go.mkw.re/ghidra-panel/pkg/token"
	"html/template"
	"log"
	"net/http"
	"net/url"
)

//go:embed templates/*
var embeds embed.FS

var (
	homePage  *template.Template
	loginPage *template.Template
)

func init() {
	templates, err := template.ParseFS(embeds, "templates/*.gohtml")
	if err != nil {
		panic(err)
	}
	homePage = templates.Lookup("home.gohtml")
	loginPage = templates.Lookup("login.gohtml")
}

type Config struct {
	BaseURL string
}

type Server struct {
	BaseURL url.URL
	Auth    *discord_auth.Auth
	Issuer  *token.Issuer
}

func NewServer(c *Config, auth *discord_auth.Auth, issuer *token.Issuer) (*Server, error) {
	server := &Server{
		Auth:   auth,
		Issuer: issuer,
	}
	if err := server.BaseURL.UnmarshalBinary([]byte(c.BaseURL)); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/redirect", s.handleOAuthRedirect)
}

func (s *Server) handleHome(wr http.ResponseWriter, req *http.Request) {
	ident, ok := s.checkAuth(req)
	if !ok {
		http.Redirect(wr, req, "/login", http.StatusTemporaryRedirect)
		return
	}

	homePage.Execute(wr, struct {
		UserID   int64
		Username string
	}{
		UserID:   ident.ID,
		Username: ident.Username,
	})
}

func (s *Server) handleLogin(wr http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		err := loginPage.Execute(wr, nil)
		if err != nil {
			panic(err)
		}
	case http.MethodPost:
		authURL := s.Auth.AuthURL()
		http.Redirect(wr, req, authURL, http.StatusTemporaryRedirect)
	default:
		http.Error(wr, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleOAuthRedirect(wr http.ResponseWriter, req *http.Request) {
	ident, err := s.Auth.HandleRedirect(req)
	if err != nil {
		log.Print(err.Error())
		http.Error(wr, "auth failed", http.StatusUnauthorized)
		return
	}

	wr.Header().Set("Set-Cookie", "token="+s.Issuer.Issue(ident)+"; Path=/; HttpOnly; Secure")
	http.Redirect(wr, req, "/", http.StatusTemporaryRedirect)
}

func (s *Server) checkAuth(req *http.Request) (*common.Identity, bool) {
	cookie, err := req.Cookie("token")
	if err != nil || cookie == nil {
		return nil, false
	}
	return s.Issuer.Verify(cookie.Value)
}
