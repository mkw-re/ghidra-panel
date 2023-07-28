package web

import (
	"go.mkw.re/ghidra-panel/pkg/discord_auth"
	"net/http"
	"net/url"
)

type Config struct {
	BaseURL string
}

type Server struct {
	BaseURL url.URL
	Auth    *discord_auth.Auth
}

func NewServer(c *Config, auth *discord_auth.Auth) (*Server, error) {
	server := &Server{
		Auth: auth,
	}
	if err := server.BaseURL.UnmarshalBinary([]byte(c.BaseURL)); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/login", s.loginPage)
	mux.HandleFunc("/redirect", s.Auth.Redirect)
}

func (s *Server) loginPage(wr http.ResponseWriter, req *http.Request) {
	authorizeURL := s.Auth.LoginURL()
	http.Redirect(wr, req, authorizeURL, http.StatusTemporaryRedirect)
}
