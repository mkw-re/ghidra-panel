package web

import (
	"go.mkw.re/ghidra-panel/pkg/common"
	"log"
	"net/http"
)

func (s *Server) handleLogin(wr http.ResponseWriter, req *http.Request) {
	_, ok := s.checkAuth(req)
	if ok {
		http.Redirect(wr, req, "/", http.StatusTemporaryRedirect)
		return
	}

	switch req.Method {
	case http.MethodGet:
		state := s.stateWithNav(
			Nav{Route: "/", Name: "Ghidra"},
			Nav{Route: "/login", Name: "Login"},
		)
		err := loginPage.Execute(wr, state)
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
		log.Print("redirect request failed: ", err)
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

func (s *Server) handleLogout(wr http.ResponseWriter, req *http.Request) {
	http.SetCookie(wr, &http.Cookie{
		Name:   "token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(wr, req, "/login", http.StatusTemporaryRedirect)
}
