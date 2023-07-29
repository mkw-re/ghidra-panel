package web

import (
	"log"
	"net/http"
)

func (s *Server) handleUpdatePassword(wr http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(wr, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ident, ok := s.checkAuth(req)
	if !ok {
		http.Error(wr, "Not authorized", http.StatusUnauthorized)
		return
	}

	if err := req.ParseForm(); err != nil {
		http.Error(wr, "Bad request", http.StatusBadRequest)
		return
	}
	pass := req.PostForm.Get("password")

	if err := s.DB.SetPassword(req.Context(), ident.ID, pass); err != nil {
		log.Print("Failed to update password of user: ", err)
		http.Error(wr, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(wr, req, "/", http.StatusTemporaryRedirect)
}
