package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"go.mkw.re/ghidra-panel/common"
	"go.mkw.re/ghidra-panel/discord"
)

func (s *Server) handleRequestAccess(wr http.ResponseWriter, req *http.Request) {
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

	// TODO query ACL to ensure user account exists

	message := s.writeMessage(ident)

	// Send access request message
	ctx := context.TODO()
	payloadBuf, _ := json.Marshal(&message)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Config.DiscordWebhookURL, bytes.NewReader(payloadBuf))
	if err != nil {
		http.Error(wr, "Internal server error", http.StatusInternalServerError)
		return
	}

	req.Header.Set("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		// TODO properly handle
		http.Redirect(wr, req, "/?access_request=failure", http.StatusTemporaryRedirect)
		return
	}
	defer res.Body.Close()

	http.Redirect(wr, req, "/?access_request=success", http.StatusTemporaryRedirect)
}

func (s *Server) writeMessage(ident *common.Identity) discord.WebhookMessage {
	embedAuthor := discord.EmbedAuthor{
		Name:    ident.Username,
		IconURL: fmt.Sprintf("https://cdn.discordapp.com/avatars/%d/%s.png", ident.ID, ident.AvatarHash),
	}

	hostnameField := discord.EmbedField{
		Name:   "Hostname",
		Value:  s.Config.GhidraEndpoint.Hostname,
		Inline: true,
	}

	portField := discord.EmbedField{
		Name:   "Port",
		Value:  strconv.FormatUint(uint64(s.Config.GhidraEndpoint.Port), 10),
		Inline: true,
	}

	ghidraEmbed := discord.Embed{
		Title:  fmt.Sprintf("%s has requested access to the following Ghidra server:", ident.Username),
		Color:  0x77DD77,
		Author: embedAuthor,
		Fields: []discord.EmbedField{hostnameField, portField},
	}

	return discord.WebhookMessage{
		Username:  "Panel",
		AvatarURL: "",
		Embeds:    []discord.Embed{ghidraEmbed},
	}
}
