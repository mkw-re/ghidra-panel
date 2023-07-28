package discord_auth

import (
	"context"
	"encoding/json"
	"golang.org/x/oauth2"
	"log"
	"net/http"
)

var Endpoint = oauth2.Endpoint{
	AuthURL:   "https://discord.com/api/oauth2/authorize",
	TokenURL:  "https://discord.com/api/oauth2/token",
	AuthStyle: oauth2.AuthStyleInParams,
}

type Auth struct {
	oauth2.Config
	prot *csrfProt
}

func NewAuth(clientID, clientSecret, redirectURL string) *Auth {
	config := &Auth{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     Endpoint,
			RedirectURL:  redirectURL,
			Scopes:       []string{"identify"},
		},
		prot: newCSRFProt(),
	}
	return config
}

func (c *Auth) LoginURL() string {
	return c.Config.AuthCodeURL(c.prot.issue(), oauth2.AccessTypeOnline)
}

func (c *Auth) Redirect(wr http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	query := req.URL.Query()
	code := query.Get("code")
	state := query.Get("state")

	if !c.prot.check(state) {
		http.Error(wr, "invalid state", http.StatusForbidden)
		return
	}

	token, err := c.Config.Exchange(ctx, code)
	if err != nil {
		log.Print("oauth2 exchange failed: " + err.Error())
		http.Error(wr, "OAuth2 failed", http.StatusInternalServerError)
		return
	}

	username, err := c.GetDiscordUsername(ctx, token)
	if err != nil {
		log.Print("get discord username failed: " + err.Error())
		http.Error(wr, "OAuth2 failed", http.StatusInternalServerError)
		return
	}

	wr.Header().Set("Content-Type", "text/html")
	wr.Write([]byte("<html><body>Logged in as " + username + "</body></html>"))
}

func (c *Auth) GetDiscordUsername(ctx context.Context, token *oauth2.Token) (username string, err error) {
	meReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://discord.com/api/oauth2/@me", nil)
	if err != nil {
		return "", err
	}

	res, err := c.Config.Client(ctx, token).Do(meReq)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	var info struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		return "", err
	}

	return info.User.Username, nil
}
