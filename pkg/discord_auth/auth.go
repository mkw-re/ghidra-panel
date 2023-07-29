package discord_auth

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"net/http"
)

var Endpoint = oauth2.Endpoint{
	AuthURL:   "https://discord.com/oauth2/authorize",
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

func (c *Auth) AuthURL() string {
	return c.Config.AuthCodeURL(c.prot.issue(), oauth2.AccessTypeOnline)
}

func (c *Auth) HandleRedirect(req *http.Request) (username string, err error) {
	ctx := req.Context()

	query := req.URL.Query()
	code := query.Get("code")
	state := query.Get("state")

	if !c.prot.check(state) {
		return "", errors.New("invalid state")
	}

	token, err := c.Config.Exchange(ctx, code)
	if err != nil {
		return "", err
	}

	return c.GetDiscordUsername(ctx, token)
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

	username = info.User.Username
	if username == "" {
		return "", errors.New("empty username")
	}

	return username, nil
}
