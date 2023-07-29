package common

type Identity struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
}

type GhidraEndpoint struct {
	Hostname string `json:"hostname"`
	Port     uint16 `json:"port"`
}

type UserState struct {
	HasPassword bool
}

type Link struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}
