package discord

// ----------- //
// Channel API //
// ----------- //

// https://discord.com/developers/docs/resources/channel#embed-object-embed-author-structure
type EmbedAuthor struct {
	Name    string `json:"name"`
	IconURL string `json:"icon_url"`
}

// https://discord.com/developers/docs/resources/channel#embed-object-embed-field-structure
type EmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// https://discord.com/developers/docs/resources/channel#embed-object
type Embed struct {
	Title  string       `json:"title"`
	Color  int          `json:"color"`
	Author EmbedAuthor  `json:"author"`
	Fields []EmbedField `json:"fields"`
}

// ----------- //
// Webhook API //
// ----------- //

// https://discord.com/developers/docs/resources/webhook#execute-webhook
type WebhookMessage struct {
	Username  string  `json:"username"`
	AvatarURL string  `json:"avatar_url"`
	Embeds    []Embed `json:"embeds"`
}
