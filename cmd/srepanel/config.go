package main

import (
	"go.mkw.re/ghidra-panel/pkg/common"
	"log"
)

type config struct {
	BaseURL string `json:"base_url"`
	Discord struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	} `json:"discord"`
	Ghidra struct {
		Endpoint common.GhidraEndpoint `json:"endpoint"`
	} `json:"ghidra"`
	Links []common.Link `json:"links"`
}

func (c *config) validate() {

	if c.Discord.ClientID == "" {
		log.Fatal("client_id not set")
	}
	if c.Discord.ClientSecret == "" {
		log.Fatal("client_secret not set")
	}
	if c.BaseURL == "" {
		log.Fatal("base_url not set")
	}
}
