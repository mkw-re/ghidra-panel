package main

import (
	"crypto/rand"
	"encoding/json"
	"log"
	"os"
)

type Secrets struct {
	HMACSecret []byte `json:"hmac_secret"`
}

func ReadSecrets(filePath string) (secrets *Secrets, err error) {
	secrets = new(Secrets)
	secretsJSON, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(secretsJSON, secrets)
	return
}

func RandomSecrets() *Secrets {
	var hmacSecret [32]byte
	if _, err := rand.Read(hmacSecret[:]); err != nil {
		log.Fatal(err)
	}
	return &Secrets{
		HMACSecret: hmacSecret[:],
	}
}

func generateSecrets(filePath string) {
	secrets := RandomSecrets()
	secretsJSON, err := json.MarshalIndent(secrets, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filePath, secretsJSON, 0600); err != nil {
		log.Fatal(err)
	}
}
