package crypto

import (
	"encoding/json"
	"fmt"
)

type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type Text struct {
	Content string `json:"content"`
}

type Binary struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

type Card struct {
	Number   string `json:"number"`
	Holder   string `json:"holder"`
	ExpMonth int    `json:"exp_month"`
	ExpYear  int    `json:"exp_year"`
	CVC      string `json:"cvc"`
}

func EncodePayload[T any](v T) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}
	return data, nil
}

func DecodePayload[T any](data []byte) (T, error) {
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return v, fmt.Errorf("decode payload: %w", err)
	}
	return v, nil
}
