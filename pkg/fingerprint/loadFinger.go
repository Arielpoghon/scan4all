package fingerprint

import (
	"encoding/json"
)

type Packjson struct {
	Fingerprint []*Fingerprint
}

type Fingerprint struct {
	Cms           string
	Method        string
	Location      string
	Keyword       []string
	KeywordMathOr bool   // Whether Keyword is an OR relation
	Id            int    // Extended id attribute, associate to component through id
	UrlPath       string // Extended, some fingerprints must be associated with a specific path, e.g. status code
}

var (
	Webfingerprint *Packjson
)

func LoadWebfingerprintEhole() error {
	var config Packjson
	err := json.Unmarshal([]byte(eHoleFinger), &config)
	if err != nil {
		return err
	}
	Webfingerprint = &config
	return nil
}

func LoadWebfingerprintLocal() error {
	var config Packjson
	err := json.Unmarshal([]byte(localFinger), &config)
	if err != nil {
		return err
	}
	Webfingerprint = &config
	return nil
}

func GetWebfingerprintLocal() *Packjson {
	return Webfingerprint
}

func GetWebfingerprintEhole() *Packjson {
	return Webfingerprint
}
