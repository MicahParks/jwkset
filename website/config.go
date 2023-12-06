package jwksetcom

import (
	"fmt"

	"github.com/MicahParks/jsontype"
)

type Config struct {
	DMode     bool      `json:"devMode"`
	ReCAPTCHA ReCAPTCHA `json:"reCAPTCHA"`
}

func (c Config) DefaultsAndValidate() (Config, error) {
	if c.ReCAPTCHA.SiteKey != "" {
		if c.ReCAPTCHA.Secret == "" {
			return Config{}, fmt.Errorf(`%w: missing reCAPTCHA "secret" config`, jsontype.ErrDefaultsAndValidate)
		}
		if c.ReCAPTCHA.ScoreMin == 0 {
			return Config{}, fmt.Errorf(`%w: missing reCAPTCHA "scoreMin" config`, jsontype.ErrDefaultsAndValidate)
		}
		if len(c.ReCAPTCHA.Hostname) == 0 {
			return Config{}, fmt.Errorf(`%w: missing reCAPTCHA "hostname" config`, jsontype.ErrDefaultsAndValidate)
		}
	}
	return c, nil
}
func (c Config) DevMode() bool {
	return c.DMode
}

type ReCAPTCHA struct {
	Hostname []string `json:"hostname"`
	ScoreMin float64  `json:"scoreMin"`
	Secret   string   `json:"secret"`
	SiteKey  string   `json:"siteKey"`
}
