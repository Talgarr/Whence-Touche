// Package config loads Whence Touché settings from the environment.
package config

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

const envPrefix = "WHENCE"

type Config struct {
	NotifyThreshold int           `envconfig:"NOTIFY_THRESHOLD" default:"3"`
	Quiet           time.Duration `envconfig:"QUIET" default:"500ms"`
	Sweep           time.Duration `envconfig:"SWEEP" default:"200ms"`
	Debug           bool          `envconfig:"DEBUG"`
}

// Load reads config from the environment (prefix WHENCE_).
func Load() (Config, error) {
	var c Config
	if err := envconfig.Process(envPrefix, &c); err != nil {
		return c, err
	}
	return c, nil
}
