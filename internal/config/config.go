// Package config loads yubikey-notifier settings from the environment.
package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/kelseyhightower/envconfig"
)

const envPrefix = "YUBIKEY"

type Config struct {
	// ObjectPath defaults to tracer.bpf.o next to the executable.
	ObjectPath      string        `envconfig:"TRACER_OBJ_PATH"`
	NotifyThreshold int           `envconfig:"NOTIFY_THRESHOLD" default:"3"`
	Quiet           time.Duration `envconfig:"QUIET" default:"500ms"`
	Sweep           time.Duration `envconfig:"SWEEP" default:"200ms"`
}

// Load reads config from the environment (prefix YUBIKEY_).
func Load() (Config, error) {
	var c Config
	if err := envconfig.Process(envPrefix, &c); err != nil {
		return c, err
	}
	if c.ObjectPath == "" {
		c.ObjectPath = defaultObjectPath()
	}
	return c, nil
}

func defaultObjectPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "tracer.bpf.o")
	}
	return "tracer.bpf.o"
}
