// Package config is the single project-level configuration for yubikey-notifier,
// sourced from the environment via envconfig and loaded once in main.
package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/kelseyhightower/envconfig"
)

// envPrefix namespaces every variable, e.g. ObjectPath -> YUBIKEY_TRACER_OBJ_PATH.
const envPrefix = "YUBIKEY"

// Config is the project-wide configuration.
type Config struct {
	// ObjectPath is the path to the compiled BPF object (tracer.bpf.o). When
	// $YUBIKEY_TRACER_OBJ_PATH is unset it defaults to a file of that name in the
	// directory of the running executable.
	ObjectPath string `envconfig:"TRACER_OBJ_PATH"`

	// NotifyThreshold is how many I/O events a session must accumulate before a
	// notification is shown — filters isolated idle polls that are not touches.
	NotifyThreshold int `envconfig:"NOTIFY_THRESHOLD" default:"3"`

	// Quiet is how long the key must be silent before a touch is treated as
	// finished and its notification dismissed.
	Quiet time.Duration `envconfig:"QUIET" default:"500ms"`

	// Sweep is how often sessions are checked for having gone quiet.
	Sweep time.Duration `envconfig:"SWEEP" default:"200ms"`
}

// Load reads configuration from the environment, applying the
// executable-relative default for ObjectPath when unset.
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
