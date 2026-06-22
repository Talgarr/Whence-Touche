// Package config loads Whence Touché settings from the environment.
package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/kelseyhightower/envconfig"
)

const envPrefix = "WHENCE"

type Config struct {
	// ObjectPath defaults to tracer.bpf.o next to the executable.
	ObjectPath      string `envconfig:"TRACER_OBJ_PATH"`
	NotifyThreshold int    `envconfig:"NOTIFY_THRESHOLD" default:"3"`
	// NotifyDelay is how long a session must keep producing I/O before we
	// notify. The brief command/PIN-probe exchange that precedes PIN entry is
	// over in milliseconds, so requiring sustained activity keeps it from
	// popping a notification that then closes during the PIN prompt and
	// reopens afterwards (the "flash" from issue #1). A real touch-wait keeps
	// the device polling for as long as the user takes to touch, so it clears
	// this easily.
	NotifyDelay time.Duration `envconfig:"NOTIFY_DELAY" default:"200ms"`
	Quiet       time.Duration `envconfig:"QUIET" default:"500ms"`
	Sweep       time.Duration `envconfig:"SWEEP" default:"200ms"`
	Debug       bool          `envconfig:"DEBUG"`
}

// Load reads config from the environment (prefix WHENCE_).
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
