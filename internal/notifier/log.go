package notifier

import "github.com/rs/zerolog/log"

// Log is a Notifier that records touches in the log instead of posting a
// desktop notification. It needs no session bus or notification daemon, which
// makes it the backend the container e2e harness runs in: the harness asserts
// the resolved tool from the log line alone. Handy for headless debugging too.
type Log struct{}

// TouchNeeded logs the pending touch at info level — so it shows without
// -verbose and is greppable by the e2e harness — and returns a zero ID, since
// there is nothing on screen to dismiss later.
func (Log) TouchNeeded(body string) (uint32, error) {
	log.Info().Str("touch", body).Msg("touch needed")
	return 0, nil
}

// Close logs that the touch finished. The ID is unused: the log backend has no
// on-screen notification to dismiss.
func (Log) Close(uint32) {
	log.Info().Msg("touch done")
}
