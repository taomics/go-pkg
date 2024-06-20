package identity_test

import (
	"log"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	log.SetFlags(0)
	os.Exit(m.Run())
}
