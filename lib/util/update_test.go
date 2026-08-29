package util

import (
	"testing"
)

// Update to the latest version
func TestUpdateScan4allVersionToLatest(t *testing.T) {
	err := UpdateScan4allVersionToLatest(true)
	if err != nil {
		t.Error("fail TestupdateNucleiVersionToLatest")
	}
}
