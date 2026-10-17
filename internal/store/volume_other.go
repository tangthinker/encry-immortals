//go:build !unix

package store

import "os"

// sameVolume is best effort off unix: we can only confirm both paths exist.
// A cross-volume rename still fails with EXDEV and is reported at publication
// time, so the guarantee degrades to "fail loudly instead of silently".
func sameVolume(a, b string) (bool, error) {
	if _, err := os.Stat(a); err != nil {
		return false, err
	}
	if _, err := os.Stat(b); err != nil {
		return false, err
	}
	return true, nil
}
