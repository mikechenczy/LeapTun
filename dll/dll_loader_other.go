//go:build !windows
// +build !windows

package dll

func EnsureWintunDLL() (string, error) {
	return "", nil
}
