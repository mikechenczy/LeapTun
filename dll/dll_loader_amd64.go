//go:build windows && amd64
// +build windows,amd64

package dll

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed amd64/wintun.dll
var wintunDLL []byte

func EnsureWintunDLL() (string, error) {
	outPath := filepath.Join(".", "wintun.dll")
	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		if err := os.WriteFile(outPath, wintunDLL, 0644); err != nil {
			return "", err
		}
		fmt.Println("wintun.dll copied to:", outPath)
	} else {
		fmt.Println("wintun.dll already exists at:", outPath)
	}
	return outPath, nil
}
