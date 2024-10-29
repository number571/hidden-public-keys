package main

import (
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/number571/go-peer/pkg/crypto/asymmetric"
	"github.com/number571/go-peer/pkg/encoding"
)

var (
	//go:embed README.md
	readme string
)

var (
	re = regexp.MustCompile(`list/(\w+\.key)[\S\s]*?sha256:\s(\w+)[\S\s]*?sha384:\s(\w+)`)
	mp = make(map[string][2]string, 512)
)

func init() {
	match := re.FindAllStringSubmatch(readme, -1)
	for _, m := range match {
		if len(m) != 4 {
			log.Fatal("len(m) != 4")
		}
		mp[m[1]] = [2]string{m[2], m[3]}
	}
}

func main() {
	entries, err := os.ReadDir("./list")
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		pkFile := e.Name()
		if !pubKeyIsValid(pkFile) {
			log.Fatalf("pubkey '%s' is not valid", pkFile)
		}
	}
}

func pubKeyIsValid(pkFile string) bool {
	pk, err := os.ReadFile(filepath.Join("list", pkFile))
	if err != nil {
		return false
	}
	pubKey := asymmetric.LoadPubKey(string(pk))
	if pubKey == nil {
		return false
	}
	pubKeyStr := pubKey.ToString()
	if mp[pkFile][0] != sha256sum(pubKeyStr) {
		return false
	}
	if mp[pkFile][1] != sha384sum(pubKeyStr) {
		return false
	}
	return true
}

func sha256sum(v string) string {
	s := sha256.Sum256([]byte(v))
	return encoding.HexEncode(s[:])
}

func sha384sum(v string) string {
	s := sha512.Sum384([]byte(v))
	return encoding.HexEncode(s[:])
}
