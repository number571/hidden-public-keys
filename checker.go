package main

import (
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"errors"
	"fmt"
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
	re = regexp.MustCompile(`list/(\w+\.key)[\S\s]*?sha256:\s(\w+)[\S\s]*?sha384:\s(\w+)[\S\s]*?sha512:\s(\w+)`)
	mp = make(map[string][3]string, 512)
)

var (
	hashFuncs = []func(string) string{
		func(v string) string {
			s := sha256.Sum256([]byte(v))
			return encoding.HexEncode(s[:])
		},
		func(v string) string {
			s := sha512.Sum384([]byte(v))
			return encoding.HexEncode(s[:])
		},
		func(v string) string {
			s := sha512.Sum512([]byte(v))
			return encoding.HexEncode(s[:])
		},
	}
)

func init() {
	match := re.FindAllStringSubmatch(readme, -1)
	for _, m := range match {
		if len(m) != 5 {
			log.Fatal("len(m) != 5")
		}
		mp[m[1]] = [3]string{m[2], m[3], m[4]}
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
		if err := pubKeyIsValid(pkFile); err != nil {
			log.Fatalf("'%s' is invalid: %s", pkFile, err.Error())
		}
	}
}

func pubKeyIsValid(pkFile string) error {
	pk, err := os.ReadFile(filepath.Join("list", pkFile))
	if err != nil {
		return err
	}

	pubKey := asymmetric.LoadPubKey(string(pk))
	if pubKey == nil {
		return errors.New("read public key")
	}

	pubKeyStr := pubKey.ToString()

	for i, hashsum := range hashFuncs {
		wantHash := mp[pkFile][i]
		if h := hashsum(pubKeyStr); h != wantHash {
			return fmt.Errorf("want:'%s'; got:'%s'", wantHash, h)
		}
	}

	return nil
}
