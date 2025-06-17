package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const FLAG_CHECK_TEXT string = "path for SHA256SUMS file to check files"

const (
	MODE_CALC_HASHES  = 0
	MODE_CHECK_HASHES = 1
)

func main() {
	checkFlag := flag.String("c", "", FLAG_CHECK_TEXT)
	flag.StringVar(checkFlag, "check", "", FLAG_CHECK_TEXT)
	flag.Parse()

	mode := MODE_CALC_HASHES
	if *checkFlag != "" {
		mode = MODE_CHECK_HASHES
	}

	args := flag.Args()
	if len(args) == 0 && mode == MODE_CALC_HASHES {
		flag.Usage()
		os.Exit(0)
	}

	var err error
	switch mode {
	case MODE_CALC_HASHES:
		err = modeCalcHashes(args)

	case MODE_CHECK_HASHES:
		err = modeCheckHashes(checkFlag)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func modeCalcHashes(args []string) error {
	filePaths, err := resolveFiles(args)
	if err != nil {
		return err
	}

	hashes, err := calcHashes(filePaths)
	if err != nil {
		return err
	}

	for filePath, hash := range hashes {
		fmt.Printf("%v  %v%v", hash, filePath, NL)
	}
	return nil
}

func modeCheckHashes(checkFlag *string) error {
	expectedHashes, err := readShasumsFile(*checkFlag)
	if err != nil {
		return err
	}

	filePaths := make([]string, 0, len(expectedHashes))
	for k := range expectedHashes {
		filePaths = append(filePaths, k)
	}

	hashes, err := calcHashes(filePaths)
	if err != nil {
		return err
	}

	for filePath, hash := range hashes {
		status := "OK"
		if expectedHashes[filePath] != hash {
			status = "NOT OK"
		}
		fmt.Printf("%v: %v%v", filePath, status, NL)
	}

	return nil
}

func resolveFiles(args []string) ([]string, error) {
	var filesToProcess []string
	for _, arg := range args {
		matches, err := filepath.Glob(arg)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve wildcard: %v", err)
		}

		if len(matches) == 0 {
			continue
		}
		filesToProcess = append(filesToProcess, matches...)
	}

	if len(filesToProcess) == 0 {
		return nil, fmt.Errorf("failed to resolve files")
	}

	return filesToProcess, nil
}

func calcHashes(files []string) (map[string]string, error) {
	hashes := make(map[string]string)
	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open file: %v", err)
			hashes[filePath] = "FAIL"
			continue
		}

		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to hash file: %v", err)
		}
		file.Close()

		hashBytes := hasher.Sum(nil)
		hashStr := hex.EncodeToString(hashBytes)
		hashes[filePath] = hashStr
	}

	return hashes, nil
}

func readShasumsFile(shasumsfilePath string) (map[string]string, error) {
	file, err := os.Open(shasumsfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open shasums file: %v", err)
	}
	defer file.Close()

	lineNum := 0
	scanner := bufio.NewScanner(file)
	hashes := make(map[string]string)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			fmt.Printf("skipping empty line %v%v", lineNum, NL)
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			fmt.Printf("skipping unknown line %v%v", lineNum, NL)
			continue
		}

		hash := strings.TrimFunc(parts[0], func(r rune) bool {
			return !((r >= '0' && r <= '9') ||
				(r >= 'a' && r <= 'f') ||
				(r >= 'A' && r <= 'F'))
		})
		hash = strings.ToLower(hash)
		filePath := strings.TrimFunc(parts[1], func(r rune) bool { return !unicode.IsGraphic(r) || unicode.IsSpace(r) || r == '*' })

		if hashLen := utf8.RuneCountInString(hash); hashLen != 64 {
			fmt.Printf("skipping line %v, invalid hash length, expected 64, got %v, hash: %v%v", lineNum, hashLen, hash, NL)
			continue
		}

		hashes[filePath] = hash
	}
	return hashes, nil
}
