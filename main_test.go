package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestResolveFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_resolve_files")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	file1Path := filepath.Join(tmpDir, "file1.txt")
	err = os.WriteFile(file1Path, []byte("content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create %s: %v", file1Path, err)
	}

	file2Path := filepath.Join(tmpDir, "another.txt")
	err = os.WriteFile(file2Path, []byte("content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create %s: %v", file2Path, err)
	}

	file3Path := filepath.Join(tmpDir, "image.jpg")
	err = os.WriteFile(file3Path, []byte("content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create %s: %v", file3Path, err)
	}

	subDirPath := filepath.Join(tmpDir, "subdir")
	err = os.Mkdir(subDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create %s: %v", subDirPath, err)
	}
	subDirFilePath := filepath.Join(subDirPath, "subfile.txt")
	err = os.WriteFile(subDirFilePath, []byte("content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create %s: %v", subDirFilePath, err)
	}

	tests := []struct {
		name          string
		args          []string
		expectedFiles []string
		expectError   bool
	}{
		{
			name:          "single existing file",
			args:          []string{file1Path},
			expectedFiles: []string{file1Path},
			expectError:   false,
		},
		{
			name:          "multiple existing files",
			args:          []string{file1Path, file3Path},
			expectedFiles: []string{file1Path, file3Path},
			expectError:   false,
		},
		{
			name:          "non-existent file",
			args:          []string{filepath.Join(tmpDir, "nonexistent.xyz")},
			expectedFiles: []string{filepath.Join(tmpDir, "nonexistent.xyz")},
			expectError:   true,
		},
		{
			name:          "wildcard matching multiple files",
			args:          []string{filepath.Join(tmpDir, "*.txt")},
			expectedFiles: []string{file2Path, file1Path},
			expectError:   false,
		},
		{
			name:          "wildcard matching no files",
			args:          []string{filepath.Join(tmpDir, "*.xyz")},
			expectedFiles: []string{},
			expectError:   true,
		},
		{
			name:          "mix of existing, non-existent, and wildcard",
			args:          []string{file1Path, filepath.Join(tmpDir, "unknown.log"), filepath.Join(tmpDir, "*.jpg")},
			expectedFiles: []string{file1Path, file3Path},
			expectError:   false,
		},
		{
			name:          "empty args slice",
			args:          []string{},
			expectedFiles: []string{},
			expectError:   true,
		},
		{
			name:          "wildcard matching in subdir (should not match)",
			args:          []string{filepath.Join(tmpDir, "*.txt")}, // should only match in tmpDir, not subdir
			expectedFiles: []string{file2Path, file1Path},
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.args) > 0 && (strings.Contains(tt.args[0], "*") || strings.Contains(tt.args[0], "?")) {
				sort.Strings(tt.expectedFiles)
			}

			actualFiles, err := resolveFiles(tt.args)

			if (err != nil) != tt.expectError {
				t.Errorf("resolveFiles() error = %v, expectError = %v", err, tt.expectError)
				return
			}
			if err == nil {
				sort.Strings(actualFiles)
				if !compareStringSlices(t, actualFiles, tt.expectedFiles) {
					t.Errorf("resolveFiles() got = %v, want = %v", actualFiles, tt.expectedFiles)
				}
			}
		})
	}
}

func compareStringSlices(t *testing.T, a, b []string) bool {
	t.Helper()
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestCalcHashes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_calc_hashes")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir) // Sicherstellen, dass aufgeräumt wird

	tests := []struct {
		name           string
		fileContents   map[string]string
		expectedHashes map[string]string
		expectedError  bool
	}{
		{
			name: "single empty file",
			fileContents: map[string]string{
				"empty.txt": "",
			},
			expectedHashes: map[string]string{
				"empty.txt": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			expectedError: false,
		},
		{
			name: "single file with content",
			fileContents: map[string]string{
				"hello.txt": "Hello, world!",
			},
			expectedHashes: map[string]string{
				"hello.txt": "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3",
			},
			expectedError: false,
		},
		{
			name: "multiple files with content",
			fileContents: map[string]string{
				"file1.txt": "Test content one.",
				"file2.txt": "Another test content.",
				"file3.bin": "\x00\x01\x02\x03\xff\xfe",
			},
			expectedHashes: map[string]string{
				"file1.txt": "896b98df1283147c057e788f1f3e84d06dd728bdf46aec98571ca2716b55df7b",
				"file2.txt": "b19e45031891faa6bcdf255817b9b106ccc7f0a922270d2279c41d93b7a49658",
				"file3.bin": "949fabd3ca6ec0c475dfba1d815764e879a8f2c87d60dd7510d646a3027647df",
			},
			expectedError: false,
		},
		{
			name: "non-existent file in input (simulated)",
			fileContents: map[string]string{
				"existing.txt": "some content",
			},
			expectedHashes: map[string]string{
				"existing.txt":       "290f493c44f5d63d06b374d0a5abd292fae38b92cab2fae5efefe1b0e9347f56",
				"does_not_exist.txt": "949fabd3ca6ec0c475dfba1d815764e879a8f2c87d60dd7510d646a3027647df",
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var inputFiles []string
			for fileName, content := range tt.fileContents {
				filePath := filepath.Join(tmpDir, fileName)
				err := os.WriteFile(filePath, []byte(content), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file %s: %v", filePath, err)
				}
				inputFiles = append(inputFiles, filePath)
			}

			if tt.name == "non-existent file in input (simulated)" {
				inputFiles = append(inputFiles, filepath.Join(tmpDir, "does_not_exist.txt"))
			}

			actualHashes, err := calcHashes(inputFiles)

			if (err != nil) != tt.expectedError {
				t.Errorf("calcHashes() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if tt.expectedError {
				return
			}

			if len(actualHashes) != len(tt.expectedHashes) {
				t.Errorf("calcHashes() returned map of unexpected size. Got %d, want %d", len(actualHashes), len(tt.expectedHashes))
				return
			}

			for fileName, expectedHash := range tt.expectedHashes {
				fullPath := filepath.Join(tmpDir, fileName)
				actualHash, ok := actualHashes[fullPath]
				if !ok {
					t.Errorf("calcHashes() missing hash for file %s", fullPath)
					continue
				}
				if tt.name == "non-existent file in input (simulated)" {
					if fileName == "does_not_exist.txt" && actualHash != "FAIL" {
						t.Errorf("actual hash should contain an error but contained %v", actualHash)
					}
				} else if actualHash != expectedHash {
					t.Errorf("calcHashes() hash mismatch for %s. Got %s, want %s", fullPath, actualHash, expectedHash)
				}
			}
		})
	}
}

func TestReadShasumsFile(t *testing.T) {
	tests := []struct {
		name           string
		fileContent    string
		fileName       string
		expectedHashes map[string]string
		expectError    bool
		errorContains  string
	}{
		{
			name: "valid file with multiple entries",
			fileContent: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.txt\n" +
				"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bffc941dfce21b3  hello world.txt\n" +
				"6a2bf854ffb0d7d8e411bf9087595e1e1948574765d770c8c078832a82645e5b  file with spaces.txt",
			expectedHashes: map[string]string{
				"empty.txt":            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"hello world.txt":      "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bffc941dfce21b3",
				"file with spaces.txt": "6a2bf854ffb0d7d8e411bf9087595e1e1948574765d770c8c078832a82645e5b",
			},
			expectError: false,
		},
		{
			name:           "empty file",
			fileContent:    "",
			expectedHashes: map[string]string{},
			expectError:    false,
		},
		{
			name:           "file with only empty lines",
			fileContent:    "\n   \n\t\n",
			expectedHashes: map[string]string{},
			expectError:    false,
		},
		{
			name: "file with invalid format lines",
			fileContent: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" + // missing file
				"invalid line format", // no space
			expectedHashes: map[string]string{},
			expectError:    false, // function prints warnings and skips, doesn't return error
		},
		{
			name: "file with invalid hash length",
			fileContent: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85  short_hash.txt\n" + // 63 chars
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555  long_hash.txt", // 65 chars
			expectedHashes: map[string]string{},
			expectError:    false, // function prints warnings and skips, doesn't return error
		},
		{
			name:           "file with non-hex characters in hash",
			fileContent:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85X  bad_hash.txt",
			expectedHashes: map[string]string{},
			expectError:    false, // function prints warnings and skips, doesn't return error
		},
		{
			name: "mix of valid and invalid lines",
			fileContent: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  valid1.txt\n" +
				"invalid line format\n" +
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555  long_hash.txt\n" +
				"0000000000000000000000000000000000000000000000000000000000000000  valid2.txt",
			expectedHashes: map[string]string{
				"valid1.txt": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"valid2.txt": "0000000000000000000000000000000000000000000000000000000000000000",
			},
			expectError: false,
		},
		{
			name:           "non-existent shasums file",
			fileContent:    "", // Not relevant for this test case
			fileName:       "non_existent_shasums.txt",
			expectedHashes: nil,
			expectError:    true,
			errorContains:  "failed to open shasums file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "test_shasums_read")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			shasumsFilePath := filepath.Join(tmpDir, "test_shasums.txt")
			if tt.fileName != "" { // Override default for non-existent file test
				shasumsFilePath = filepath.Join(tmpDir, tt.fileName)
			} else {
				err = os.WriteFile(shasumsFilePath, []byte(tt.fileContent), 0644)
				if err != nil {
					t.Fatalf("Failed to write test shasums file: %v", err)
				}
			}

			actualHashes, err := readShasumsFile(shasumsFilePath)

			if (err != nil) != tt.expectError {
				t.Errorf("readShasumsFile() error = %v, expectError %v", err, tt.expectError)
				return
			}
			if tt.expectError {
				if tt.errorContains != "" && err != nil && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("readShasumsFile() error message '%v' did not contain '%v'", err.Error(), tt.errorContains)
				}
				return
			}

			if len(actualHashes) != len(tt.expectedHashes) {
				t.Errorf("readShasumsFile() returned map of unexpected size. Got %d, want %d", len(actualHashes), len(tt.expectedHashes))
				return
			}

			for filePath, expectedHash := range tt.expectedHashes {
				actualHash, ok := actualHashes[filePath]
				if !ok {
					t.Errorf("readShasumsFile() missing hash for file %s", filePath)
					continue
				}
				if actualHash != expectedHash {
					t.Errorf("readShasumsFile() hash mismatch for %s. Got %s, want %s", filePath, actualHash, expectedHash)
				}
			}
		})
	}
}
