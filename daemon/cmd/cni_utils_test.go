package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetDefaultCNINetwork(t *testing.T) {
	tempDir := t.TempDir()

	cases := []struct {
		name            string
		dir             string
		inFilename      string
		outFilename     string
		fileContents    string
		expectedFailure bool
	}{
		{
			name:            "inexistent directory",
			dir:             "/inexistent/directory",
			expectedFailure: true,
		},
		{
			name:            "empty directory",
			dir:             tempDir,
			expectedFailure: true,
		},
		{
			// Only .conf and .conflist files are detectable
			name:            "undetectable file",
			dir:             tempDir,
			expectedFailure: true,
			inFilename:      "undetectable.file",
			fileContents: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
		},
		{
			name:            "empty file",
			dir:             tempDir,
			expectedFailure: true,
			inFilename:      "empty.conf",
		},
		{
			name:            "regular file",
			dir:             tempDir,
			expectedFailure: false,
			inFilename:      "regular.conf",
			outFilename:     "regular.conf",
			fileContents: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
		},
		{
			name:            "another regular file",
			dir:             tempDir,
			expectedFailure: false,
			inFilename:      "regular2.conf",
			outFilename:     "regular.conf",
			fileContents: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.fileContents != "" {
				err := os.WriteFile(filepath.Join(c.dir, c.inFilename), []byte(c.fileContents), 0o644)
				if err != nil {
					t.Fatal(err)
				}
			}

			result, _, err := getDefaultCNINetworkList(c.dir)
			if (c.expectedFailure && err == nil) || (!c.expectedFailure && err != nil) {
				t.Fatalf("expected failure: %t, got %v", c.expectedFailure, err)
			}

			if c.fileContents != "" && c.outFilename != "" {
				if c.outFilename != filepath.Base(result) {
					t.Fatalf("expected %s, got %s", c.outFilename, result)
				}
			}
		})
	}
}

func TestInsertConfList(t *testing.T) {
	cases := []struct {
		name            string
		cniChainMode    string
		original        string
		inserted        string
		expected        string
		expectedFailure bool
	}{
		{
			name:         "insert the plugin into the file suffixed with .conf",
			cniChainMode: "generic-veth",
			original: `
 {
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
			inserted: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}
`,
			expected: `
{
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins": [
        {
            "name": "calico",
            "type": "calico"
        },
        {
            "name": "cilium-cni",
            "type": "cilium-cni"
        }
    ]
}`,
		},
		{
			name:         "insert the plugin into the file suffixed with .conflist",
			cniChainMode: "generic-veth",
			original: `
 {
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins":
    [
        {
            "name": "calico",
            "type": "calico"
        },
        {
            "name": "cilium-cni",
            "type": "cilium-cni",
			"enable-debug": true
        }
    ]
}`,
			inserted: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}
`,
			expected: `
{
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins":
    [
        {
            "name": "calico",
            "type": "calico"
        },
        {
            "name": "cilium-cni",
            "type": "cilium-cni"
        }
    ]
}`,
		},
		{
			name:         "insert the plugins suffixed with .conflist into the file suffixed with .conflist",
			cniChainMode: "generic-veth",
			original: `
 {
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins":
    [
        {
            "name": "calico",
            "type": "calico"
        },
        {
            "name": "isto-cni",
            "type": "isto-cni"
        }
    ]
}`,
			inserted: `
{
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins":
    [
        {
            "name": "portmap",
            "type": "portmap"
        },
        {
            "name": "cilium-cni",
            "type": "cilium-cni",
			"enable-debug": true
        }
    ]
}
`,
			expected: `
{
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins":
    [
        {
            "name": "calico",
            "type": "calico"
        },
        {
            "name": "isto-cni",
            "type": "isto-cni"
        },
        {
            "name": "portmap",
            "type": "portmap"
        },
        {
            "enable-debug": true,
            "name": "cilium-cni",
            "type": "cilium-cni"
        }
    ]
}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, err := insertConfList(c.cniChainMode, []byte(c.original), []byte(c.inserted))
			if (c.expectedFailure && err == nil) || (!c.expectedFailure && err != nil) {
				t.Fatalf("expected failure: %t, got %v", c.expectedFailure, err)
			}

			if c.expected != "" {
				require.JSONEqf(t, c.expected, string(result), "expected %s, got %s", c.expected, string(result))
			}
		})
	}
}

func TestGetCNINetworkListFromFile(t *testing.T) {
	tempDir := t.TempDir()

	cases := []struct {
		name            string
		inFilename      string
		fileContents    string
		outFileContents string
		expectedFailure bool
	}{
		{
			name:       "the correct content for the file suffixed with .conf",
			inFilename: "cilium.conf",
			fileContents: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
			outFileContents: `
 {
    "cniVersion": "0.3.1",
    "name": "cilium-cni",
    "plugins":
    [
        {
            "cniVersion": "0.3.1",
            "name": "cilium-cni",
            "type": "cilium-cni"
        }
    ]
}
`,
			expectedFailure: false,
		},
		{
			name:       "the correct content for the file suffixed with .conflist",
			inFilename: "cilium.conflist",
			fileContents: `
{
  "cniVersion": "0.2.0",
  "name": "generic-veth",
  "plugins": [
    {
      "name": "cilium",
      "type": "cilium-cni"
    }
  ]
}`,
			outFileContents: `
{
  "cniVersion": "0.2.0",
  "name": "generic-veth",
  "plugins": [
    {
      "name": "cilium",
      "type": "cilium-cni"
    }
  ]
}
`,
			expectedFailure: false,
		},
		{
			name:            "unexpected content in the file suffixed with .conf",
			expectedFailure: true,
			inFilename:      "cilium.conf",
			fileContents: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni"
}`,
		},
		{
			name:            "no plugins in the file suffixed with .conflist",
			expectedFailure: true,
			inFilename:      "cilium.conflist",
			fileContents: `
{
  "cniVersion": "0.2.0",
  "name": "generic-veth",
  "plugins": [
  ]
}
`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.fileContents != "" {
				err := os.WriteFile(filepath.Join(tempDir, c.inFilename), []byte(c.fileContents), 0o644)
				if err != nil {
					t.Fatal(err)
				}
			}

			result, err := getCNINetworkListFromFile(filepath.Join(tempDir, c.inFilename))
			if (c.expectedFailure && err == nil) || (!c.expectedFailure && err != nil) {
				t.Fatalf("expected failure: %t, got %v", c.expectedFailure, err)
			}

			if c.expectedFailure == false {
				require.JSONEqf(t, c.outFileContents, string(result), "expected %s, got %s", c.outFileContents, string(result))
			}
		})
	}
}
