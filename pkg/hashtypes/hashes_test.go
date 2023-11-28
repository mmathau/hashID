package hashtypes

import (
	"os"
	"testing"
)

var hashid *Hashes

func TestMain(m *testing.M) {
	var err error
	hashid, err = New()
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func TestFindHashType(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		expected string
	}{
		{
			name:     "md5",
			hash:     "5f4dcc3b5aa765d61d8327deb882cf99",
			expected: "MD5",
		},
		{
			name:     "sha1",
			hash:     "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
			expected: "SHA1",
		},
		{
			name:     "SHA2-256",
			hash:     "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb9",
			expected: "SHA2-256",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashid.FindHashType(tt.hash)
			found := false
			for _, hash := range got {
				if hash.Name() == tt.expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected hash type %q not found in results", tt.expected)
			}
		})
	}

}
