package sha3

import (
	"testing"

	"github.com/dedis/crypto/test"
)

func TestAES(t *testing.T) {
	test.CipherTest(t, NewCipher224)
}
