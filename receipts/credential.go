// SPDX-License-Identifier: Apache-2.0

package receipts

import (
	"errors"
	"fmt"

	"github.com/Ad-Astra-Computing/receipts/c2pa"
)

// c2paVerify runs SPEC.md section 8 step 5: the embedded credential
// must carry a valid signature of its own, and it must bind the same
// body and the same author identity as the bundle around it. Without
// the bindings an attacker holding a genuine bundle could swap in a
// differently signed credential and still pass every outer check.
func c2paVerify(b Bundle) error {
	if err := c2pa.Verify(b.Credential); err != nil {
		return fmt.Errorf("receipts: embedded credential: %w", err)
	}
	if b.Credential.Asset.SHA256 != b.Post.SHA256 {
		return errors.New("receipts: credential asset hash does not match post hash")
	}
	if b.Credential.Signature.PublicKey != b.Signature.PublicKey {
		return errors.New("receipts: credential is signed by a different key")
	}
	return nil
}
