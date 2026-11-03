package roots

import "testing"

func TestEmbeddedBundleLoads(t *testing.T) {
	p := Pool()
	if p == nil {
		t.Fatal("nil pool")
	}
	if p.Equal(nil) {
		t.Fatal("empty pool")
	}
}
