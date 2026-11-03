package discover

import (
	"context"
	"net"
	"strings"
)

// NetResolver adapts net.Resolver to the Resolver interface.
type NetResolver struct{ R *net.Resolver }

// LookupHost resolves A and AAAA records.
func (n NetResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return n.resolver().LookupHost(ctx, host)
}

// LookupCNAME returns the canonical name, or "" when the name is already
// canonical.
func (n NetResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	cname, err := n.resolver().LookupCNAME(ctx, host)
	if err != nil {
		return "", err
	}
	if strings.EqualFold(strings.TrimSuffix(cname, "."), host) {
		return "", nil
	}
	return cname, nil
}

func (n NetResolver) resolver() *net.Resolver {
	if n.R != nil {
		return n.R
	}
	return net.DefaultResolver
}
