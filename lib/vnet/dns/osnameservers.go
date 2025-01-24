package dns

import (
	"context"
	"time"

	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
)

// OSUpstreamNameserverSource provides the list of upstream DNS nameservers
// configured in the OS. The VNet DNS resolver will forward unhandles queries to
// these nameservers.
type OSUpstreamNameserverSource struct {
	ttlCache *utils.FnCache
}

// NewOSUpstreamNameserverSource returns a new *OSUpstreamNameserverSource.
func NewOSUpstreamNameserverSource() (*OSUpstreamNameserverSource, error) {
	ttlCache, err := utils.NewFnCache(utils.FnCacheConfig{
		TTL: 10 * time.Second,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &OSUpstreamNameserverSource{
		ttlCache: ttlCache,
	}, nil
}

// UpstreamNameservers returns a cached view of the host OS's current default
// nameservers, as found in /etc/resolv.conf.
func (s *OSUpstreamNameserverSource) UpstreamNameservers(ctx context.Context) ([]string, error) {
	return utils.FnCacheGet(ctx, s.ttlCache, 0, s.upstreamNameservers)
}

func loadUpstreamNameservers(ctx context.Context) ([]string, error) {
	return platformLoadUpstreamNameservers, nil
}
