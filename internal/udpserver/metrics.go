package udpserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// MetricsHandler exposes a dependency-free Prometheus endpoint and a liveness
// endpoint. It intentionally contains no configuration or key material.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		stats := s.Stats()
		writeMetric := func(name string, value uint64) {
			_, _ = fmt.Fprintf(w, "# TYPE cottendns_%s gauge\ncottendns_%s %d\n", name, name, value)
		}
		writeMetric("active_sessions", stats.ActiveSessions)
		writeMetric("active_streams", stats.ActiveStreams)
		writeMetric("dropped_packets_total", stats.DroppedPackets)
		writeMetric("deferred_dropped_packets_total", stats.DeferredDroppedPackets)
		writeMetric("stream_cap_rejections_total", stats.StreamCapRejections)
		writeMetric("dns_response_oversize_total", stats.DNSResponseOversize)
		writeMetric("fragment_conflict_drops_total", stats.FragmentConflictDrops)
		writeMetric("fragment_invalid_header_total", stats.FragmentInvalidHeader)
		writeMetric("dns_upstream_queries_total", stats.DNSUpstreamQueries)
		writeMetric("dns_upstream_failures_total", stats.DNSUpstreamFailures)
		writeMetric("dns_upstream_hedges_total", stats.DNSUpstreamHedges)
		writeMetric("dns_upstream_tcp_fallbacks_total", stats.DNSUpstreamTCPFallbacks)
	})
	return mux
}

func (s *Server) ServeMetrics(ctx context.Context, listener net.Listener) error {
	server := &http.Server{Handler: s.MetricsHandler(), ReadHeaderTimeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		case <-done:
		}
	}()
	err := server.Serve(listener)
	close(done)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
