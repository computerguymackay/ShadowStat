// Package web implements ShadowStat's HTTPS-only web interface: session-based
// login, the host dashboard, and the JSON API driving the uPlot graphs.
package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"ShadowStat/internal/auth"
	"ShadowStat/internal/store"
	"ShadowStat/internal/tlscert"
)

// Server owns ShadowStat's HTTPS listener.
type Server struct {
	httpSrv *http.Server
}

// NewServer builds a Server bound to addr, generating a self-signed certificate
// at certPath/keyPath first if neither already exists. Never serves plaintext HTTP.
func NewServer(addr, certPath, keyPath string, db *store.DB, sessions *auth.Manager) (*Server, error) {
	if err := tlscert.EnsureSelfSigned(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("ensure TLS cert: %w", err)
	}

	router := newRouter(db, sessions)

	return &Server{
		httpSrv: &http.Server{
			Addr:      addr,
			Handler:   router,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// Start runs the HTTPS server until ctx is canceled, then gracefully shuts down.
func (s *Server) Start(ctx context.Context, certPath, keyPath string) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.httpSrv.ListenAndServeTLS(certPath, keyPath)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(shutdownCtx)
	}
}
