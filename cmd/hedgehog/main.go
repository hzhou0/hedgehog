// Command hedgehog scans the images running in a cluster with grype and, for critical, actively exploited
// vulnerabilities, builds patched images (copa plus node runtime replacement), rewrites Pods to them, and blocks
// changes that would keep the vulnerable images.
//
// Configuration is by environment variable: see deploy/hedgehog.yaml.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"hedgehog/internal"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	log.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := internal.Run(ctx); err != nil {
		slog.Error("hedgehog exited", "err", err)
		os.Exit(1)
	}
}
