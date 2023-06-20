//go:build linux || freebsd
// +build linux freebsd

package libpod

import (
	"github.com/containers/conmon-rs/pkg/client"
)


type ConmonRSOCIRuntime struct {
	client client.ConmonClient
}
