//go:build linux || freebsd
// +build linux freebsd

package libpod

import (
	"fmt"
	"net/http"

	"github.com/containers/common/pkg/config"
	"github.com/containers/common/pkg/resize"
	"github.com/containers/conmon-rs/pkg/client"
	"github.com/containers/podman/v4/libpod/define"
	spec "github.com/opencontainers/runtime-spec/specs-go"
)

type ConmonRSOCIRuntime struct {
	name string

	client client.ConmonClient
}

func newConmonRSOCIRuntime(name string, paths []string, runtimeFlags []string, runtimeCfg *config.Config) (OCIRuntime, error) {
	runtime := new(ConmonRSOCIRuntime)
	runtime.name = name
	return runtime, nil
}

// Name returns the name of the runtime.
func (r *ConmonRSOCIRuntime) Name() string {
	return fmt.Sprintf("conmon-rs:%s", r.name)
}

// Path returns the path to the runtime executable.
func (r *ConmonRSOCIRuntime) Path() string {
	return "(todo: runtime path)"
}

// CreateContainer creates the container in the OCI runtime.
// The returned int64 contains the microseconds needed to restore
// the given container if it is a restore and if restoreOptions.PrintStats
// is true. In all other cases the returned int64 is 0.
func (r *ConmonRSOCIRuntime) CreateContainer(ctr *Container, restoreOptions *ContainerCheckpointOptions) (int64, error) {
	return 0, r.printError("CreateContainer")
}

// UpdateContainerStatus updates the status of the given container.
func (r *ConmonRSOCIRuntime) UpdateContainerStatus(ctr *Container) error {
	return r.printError("UpdateContainerStatus")
}

// StartContainer starts the given container.
func (r *ConmonRSOCIRuntime) StartContainer(ctr *Container) error {
	return r.printError("StartContainer")
}

// KillContainer sends the given signal to the given container.
// If all is set, all processes in the container will be signalled;
// otherwise, only init will be signalled.
func (r *ConmonRSOCIRuntime) KillContainer(ctr *Container, signal uint, all bool) error {
	return r.printError("KillContainer")
}

// StopContainer stops the given container.
// The container's stop signal (or SIGTERM if unspecified) will be sent
// first.
// After the given timeout, SIGKILL will be sent.
// If the given timeout is 0, SIGKILL will be sent immediately, and the
// stop signal will be omitted.
// If all is set, we will attempt to use the --all flag will `kill` in
// the OCI runtime to kill all processes in the container, including
// exec sessions. This is only supported if the container has cgroups.
func (r *ConmonRSOCIRuntime) StopContainer(ctr *Container, timeout uint, all bool) error {
	return r.printError("StopContainer")
}

// DeleteContainer deletes the given container from the OCI runtime.
func (r *ConmonRSOCIRuntime) DeleteContainer(ctr *Container) error {
	return r.printError("DeleteContainer")
}

// PauseContainer pauses the given container.
func (r *ConmonRSOCIRuntime) PauseContainer(ctr *Container) error {
	return r.printError("PauseContainer")
}

// UnpauseContainer unpauses the given container.
func (r *ConmonRSOCIRuntime) UnpauseContainer(ctr *Container) error {
	return r.printError("UnpauseContainer")
}

// Attach to a container.
func (r *ConmonRSOCIRuntime) Attach(ctr *Container, params *AttachOptions) error {
	return r.printError("Attach")
}

// HTTPAttach performs an attach intended to be transported over HTTP.
// For terminal attach, the container's output will be directly streamed
// to output; otherwise, STDOUT and STDERR will be multiplexed, with
// a header prepended as follows: 1-byte STREAM (0, 1, 2 for STDIN,
// STDOUT, STDERR), 3 null (0x00) bytes, 4-byte big endian length.
// If a cancel channel is provided, it can be used to asynchronously
// terminate the attach session. Detach keys, if given, will also cause
// the attach session to be terminated if provided via the STDIN
// channel. If they are not provided, the default detach keys will be
// used instead. Detach keys of "" will disable detaching via keyboard.
// The streams parameter will determine which streams to forward to the
// client.
func (r *ConmonRSOCIRuntime) HTTPAttach(ctr *Container, req *http.Request, w http.ResponseWriter, streams *HTTPAttachStreams, detachKeys *string, cancel <-chan bool, hijackDone chan<- bool, streamAttach, streamLogs bool) error {
	return r.printError("HTTPAttach")
}

// AttachResize resizes the terminal in use by the given container.
func (r *ConmonRSOCIRuntime) AttachResize(ctr *Container, newSize resize.TerminalSize) error {
	return r.printError("AttachResize")
}

// ExecContainer executes a command in a running container.
// Returns an int (PID of exec session), error channel (errors from
// attach), and error (errors that occurred attempting to start the exec
// session). This returns once the exec session is running - not once it
// has completed, as one might expect. The attach session will remain
// running, in a goroutine that will return via the chan error in the
// return signature.
// newSize resizes the tty to this size before the process is started, must be nil if the exec session has no tty
func (r *ConmonRSOCIRuntime) ExecContainer(ctr *Container, sessionID string, options *ExecOptions, streams *define.AttachStreams, newSize *resize.TerminalSize) (int, chan error, error) {
	return -1, nil, r.printError("ExecContainer")
}

// ExecContainerHTTP executes a command in a running container and
// attaches its standard streams to a provided hijacked HTTP session.
// Maintains the same invariants as ExecContainer (returns on session
// start, with a goroutine running in the background to handle attach).
// The HTTP attach itself maintains the same invariants as HTTPAttach.
// newSize resizes the tty to this size before the process is started, must be nil if the exec session has no tty
func (r *ConmonRSOCIRuntime) ExecContainerHTTP(ctr *Container, sessionID string, options *ExecOptions, req *http.Request, w http.ResponseWriter,
	streams *HTTPAttachStreams, cancel <-chan bool, hijackDone chan<- bool, holdConnOpen <-chan bool, newSize *resize.TerminalSize) (int, chan error, error) {
	return -1, nil, r.printError("ExecContainerHTTP")
}

// ExecContainerDetached executes a command in a running container, but
// does not attach to it. Returns the PID of the exec session and an
// error (if starting the exec session failed)
func (r *ConmonRSOCIRuntime) ExecContainerDetached(ctr *Container, sessionID string, options *ExecOptions, stdin bool) (int, error) {
	return -1, r.printError("ExecContainerDetached")
}

// ExecAttachResize resizes the terminal of a running exec session. Only
// allowed with sessions that were created with a TTY.
func (r *ConmonRSOCIRuntime) ExecAttachResize(ctr *Container, sessionID string, newSize resize.TerminalSize) error {
	return r.printError("ExecAttachResize")
}

// ExecStopContainer stops a given exec session in a running container.
// SIGTERM with be sent initially, then SIGKILL after the given timeout.
// If timeout is 0, SIGKILL will be sent immediately, and SIGTERM will
// be omitted.
func (r *ConmonRSOCIRuntime) ExecStopContainer(ctr *Container, sessionID string, timeout uint) error {
	return r.printError("ExecStopContainer")
}

// ExecUpdateStatus checks the status of a given exec session.
// Returns true if the session is still running, or false if it exited.
func (r *ConmonRSOCIRuntime) ExecUpdateStatus(ctr *Container, sessionID string) (bool, error) {
	return false, r.printError("ExecUpdateStatus")
}

// CheckpointContainer checkpoints the given container.
// Some OCI runtimes may not support this - if SupportsCheckpoint()
// returns false, this is not implemented, and will always return an
// error. If CheckpointOptions.PrintStats is true the first return parameter
// contains the number of microseconds the runtime needed to checkpoint
// the given container.
func (r *ConmonRSOCIRuntime) CheckpointContainer(ctr *Container, options ContainerCheckpointOptions) (int64, error) {
	return 0, r.printError("CheckpointContainer")
}

// CheckConmonRunning verifies that the given container's Conmon
// instance is still running. Runtimes without Conmon, or systems where
// the PID of conmon is not available, should mock this as True.
// True indicates that Conmon for the instance is running, False
// indicates it is not.
func (r *ConmonRSOCIRuntime) CheckConmonRunning(ctr *Container) (bool, error) {
	return false, r.printError("CheckConmonRunning")
}

// SupportsCheckpoint returns whether this OCI runtime
// implementation supports the CheckpointContainer() operation.
func (r *ConmonRSOCIRuntime) SupportsCheckpoint() bool {
	return false
}

// SupportsJSONErrors is whether the runtime can return JSON-formatted
// error messages.
func (r *ConmonRSOCIRuntime) SupportsJSONErrors() bool {
	return false
}

// SupportsNoCgroups is whether the runtime supports running containers
// without cgroups.
func (r *ConmonRSOCIRuntime) SupportsNoCgroups() bool {
	return false
}

// SupportsKVM os whether the OCI runtime supports running containers
// without KVM separation
func (r *ConmonRSOCIRuntime) SupportsKVM() bool {
	return false
}

// AttachSocketPath is the path to the socket to attach to a given
// container.
func (r *ConmonRSOCIRuntime) AttachSocketPath(ctr *Container) (string, error) {
	return "", r.printError("AttachSocketPath")
}

// ExecAttachSocketPath is the path to the socket to attach to a given
// exec session in the given container.
func (r *ConmonRSOCIRuntime) ExecAttachSocketPath(ctr *Container, sessionID string) (string, error) {
	return "", r.printError("ExecAttachSocketPath")
}

// ExitFilePath is the path to a container's exit file.
func (r *ConmonRSOCIRuntime) ExitFilePath(ctr *Container) (string, error) {
	return "", r.printError("ExitFilePath")
}

// RuntimeInfo returns verbose information about the runtime.
func (r *ConmonRSOCIRuntime) RuntimeInfo() (*define.ConmonInfo, *define.OCIRuntimeInfo, error) {
	conmon := define.ConmonInfo{
		Package: "todo: package",
		Path:    "conmonrs (in PATH)",
		Version: "todo: version",
	}
	ocirt := define.OCIRuntimeInfo{
		Name:    r.name,
		Path:    "todo: path",
		Package: "todo: package",
		Version: "todo: version",
	}
	return &conmon, &ocirt, nil
}

// UpdateContainer updates the given container's cgroup configuration.
func (r *ConmonRSOCIRuntime) UpdateContainer(ctr *Container, resources *spec.LinuxResources) error {
	return r.printError("UpdateContainer")
}

// Return an error indicating the feature is not implemented
func (r *ConmonRSOCIRuntime) printError(feature string) error {
	return fmt.Errorf("conmon-rs runtime %s: %s not implemented", r.name, feature)
}
