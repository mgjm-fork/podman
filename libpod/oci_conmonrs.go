//go:build linux || freebsd
// +build linux freebsd

package libpod

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containers/common/pkg/config"
	"github.com/containers/common/pkg/resize"
	cutil "github.com/containers/common/pkg/util"
	"github.com/containers/conmon-rs/pkg/client"
	"github.com/containers/podman/v4/libpod/define"
	"github.com/containers/podman/v4/pkg/errorhandling"
	"github.com/containers/podman/v4/pkg/rootless"
	"github.com/containers/podman/v4/pkg/specgenutil"
	"github.com/containers/podman/v4/pkg/util"
	"github.com/containers/podman/v4/utils"
	"github.com/containers/storage/pkg/homedir"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type ConmonRSOCIRuntime struct {
	name              string
	path              string
	conmonRSPath      string
	conmonRSEnv       []string
	tmpDir            string
	exitsDir          string
	logSizeMax        uint64
	noPivot           bool
	reservePorts      bool
	runtimeFlags      []string
	supportsJSON      bool
	supportsKVM       bool
	supportsNoCgroups bool
	enableKeyring     bool

	cachedClient *client.ConmonClient
}

func newConmonRSOCIRuntime(name string, paths []string, runtimeFlags []string, runtimeCfg *config.Config) (OCIRuntime, error) {
	if name == "" {
		return nil, fmt.Errorf("the OCI runtime must be provided a non-empty name: %w", define.ErrInvalidArg)
	}

	runtime := new(ConmonRSOCIRuntime)
	runtime.name = name
	runtime.conmonRSPath = "conmonrs" // TODO: make this configurable?
	runtime.runtimeFlags = runtimeFlags

	runtime.conmonRSEnv = runtimeCfg.Engine.ConmonEnvVars // TODO: custom conmon-rs env vars?
	runtime.tmpDir = runtimeCfg.Engine.TmpDir
	if runtimeCfg.Containers.LogSizeMax > 0 {
		runtime.logSizeMax = uint64(runtimeCfg.Containers.LogSizeMax)
	}
	runtime.noPivot = runtimeCfg.Engine.NoPivotRoot
	runtime.reservePorts = runtimeCfg.Engine.EnablePortReservation
	runtime.enableKeyring = runtimeCfg.Containers.EnableKeyring

	// TODO: probe OCI runtime for feature and enable automatically if
	// available.

	base := filepath.Base(name)
	runtime.supportsJSON = stringSliceContains(runtimeCfg.Engine.RuntimeSupportsJSON, base)
	runtime.supportsNoCgroups = stringSliceContains(runtimeCfg.Engine.RuntimeSupportsNoCgroups, base)
	runtime.supportsKVM = stringSliceContains(runtimeCfg.Engine.RuntimeSupportsKVM, base)

	foundPath := false
	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("cannot stat OCI runtime %s path: %w", name, err)
		}
		if !stat.Mode().IsRegular() {
			continue
		}
		foundPath = true
		logrus.Tracef("found runtime %q", path)
		runtime.path = path
		break
	}

	// Search the $PATH as last fallback
	if !foundPath {
		if foundRuntime, err := exec.LookPath(name); err == nil {
			foundPath = true
			runtime.path = foundRuntime
			logrus.Debugf("using runtime %q from $PATH: %q", name, foundRuntime)
		}
	}

	if !foundPath {
		return nil, fmt.Errorf("no valid executable found for OCI runtime %s: %w", name, define.ErrInvalidArg)
	}

	runtime.exitsDir = filepath.Join(runtime.tmpDir, "exits")

	// Create the exit files and attach sockets directories
	if err := os.MkdirAll(runtime.exitsDir, 0750); err != nil {
		// The directory is allowed to exist
		if !os.IsExist(err) {
			return nil, fmt.Errorf("creating OCI runtime exit files directory: %w", err)
		}
	}

	return runtime, nil
}

func (r *ConmonRSOCIRuntime) cgroupManager(ctr *Container) (client.CgroupManager, error) {
	switch ctr.CgroupManager() {
	case config.SystemdCgroupsManager:
		return client.CgroupManagerSystemd, nil
	case config.CgroupfsCgroupsManager:
		return client.CgroupManagerCgroupfs, nil
	default:
		return -1, fmt.Errorf("unsupported conmon-rs cgroup manager: %q", ctr.CgroupManager())
	}
}

func (r *ConmonRSOCIRuntime) client() (*client.ConmonClient, error) {
	if r.cachedClient == nil {
		// TODO: ServerRunDir = ???
		serverConfig := client.NewConmonServerConfig(r.path, "", "/run/libpod/conmon-rs")
		// TODO: serverConfig.LogLevel =
		// TODO: log to logfile (set serverConfig.Stdout / Stderr)
		serverConfig.LogDriver = client.LogDriverStdout

		client, err := client.New(serverConfig)
		if err != nil {
			return nil, err
		}
		r.cachedClient = client
	}
	return r.cachedClient, nil
}

// Name returns the name of the runtime.
func (r *ConmonRSOCIRuntime) Name() string {
	return fmt.Sprintf("conmon-rs:%s", r.name)
}

// Path returns the path to the runtime executable.
func (r *ConmonRSOCIRuntime) Path() string {
	return r.path
}

// CreateContainer creates the container in the OCI runtime.
// The returned int64 contains the microseconds needed to restore
// the given container if it is a restore and if restoreOptions.PrintStats
// is true. In all other cases the returned int64 is 0.
func (r *ConmonRSOCIRuntime) CreateContainer(ctr *Container, restoreOptions *ContainerCheckpointOptions) (int64, error) {
	// always make the run dir accessible to the current user so that the PID files can be read without
	// being in the rootless user namespace.
	if err := makeAccessible(ctr.state.RunDir, 0, 0); err != nil {
		return 0, err
	}

	if !hasCurrentUserMapped(ctr) {
		for _, i := range []string{ctr.state.RunDir, ctr.runtime.config.Engine.TmpDir, ctr.config.StaticDir, ctr.state.Mountpoint, ctr.runtime.config.Engine.VolumePath} {
			if err := makeAccessible(i, ctr.RootUID(), ctr.RootGID()); err != nil {
				return 0, err
			}
		}

		// if we are running a non privileged container, be sure to umount some kernel paths so they are not
		// bind mounted inside the container at all.
		if !ctr.config.Privileged && !rootless.IsRootless() {
			return 0, r.printError("createRootlessContainer")
			// return r.createRootlessContainer(ctr, restoreOptions)
		}
	}

	return r.createOCIContainer(ctr, restoreOptions)
}

func (r *ConmonRSOCIRuntime) createOCIContainer(ctr *Container, restoreOptions *ContainerCheckpointOptions) (int64, error) {
	var err error

	runtimeDir, err := util.GetRuntimeDir()
	if err != nil {
		return 0, err
	}

	var ociLogPath string
	if logrus.GetLevel() != logrus.DebugLevel && r.supportsJSON {
		ociLogPath = filepath.Join(ctr.state.RunDir, "oci-log")
	}

	if logTag := ctr.LogTag(); logTag != "" {
		return 0, fmt.Errorf("log tag specified %q, but not supported with conmon-rs", logTag)
	}

	switch ctr.config.CgroupsMode {
	case cgroupSplit:
		return 0, fmt.Errorf("cgroups mode %q not supported with conmon-rs", ctr.config.CgroupsMode)
	case "enabled":
		logrus.Warnf("cgroups mode %q used with conmon-rs, handled as %q", ctr.config.CgroupsMode, "no-conmon")
	}

	if ctr.config.PidFile != "" {
		return 0, fmt.Errorf("pid file specified %q, but not supported with conmon-rs", ctr.config.PidFile)
	}

	config := new(client.CreateContainerConfig)
	config.ID = ctr.ID()
	config.BundlePath = ctr.bundlePath()

	if ctr.Terminal() {
		config.Terminal = true
	} else if ctr.config.Stdin {
		config.Stdin = true
	}

	config.ExitPaths = []string{filepath.Join(r.exitsDir, ctr.ID())}
	config.OOMExitPaths = []string{} // TODO

	maxSize := r.logSizeMax
	if ctr.config.LogSize > 0 {
		maxSize = uint64(ctr.config.LogSize)
	}

	logDriver := ctr.LogDriver()
	switch logDriver {
	case define.JournaldLogging:
		fallthrough
	case define.NoLogging:
		fallthrough
	case define.PassthroughLogging:
		return 0, fmt.Errorf("%s log driver not supported with conmon-rs", logDriver)
	//lint:ignore ST1015 the default case has to be here
	default: //nolint:gocritic
		// No case here should happen except JSONLogging, but keep this here in case the options are extended
		logrus.Errorf("%s logging specified but not supported. Choosing k8s-file logging instead", ctr.LogDriver())
		fallthrough
	case "":
		// to get here, either a user would specify `--log-driver ""`, or this came from another place in libpod
		// since the former case is obscure, and the latter case isn't an error, let's silently fallthrough
		fallthrough
	case define.JSONLogging:
		fallthrough
	case define.KubernetesLogging:
		config.LogDrivers = []client.ContainerLogDriver{{
			Type:    client.LogDriverTypeContainerRuntimeInterface,
			Path:    ctr.LogPath(),
			MaxSize: maxSize,
		}}
	}

	config.GlobalArgs = append(config.GlobalArgs, r.runtimeFlags...)

	if ociLogPath != "" {
		config.GlobalArgs = append(config.GlobalArgs, "--log-format=json", "--log", ociLogPath)
	}

	if ctr.config.NoCgroups {
		logrus.Debugf("Running with no Cgroups")
		config.GlobalArgs = append(config.GlobalArgs, "--cgroup-manager", "disabled")
	}

	if ctr.config.SdNotifyMode == define.SdNotifyModeContainer && ctr.config.SdNotifySocket != "" {
		// TODO
		return 0, fmt.Errorf("sd-notify mode container not supported with conmon-rs")
	}

	ctx := context.Background()
	if ctr.config.Timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, time.Duration(ctr.config.Timeout)*time.Second)
		defer cancel()
	}

	if !r.enableKeyring {
		config.GlobalArgs = append(config.GlobalArgs, "--no-new-keyring")

	}

	if ctr.config.ConmonPidFile != "" {
		return 0, fmt.Errorf("conmon pid file specified %q, but not supported with conmon-rs", ctr.config.ConmonPidFile)
	}

	if r.noPivot {
		config.GlobalArgs = append(config.GlobalArgs, "--no-pivot")
	}

	config.CleanupCmd, err = specgenutil.CreateExitCommandArgs(ctr.runtime.storageConfig, ctr.runtime.config, logrus.IsLevelEnabled(logrus.DebugLevel), ctr.AutoRemove(), false)
	if err != nil {
		return 0, err
	}
	config.CleanupCmd = append(config.CleanupCmd, ctr.ID())

	preserveFDs := ctr.config.PreserveFDs
	if val := os.Getenv("LISTEN_FDS"); val != "" {
		if ctr.config.PreserveFDs > 0 {
			logrus.Warnf("Ignoring LISTEN_FDS to preserve custom user-specified FDs")
		} else {
			fds, err := strconv.Atoi(val)
			if err != nil {
				return 0, fmt.Errorf("converting LISTEN_FDS=%s: %w", val, err)
			}
			preserveFDs = uint(fds)
		}
	}

	if preserveFDs > 0 {
		config.CommandArgs = append(config.CommandArgs, "--preserve-fds", fmt.Sprintf("%d", preserveFDs))
	}

	if restoreOptions != nil {
		return 0, r.printError("create: restoreOptions")
	}

	var filesToClose []*os.File
	var extraFiles []int
	if preserveFDs > 0 {
		for fd := 3; fd < int(3+preserveFDs); fd++ {
			f := os.NewFile(uintptr(fd), fmt.Sprintf("fd-%d", fd))
			filesToClose = append(filesToClose, f)
			extraFiles = append(extraFiles, int(f.Fd()))
		}
	}

	config.EnvVars = append(config.EnvVars, r.configureConmonEnv(runtimeDir)...)

	if r.reservePorts && !rootless.IsRootless() && !ctr.config.NetMode.IsSlirp4netns() {
		ports, err := bindPorts(ctr.convertPortMappings())
		if err != nil {
			return 0, err
		}
		filesToClose = append(filesToClose, ports...)

		// Leak the port we bound in the conmon process.  These fd's won't be used
		// by the container and conmon will keep the ports busy so that another
		// process cannot use them.
		for _, port := range ports {
			extraFiles = append(extraFiles, int(port.Fd()))
		}
	}

	if ctr.config.NetMode.IsSlirp4netns() || rootless.IsRootless() {
		if ctr.config.PostConfigureNetNS {
			havePortMapping := len(ctr.config.PortMappings) > 0
			if havePortMapping {
				ctr.rootlessPortSyncR, ctr.rootlessPortSyncW, err = os.Pipe()
				if err != nil {
					return 0, fmt.Errorf("failed to create rootless port sync pipe: %w", err)
				}
			}
			ctr.rootlessSlirpSyncR, ctr.rootlessSlirpSyncW, err = os.Pipe()
			if err != nil {
				return 0, fmt.Errorf("failed to create rootless network sync pipe: %w", err)
			}
		} else {
			if ctr.rootlessSlirpSyncR != nil {
				defer errorhandling.CloseQuiet(ctr.rootlessSlirpSyncR)
			}
			if ctr.rootlessSlirpSyncW != nil {
				defer errorhandling.CloseQuiet(ctr.rootlessSlirpSyncW)
			}
		}
		// Leak one end in conmon, the other one will be leaked into slirp4netns
		extraFiles = append(extraFiles, int(ctr.rootlessSlirpSyncW.Fd()))

		if ctr.rootlessPortSyncW != nil {
			defer errorhandling.CloseQuiet(ctr.rootlessPortSyncW)
			// Leak one end in conmon, the other one will be leaked into rootlessport
			extraFiles = append(extraFiles, int(ctr.rootlessPortSyncW.Fd()))
		}
	}

	config.CgroupManager, err = r.cgroupManager(ctr)
	if err != nil {
		return 0, err
	}

	client, err := r.client()
	if err != nil {
		return 0, err
	}

	if len(extraFiles) > 0 {
		remoteFds, err := client.RemoteFds(ctx)
		if err != nil {
			return 0, err
		}
		defer remoteFds.Close()

		config.AdditionalFds, err = remoteFds.Send(extraFiles...)
		if err != nil {
			return 0, err
		}

	}

	var runtimeRestoreStarted time.Time
	if restoreOptions != nil {
		runtimeRestoreStarted = time.Now()
	}

	res, err := client.CreateContainer(ctx, config)
	if err != nil {
		return 0, err
	}

	ctr.state.PID = int(res.PID)

	runtimeRestoreDuration := func() int64 {
		if restoreOptions != nil && restoreOptions.PrintStats {
			return time.Since(runtimeRestoreStarted).Microseconds()
		}
		return 0
	}()

	// These fds were passed down to the runtime.  Close them
	// and not interfere
	for _, f := range filesToClose {
		errorhandling.CloseQuiet(f)
	}

	return runtimeRestoreDuration, nil
}

// configureConmonEnv gets the environment values to add to conmon's exec struct
// TODO this may want to be less hardcoded/more configurable in the future
func (r *ConmonRSOCIRuntime) configureConmonEnv(runtimeDir string) []string {
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "LC_") {
			env = append(env, e)
		}
	}
	if path, ok := os.LookupEnv("PATH"); ok {
		env = append(env, fmt.Sprintf("PATH=%s", path))
	}
	if conf, ok := os.LookupEnv("CONTAINERS_CONF"); ok {
		env = append(env, fmt.Sprintf("CONTAINERS_CONF=%s", conf))
	}
	if conf, ok := os.LookupEnv("CONTAINERS_HELPER_BINARY_DIR"); ok {
		env = append(env, fmt.Sprintf("CONTAINERS_HELPER_BINARY_DIR=%s", conf))
	}
	env = append(env, fmt.Sprintf("XDG_RUNTIME_DIR=%s", runtimeDir))
	env = append(env, fmt.Sprintf("_CONTAINERS_USERNS_CONFIGURED=%s", os.Getenv("_CONTAINERS_USERNS_CONFIGURED")))
	env = append(env, fmt.Sprintf("_CONTAINERS_ROOTLESS_UID=%s", os.Getenv("_CONTAINERS_ROOTLESS_UID")))
	home := homedir.Get()
	if home != "" {
		env = append(env, fmt.Sprintf("HOME=%s", home))
	}

	return env
}

// UpdateContainerStatus updates the status of the given container.
func (r *ConmonRSOCIRuntime) UpdateContainerStatus(ctr *Container) error {
	return r.printError("UpdateContainerStatus")
}

// StartContainer starts the given container.
func (r *ConmonRSOCIRuntime) StartContainer(ctr *Container) error {
	// TODO: streams should probably *not* be our STDIN/OUT/ERR - redirect to buffers?
	runtimeDir, err := util.GetRuntimeDir()
	if err != nil {
		return err
	}
	env := []string{fmt.Sprintf("XDG_RUNTIME_DIR=%s", runtimeDir)}
	if path, ok := os.LookupEnv("PATH"); ok {
		env = append(env, fmt.Sprintf("PATH=%s", path))
	}
	if err := utils.ExecCmdWithStdStreams(os.Stdin, os.Stdout, os.Stderr, env, r.path, append(r.runtimeFlags, "start", ctr.ID())...); err != nil {
		return err
	}

	ctr.state.StartedTime = time.Now()

	return nil
}

// KillContainer sends the given signal to the given container.
// If all is set, all processes in the container will be signalled;
// otherwise, only init will be signalled.
func (r *ConmonRSOCIRuntime) KillContainer(ctr *Container, signal uint, all bool) error {
	if _, err := r.killContainer(ctr, signal, all, false); err != nil {
		return err
	}

	return nil
}

// If captureStderr is requested, OCI runtime STDERR will be captured as a
// *bytes.buffer and returned; otherwise, it is set to os.Stderr.
func (r *ConmonRSOCIRuntime) killContainer(ctr *Container, signal uint, all, captureStderr bool) (*bytes.Buffer, error) {
	logrus.Debugf("Sending signal %d to container %s", signal, ctr.ID())
	runtimeDir, err := util.GetRuntimeDir()
	if err != nil {
		return nil, err
	}
	env := []string{fmt.Sprintf("XDG_RUNTIME_DIR=%s", runtimeDir)}
	var args []string
	args = append(args, r.runtimeFlags...)
	if all {
		args = append(args, "kill", "--all", ctr.ID(), fmt.Sprintf("%d", signal))
	} else {
		args = append(args, "kill", ctr.ID(), fmt.Sprintf("%d", signal))
	}
	var (
		stderr       io.Writer = os.Stderr
		stderrBuffer *bytes.Buffer
	)
	if captureStderr {
		stderrBuffer = new(bytes.Buffer)
		stderr = stderrBuffer
	}
	if err := utils.ExecCmdWithStdStreams(os.Stdin, os.Stdout, stderr, env, r.path, args...); err != nil {
		// Update container state - there's a chance we failed because
		// the container exited in the meantime.
		if err2 := r.UpdateContainerStatus(ctr); err2 != nil {
			logrus.Infof("Error updating status for container %s: %v", ctr.ID(), err2)
		}
		if ctr.ensureState(define.ContainerStateStopped, define.ContainerStateExited) {
			return stderrBuffer, fmt.Errorf("%w: %s", define.ErrCtrStateInvalid, ctr.state.State)
		}
		return stderrBuffer, fmt.Errorf("sending signal to container %s: %w", ctr.ID(), err)
	}

	return stderrBuffer, nil
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
	logrus.Debugf("Stopping container %s (PID %d)", ctr.ID(), ctr.state.PID)

	// Ping the container to see if it's alive
	// If it's not, it's already stopped, return
	err := unix.Kill(ctr.state.PID, 0)
	if err == unix.ESRCH {
		return nil
	}

	killCtr := func(signal uint) (bool, error) {
		stderr, err := r.killContainer(ctr, signal, all, true)

		// Before handling error from KillContainer, convert STDERR to a []string
		// (one string per line of output) and print it, ignoring known OCI runtime
		// errors that we don't care about
		stderrLines := strings.Split(stderr.String(), "\n")
		for _, line := range stderrLines {
			if line == "" {
				continue
			}
			if strings.Contains(line, "container not running") || strings.Contains(line, "open pidfd: No such process") {
				logrus.Debugf("Failure to kill container (already stopped?): logged %s", line)
				continue
			}
			fmt.Fprintf(os.Stderr, "%s\n", line)
		}

		if err != nil {
			// There's an inherent race with the cleanup process (see
			// #16142, #17142). If the container has already been marked as
			// stopped or exited by the cleanup process, we can return
			// immediately.
			if errors.Is(err, define.ErrCtrStateInvalid) && ctr.ensureState(define.ContainerStateStopped, define.ContainerStateExited) {
				return true, nil
			}

			// If the PID is 0, then the container is already stopped.
			if ctr.state.PID == 0 {
				return true, nil
			}

			// Is the container gone?
			// If so, it probably died between the first check and
			// our sending the signal
			// The container is stopped, so exit cleanly
			err := unix.Kill(ctr.state.PID, 0)
			if err == unix.ESRCH {
				return true, nil
			}

			return false, err
		}
		return false, nil
	}

	if timeout > 0 {
		stopSignal := ctr.config.StopSignal
		if stopSignal == 0 {
			stopSignal = uint(syscall.SIGTERM)
		}

		stopped, err := killCtr(stopSignal)
		if err != nil {
			return err
		}
		if stopped {
			return nil
		}

		if err := waitContainerStop(ctr, time.Duration(timeout)*time.Second); err != nil {
			logrus.Debugf("Timed out stopping container %s with %s, resorting to SIGKILL: %v", ctr.ID(), unix.SignalName(syscall.Signal(stopSignal)), err)
			logrus.Warnf("StopSignal %s failed to stop container %s in %d seconds, resorting to SIGKILL", unix.SignalName(syscall.Signal(stopSignal)), ctr.Name(), timeout)
		} else {
			// No error, the container is dead
			return nil
		}
	}

	stopped, err := killCtr(uint(unix.SIGKILL))
	if err != nil {
		return fmt.Errorf("sending SIGKILL to container %s: %w", ctr.ID(), err)
	}
	if stopped {
		return nil
	}

	// Give runtime a few seconds to make it happen
	if err := waitContainerStop(ctr, killContainerTimeout); err != nil {
		return err
	}

	return nil
}

// DeleteContainer deletes the given container from the OCI runtime.
func (r *ConmonRSOCIRuntime) DeleteContainer(ctr *Container) error {
	runtimeDir, err := util.GetRuntimeDir()
	if err != nil {
		return err
	}
	env := []string{fmt.Sprintf("XDG_RUNTIME_DIR=%s", runtimeDir)}
	return utils.ExecCmdWithStdStreams(os.Stdin, os.Stdout, os.Stderr, env, r.path, append(r.runtimeFlags, "delete", "--force", ctr.ID())...)
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
	return true, nil
}

// SupportsCheckpoint returns whether this OCI runtime
// implementation supports the CheckpointContainer() operation.
func (r *ConmonRSOCIRuntime) SupportsCheckpoint() bool {
	return false
}

// SupportsJSONErrors is whether the runtime can return JSON-formatted
// error messages.
func (r *ConmonRSOCIRuntime) SupportsJSONErrors() bool {
	return r.supportsJSON
}

// SupportsNoCgroups is whether the runtime supports running containers
// without cgroups.
func (r *ConmonRSOCIRuntime) SupportsNoCgroups() bool {
	return r.supportsNoCgroups
}

// SupportsKVM os whether the OCI runtime supports running containers
// without KVM separation
func (r *ConmonRSOCIRuntime) SupportsKVM() bool {
	return r.supportsKVM
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
	if ctr == nil {
		return "", fmt.Errorf("must provide a valid container to get exit file path: %w", define.ErrInvalidArg)
	}
	return filepath.Join(r.exitsDir, ctr.ID()), nil
}

// getConmonVersion returns a string representation of the conmon version.
func (r *ConmonRSOCIRuntime) getConmonRSVersion() (string, error) {
	output, err := utils.ExecCmd(r.conmonRSPath, "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.Replace(output, "\n", ", ", 1), "\n"), nil
}

// getOCIRuntimeVersion returns a string representation of the OCI runtime's
// version.
func (r *ConmonRSOCIRuntime) getOCIRuntimeVersion() (string, error) {
	output, err := utils.ExecCmd(r.path, "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(output, "\n"), nil
}

// RuntimeInfo returns verbose information about the runtime.
func (r *ConmonRSOCIRuntime) RuntimeInfo() (*define.ConmonInfo, *define.OCIRuntimeInfo, error) {
	runtimePackage := cutil.PackageVersion(r.path)
	conmonPackage := cutil.PackageVersion(r.conmonRSPath)
	runtimeVersion, err := r.getOCIRuntimeVersion()
	if err != nil {
		return nil, nil, fmt.Errorf("getting version of OCI runtime %s: %w", r.name, err)
	}
	conmonVersion, err := r.getConmonRSVersion()
	if err != nil {
		return nil, nil, fmt.Errorf("getting conmon version: %w", err)
	}
	conmon := define.ConmonInfo{
		Package: conmonPackage,
		Path:    "conmonrs (in PATH)",
		Version: conmonVersion,
	}
	ocirt := define.OCIRuntimeInfo{
		Name:    r.name,
		Path:    "todo: path",
		Package: runtimePackage,
		Version: runtimeVersion,
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
