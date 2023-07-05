package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/containers/conmon-rs/internal/proto"
)

// RemoteFd represents a file descriptor on the server, identified by a slot number.
type RemoteFd uint64

func (r RemoteFd) String() string {
	return fmt.Sprintf("RemoteFd(%d)", r)
}

// NewRemoteFds can be used to send file descriptors to the server.
type RemoteFds struct {
	conn  *net.UnixConn
	reqId uint64
}

// NewRemoteFds connects to the fd socket at `path`.
func NewRemoteFds(path string) (*RemoteFds, error) {
	conn, err := DialLongSocket("unixpacket", path)
	if err != nil {
		return nil, fmt.Errorf("dial long socket: %w", err)
	}
	return &RemoteFds{
		conn: conn,
	}, nil
}

// Send file descriptors to the server.
func (r *RemoteFds) Send(fds ...int) ([]RemoteFd, error) {
	if len(fds) > 253 {
		return nil, fmt.Errorf("too many file descriptors")
	}

	r.reqId += 1
	id := r.reqId
	idAndNumFds := id<<8 | uint64(len(fds))
	b := binary.LittleEndian.AppendUint64(nil, idAndNumFds)
	oob := syscall.UnixRights(fds...)
	_, _, err := r.conn.WriteMsgUnix(b, oob, nil)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := r.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	buf = buf[:n]

	if len(buf) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	resIdAndNumFds := binary.LittleEndian.Uint64(buf[:8])
	buf = buf[8:]

	if resIdAndNumFds>>8 != id {
		return nil, fmt.Errorf("response id does not match: %d (expected %d)", resIdAndNumFds>>8, id)
	}

	numFds := int(resIdAndNumFds & 0xff)
	if numFds == 0xff {
		return nil, fmt.Errorf("server error: %s", string(buf))
	}

	if numFds != len(fds) {
		return nil, fmt.Errorf("number of fds does not match: %d (expected %d)", numFds, len(fds))
	}

	if len(buf) != numFds*8 {
		return nil, fmt.Errorf("invalid response length")
	}

	slots := make([]RemoteFd, 0, numFds)
	for i := 0; i < numFds; i++ {
		slots = append(slots, RemoteFd(binary.LittleEndian.Uint64(buf[i*8:])))
	}
	return slots, nil
}

// Close the connection and unused remote file descriptors.
func (r *RemoteFds) Close() error {
	return r.conn.Close()
}

// RemoteFds can be used start and connect to the remote fd socket.
func (c *ConmonClient) RemoteFds(ctx context.Context) (*RemoteFds, error) {
	ctx, span := c.startSpan(ctx, "AttachContainer")
	if span != nil {
		defer span.End()
	}

	conn, err := c.newRPCConn()
	if err != nil {
		return nil, fmt.Errorf("create RPC connection: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			c.logger.Errorf("Unable to close connection: %v", err)
		}
	}()

	client := proto.Conmon(conn.Bootstrap(ctx))

	future, free := client.StartFdSocket(ctx, func(p proto.Conmon_startFdSocket_Params) error {
		req, err := p.NewRequest()
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}

		metadata, err := c.metadataBytes(ctx)
		if err != nil {
			return fmt.Errorf("get metadata: %w", err)
		}
		if err := req.SetMetadata(metadata); err != nil {
			return fmt.Errorf("set metadata: %w", err)
		}

		return nil
	})
	defer free()

	result, err := future.Struct()
	if err != nil {
		return nil, fmt.Errorf("create result: %w", err)
	}

	res, err := result.Response()
	if err != nil {
		return nil, fmt.Errorf("get response: %w", err)
	}

	path, err := res.Path()
	if err != nil {
		return nil, fmt.Errorf("get path: %w", err)
	}

	r, err := NewRemoteFds(path)
	if err != nil {
		return nil, fmt.Errorf("connect to remote fd socket: %w", err)
	}

	return r, nil
}
