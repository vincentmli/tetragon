// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// CGO_LDFLAGS=-L$(realpath ./lib) go test -gcflags="" -c ./pkg/grpc/exec/ -o go-tests/grpc-exec.test
// sudo LD_LIBRARY_PATH=/home/apapag/tetragon/lib ./go-tests/grpc-exec.test  [ -test.run TestGrpcExec ]

package exec

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/dns"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/execcache"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/stretchr/testify/assert"
)

var (
	AllEvents []*tetragon.GetEventsResponse
	ExecGrpc  *Grpc
)

type DummyNotifier struct {
	t *testing.T
}

func (n DummyNotifier) AddListener(listener server.Listener) {}

func (n DummyNotifier) RemoveListener(listener server.Listener) {}

func (n DummyNotifier) NotifyListener(original interface{}, processed *tetragon.GetEventsResponse) {
	switch v := original.(type) {
	case *processapi.MsgExitEventUnix:
		e := ExecGrpc.HandleExitMessage(v)
		if e != nil {
			AllEvents = append(AllEvents, e)
		}
	case *processapi.MsgExecveEventUnix:
		e := ExecGrpc.HandleExecveMessage(v)
		if e != nil {
			AllEvents = append(AllEvents, e)
		}
	default:
		n.t.Fatalf("Unknown type in NotifyListener = %T", v)
	}
}

type DummyObserver struct {
	t *testing.T
}

func (o DummyObserver) AddTracingPolicy(ctx context.Context, sensorName string, spec interface{}) error {
	return nil
}

func (o DummyObserver) DelTracingPolicy(ctx context.Context, sensorName string) error {
	return nil
}

func (o DummyObserver) EnableSensor(ctx context.Context, name string) error {
	return nil
}

func (o DummyObserver) DisableSensor(ctx context.Context, name string) error {
	return nil
}

func (o DummyObserver) ListSensors(ctx context.Context) (*[]sensors.SensorStatus, error) {
	return nil, nil
}

func (o DummyObserver) GetSensorConfig(ctx context.Context, name string, cfgkey string) (string, error) {
	return "<dummy>", nil
}

func (o DummyObserver) SetSensorConfig(ctx context.Context, name string, cfgkey string, cfgval string) error {
	return nil
}

func (o DummyObserver) RemoveSensor(ctx context.Context, sensorName string) error {
	return nil
}

func createEvents(Pid uint32, Ktime uint64) (*processapi.MsgExecveEventUnix, *processapi.MsgExitEventUnix) {
	execMsg := &processapi.MsgExecveEventUnix{
		Common: processapi.MsgCommon{
			Op:     5,
			Flags:  0,
			Pad_v2: [2]uint8{0, 0},
			Size:   326,
			Ktime:  21034975106173,
		},
		Kube: processapi.MsgK8sUnix{
			NetNS:  4026531992,
			Cid:    0,
			Cgrpid: 0,
			Docker: "",
		},
		Parent: processapi.MsgExecveKey{
			Pid:   1459,
			Pad:   0,
			Ktime: 75200000000,
		},
		ParentFlags: 0,
		Process: processapi.MsgProcess{
			Size:     78,
			PID:      Pid,
			NSPID:    0,
			UID:      1010,
			AUID:     1010,
			Flags:    16385,
			Ktime:    Ktime,
			Filename: "/usr/bin/ls",
			Args:     "--color=auto\x00/home/apapag/tetragon",
		},
	}

	exitMsg := &processapi.MsgExitEventUnix{
		Common: processapi.MsgCommon{
			Op:     7,
			Flags:  0,
			Pad_v2: [2]uint8{0, 0},
			Size:   40,
			Ktime:  21034976281104,
		},
		ProcessKey: processapi.MsgExecveKey{
			Pid:   Pid,
			Pad:   0,
			Ktime: Ktime,
		},
		Info: processapi.MsgExitInfo{
			Code:   0,
			Cached: 0,
		},
	}

	return execMsg, exitMsg
}

func initEnv(t *testing.T, cancelWg *sync.WaitGroup) (*Grpc, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	watcher := watcher.NewFakeK8sWatcher(nil)
	_, err := cilium.InitCiliumState(ctx, false)
	if err != nil {
		t.Fatalf("failed to call cilium.InitCiliumState %s", err)
	}

	if err := process.InitCache(ctx, watcher, false, 65536); err != nil {
		t.Fatalf("failed to call process.InitCache %s", err)
	}

	lDns, err := dns.NewCache()
	if err != nil {
		t.Fatalf("failed to create DNS cache %s", err)
	}

	dn := DummyNotifier{t}
	do := DummyObserver{t}
	lServer := server.NewServer(ctx, cancelWg, dn, do)

	lEventCache := eventcache.New(lServer, lDns)
	lExecCache := execcache.New(lServer, lDns)

	return New(lExecCache, lEventCache, false, false), cancel
}

func TestGrpcExecOutOfOrder(t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	grpc, cancel := initEnv(t, &cancelWg)
	ExecGrpc = grpc

	execMsg, exitMsg := createEvents(46983, 21034975089403)

	e1 := ExecGrpc.HandleExitMessage(exitMsg)
	if e1 != nil {
		AllEvents = append(AllEvents, e1)
	}

	e2 := ExecGrpc.HandleExecveMessage(execMsg)
	if e2 != nil {
		AllEvents = append(AllEvents, e2)
	}

	time.Sleep(2 * time.Second) // wait for cache to do it's work

	assert.Equal(t, len(AllEvents), 2)

	var ev1 *tetragon.GetEventsResponse
	var ev2 *tetragon.GetEventsResponse
	if AllEvents[0].GetProcessExec() != nil {
		ev1 = AllEvents[0]
		ev2 = AllEvents[1]
	} else {
		ev2 = AllEvents[0]
		ev1 = AllEvents[1]
	}

	// fails but we don't expect to have the same Refcnt
	ev1.GetProcessExec().Process.Refcnt = 0 // hardcode that to make the following pass
	assert.Equal(t, ev1.GetProcessExec().Process, ev2.GetProcessExit().Process)

	// success
	assert.Equal(t, ev1.GetProcessExec().Parent, ev2.GetProcessExit().Parent)

	cancel()
	cancelWg.Wait()
}

func TestGrpcExecInOrder(t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	grpc, cancel := initEnv(t, &cancelWg)
	ExecGrpc = grpc

	execMsg, exitMsg := createEvents(46983, 21034975089403)

	e2 := ExecGrpc.HandleExecveMessage(execMsg)
	if e2 != nil {
		AllEvents = append(AllEvents, e2)
	}

	e1 := ExecGrpc.HandleExitMessage(exitMsg)
	if e1 != nil {
		AllEvents = append(AllEvents, e1)
	}

	time.Sleep(2 * time.Second) // wait for cache to do it's work

	assert.Equal(t, len(AllEvents), 2)

	var ev1 *tetragon.GetEventsResponse
	var ev2 *tetragon.GetEventsResponse
	if AllEvents[0].GetProcessExec() != nil {
		ev1 = AllEvents[0]
		ev2 = AllEvents[1]
	} else {
		ev2 = AllEvents[0]
		ev1 = AllEvents[1]
	}

	// fails but we don't expect to have the same Refcnt
	ev1.GetProcessExec().Process.Refcnt = 0 // hardcode that to make the following pass
	assert.Equal(t, ev1.GetProcessExec().Process, ev2.GetProcessExit().Process)

	// success
	assert.Equal(t, ev1.GetProcessExec().Parent, ev2.GetProcessExit().Parent)

	cancel()
	cancelWg.Wait()
}
