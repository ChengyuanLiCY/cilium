// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probe

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type probeKey struct {
	Prefixlen uint32
	Key       uint32
}

type probeValue struct {
	Value uint32
}

var (
	haveFullLPMOnce sync.Once
	haveFullLPM     bool

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "probe")
)

func (p *probeKey) String() string             { return fmt.Sprintf("key=%d", p.Key) }
func (p *probeKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(p) }
func (p *probeKey) NewValue() bpf.MapValue     { return &probeValue{} }
func (p *probeKey) DeepCopyMapKey() bpf.MapKey { return &probeKey{p.Prefixlen, p.Key} }

func (p *probeValue) String() string                 { return fmt.Sprintf("value=%d", p.Value) }
func (p *probeValue) GetValuePtr() unsafe.Pointer    { return unsafe.Pointer(p) }
func (p *probeValue) DeepCopyMapValue() bpf.MapValue { return &probeValue{p.Value} }

// HaveFullLPM tests whether kernel supports fully functioning BPF LPM map
// with proper bpf.GetNextKey() traversal. Needs 4.16 or higher.
func HaveFullLPM() bool {
	haveFullLPMOnce.Do(func() {
		m := bpf.NewMap("cilium_test", bpf.MapTypeLPMTrie,
			&probeKey{}, int(unsafe.Sizeof(probeKey{})),
			&probeValue{}, int(unsafe.Sizeof(probeValue{})),
			1, bpf.BPF_F_NO_PREALLOC, 0, bpf.ConvertKeyValue).WithCache()
		err := m.CreateUnpinned()
		defer m.Close()
		if err != nil {
			return
		}
		err = bpf.UpdateElement(m.GetFd(), m.Name(), unsafe.Pointer(&probeKey{}),
			unsafe.Pointer(&probeValue{}), bpf.BPF_ANY)
		if err != nil {
			return
		}
		err = bpf.GetNextKey(m.GetFd(), nil, unsafe.Pointer(&probeKey{}))
		if err != nil {
			return
		}

		haveFullLPM = true
	})

	return haveFullLPM
}

// HaveIPv6Support tests whether kernel can open an IPv6 socket. This will
// also implicitly auto-load IPv6 kernel module if available and not yet
// loaded.
func HaveIPv6Support() bool {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) {
		return false
	}
	unix.Close(fd)
	return true
}

// HaveSourceOuterIPSupport tests whether the kernel support setting the outer
// source IP address via the bpf_skb_set_tunnel_key BPF helper. We can't rely
// on the verifier to reject a program using the new support because the
// verifier just accepts any argument size for that helper; non-supported
// fields will simply not be used. Instead, we set the outer source IP and
// retrieve it with bpf_skb_get_tunnel_key right after. If the retrieved value
// equals the value set, we have a confirmation the kernel supports it.
func HaveOuterSourceIPSupport() (bool, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return false, err
	}

	progSpec := &ebpf.ProgramSpec{
		Name:    "set_tunnel_key_probe",
		Type:    ebpf.SchedACT,
		License: "GPL",
	}
	progSpec.Instructions = asm.Instructions{
		asm.Mov.Reg(asm.R8, asm.R1),

		asm.Mov.Imm(asm.R2, 0),
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, -24, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, -32, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, -40, asm.R2, asm.DWord),
		asm.Mov.Imm(asm.R2, 42),
		asm.StoreMem(asm.RFP, -44, asm.R2, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -44),
		asm.Mov.Imm(asm.R3, 44), // sizeof(struct bpf_tunnel_key) when setting the outer source IP is supported.
		asm.Mov.Imm(asm.R4, 0),
		asm.FnSkbSetTunnelKey.Call(),

		asm.Mov.Reg(asm.R1, asm.R8),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -44),
		asm.Mov.Imm(asm.R3, 44),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnSkbGetTunnelKey.Call(),

		asm.LoadMem(asm.R0, asm.RFP, -44, asm.Word),
		asm.Return(),
	}
	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		return false, err
	}
	defer prog.Close()

	pkt := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ret, _, err := prog.Test(pkt)
	return ret == 42, err
}
