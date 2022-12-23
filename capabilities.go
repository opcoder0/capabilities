package capabilities

import (
	"errors"
	"os"

	"github.com/opcoder0/capabilities/internal"
	"golang.org/x/sys/unix"
)

// CapabilitySet holds one of the 4 capability set types
type CapabilitySet int

const (
	// Effective is the set of capabilities used by the kernel to perform permission checks for the thread.
	Effective CapabilitySet = 0
	// Permitted is the limiting superset for the effective capabilities that the thread may assume.
	Permitted CapabilitySet = 1
	// Inheritable is the set of capabilities preserved across an execve(2). Inheritable capabilities
	// remain inheritable when executing any program, and inheritable capabilities are added to the
	// permitted set when executing a program that has the corresponding bits set in the file
	// inheritable set.
	Inheritable CapabilitySet = 2
	// Bounding is a mechanism that can be used to limit the capabilities that are gained during execve(2).
	Bounding CapabilitySet = 3
	// Ambient set of capabilities that are preserved across an execve(2) of a program that is not privileged.
	// The ambient capability set obeys the invariant that no capability can ever be ambient if it is not
	// both permitted and inheritable.
	Ambient CapabilitySet = 4
)

// Capabilities holds the capabilities header and data
type Capabilities struct {
	v3 internal.CapabilityV3
	v1 internal.CapabilityV1
	// Version has values 1, 2 or 3 depending on the kernel version.
	// Prior to 2.6.25 value is set to 1.
	// For Linux 2.6.25 added 64-bit capability sets the value is set to 2.
	// For Linux 2.6.26 and later the value is set to 3.
	Version int
}

// Init sets a capability state pointer to the initial capability state.
// The call probes the kernel to determine the capabilities version. After
// Init Capability.Version is set.
// The initial value of all flags are cleared. The Capabilities value can be
// used to get or set capabilities.
func Init() (*Capabilities, error) {
	var header unix.CapUserHeader
	var capability Capabilities
	err := unix.Capget(&header, nil)
	if err != nil {
		return nil, errors.New("unable to probe capability version")
	}
	switch header.Version {
	case unix.LINUX_CAPABILITY_VERSION_1:
		capability.Version = 1
		capability.v1.Header = header
	case unix.LINUX_CAPABILITY_VERSION_2:
		capability.Version = 2
		capability.v3.Header = header
	case unix.LINUX_CAPABILITY_VERSION_3:
		capability.Version = 3
		capability.v3.Header = header
	default:
		panic("Unsupported Linux capability version")
	}
	return &capability, nil
}

// IsSet returns true if the capability from the capability list
// (unix.CAP_*) is set for the pid in the capSet CapabilitySet.
// Returns false with nil error if the capability is not set.
// Returns false with an error if there was an error getting capability.
func (c *Capabilities) IsSet(pid, capability int, capSet CapabilitySet) (bool, error) {
	return c.isSetFor(os.Getpid(), capability, capSet)
}

func (c *Capabilities) isSetFor(pid, capability int, capSet CapabilitySet) (bool, error) {
	if c.Version < 1 || c.Version > 3 {
		return false, errors.New("invalid capability version")
	}
	if c.Version == 1 {
		c.v1.Header.Version = unix.LINUX_CAPABILITY_VERSION_1
		c.v1.Header.Pid = int32(pid)
		err := unix.Capget(&c.v1.Header, &c.v1.Data)
		if err != nil {
			return false, err
		}
		switch capSet {
		case Effective:
			return c.v1.IsEffectiveSet(capability), nil
		case Inheritable:
			return c.v1.IsInheritableSet(capability), nil
		case Permitted:
			return c.v1.IsPermittedSet(capability), nil
		default:
			return false, errors.New("invalid capability set for capability v1")
		}
	}
	if c.Version == 2 {
		c.v3.Header.Version = unix.LINUX_CAPABILITY_VERSION_2
	} else if c.Version == 3 {
		c.v3.Header.Version = unix.LINUX_CAPABILITY_VERSION_3
	}
	c.v3.Header.Pid = int32(pid)
	err := unix.Capget(&c.v3.Header, &c.v3.Datap[0])
	if err != nil {
		return false, err
	}
	switch capSet {
	case Effective:
		return c.v3.IsEffectiveSet(capability), nil
	case Permitted:
		return c.v3.IsPermittedSet(capability), nil
	case Inheritable:
		return c.v3.IsInheritableSet(capability), nil
	case Bounding:
		return c.v3.IsBoundingSet(capability), nil
	case Ambient:
		return c.v3.IsAmbientSet(capability), nil
	default:
		return false, errors.New("invalid capability set for capability v2 or v3")
	}
}
