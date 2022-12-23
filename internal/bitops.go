package internal

// structure definitions and bit logic have been modified based
// https://github.com/syndtr/gocapability. Retain this license
// if the code is used as-is or in modified form.

// Copyright 2013 Suryandaru Triandana <syndtr@gmail.com>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import (
	"golang.org/x/sys/unix"
)

// CapabilityV1 is the Capability structure for LINUX_CAPABILITY_VERSION_1
type CapabilityV1 struct {
	Header unix.CapUserHeader
	Data   unix.CapUserData
}

// CapabilityV3 is the Capability structure for LINUX_CAPABILITY_VERSION_2
// or LINUX_CAPABILITY_VERSION_3. See
// See also
// https://git.kernel.org/pub/scm/linux/kernel/git/morgan/libcap.git/tree/libcap/libcap.h#n115
// indicating datap[0] and datap[1] for 64 bit capabilities.
type CapabilityV3 struct {
	Header  unix.CapUserHeader
	Datap   [2]unix.CapUserData
	Bounds  [2]uint32
	Ambient [2]uint32
}

func (v1 *CapabilityV1) IsEffectiveSet(capability int) bool {
	return (1<<uint(capability))&v1.Data.Effective != 0
}

func (v1 *CapabilityV1) IsPermittedSet(capability int) bool {
	return (1<<uint(capability))&v1.Data.Permitted != 0
}

func (v1 *CapabilityV1) IsInheritableSet(capability int) bool {
	return (1<<uint(capability))&v1.Data.Inheritable != 0
}

func (v3 *CapabilityV3) IsEffectiveSet(capability int) bool {
	var i uint
	bitIndex := capability
	if bitIndex > 31 {
		i = 1
		bitIndex %= 32
	}
	return (1<<uint(bitIndex))&v3.Datap[i].Effective != 0
}

func (v3 *CapabilityV3) IsPermittedSet(capability int) bool {
	var i uint
	bitIndex := capability
	if bitIndex > 31 {
		i = 1
		bitIndex %= 32
	}
	return (1<<uint(bitIndex))&v3.Datap[i].Permitted != 0
}

func (v3 *CapabilityV3) IsInheritableSet(capability int) bool {
	var i uint
	bitIndex := capability
	if bitIndex > 31 {
		i = 1
		bitIndex %= 32
	}
	return (1<<uint(bitIndex))&v3.Datap[i].Inheritable != 0
}

func (v3 *CapabilityV3) IsBoundingSet(capability int) bool {
	var i uint
	bitIndex := capability
	if bitIndex > 31 {
		i = 1
		bitIndex %= 32
	}
	return (1<<uint(bitIndex))&v3.Bounds[i] != 0
}

func (v3 *CapabilityV3) IsAmbientSet(capability int) bool {
	var i uint
	bitIndex := capability
	if bitIndex > 31 {
		i = 1
		bitIndex %= 32
	}
	return (1<<uint(bitIndex))&v3.Ambient[i] != 0
}
