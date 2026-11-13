/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func init() {
	controlFns = append(controlFns,
		func(network, address string, c syscall.RawConn) error {
			var socketErr error
			if err := c.Control(func(fd uintptr) {
				socketErr = tuneWindowsSocket(windows.Handle(fd))
			}); err != nil {
				return err
			}
			return socketErr
		},
	)
}
