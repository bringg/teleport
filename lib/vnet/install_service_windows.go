// Teleport
// Copyright (C) 2025 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package vnet

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/gravitational/teleport/lib/windowsexec"
)

// InstallService installs the VNet windows service.
func InstallService(ctx context.Context) (err error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return trace.Wrap(installServiceInElevatedChild(ctx),
			"elevating process to install VNet Windows service")
	}

	defer func() {
		msg := "connected to service manager"
		if err != nil {
			msg = err.Error()
		}
		os.WriteFile(`C:\Temp\installdump.exe`, []byte(msg), 0)
	}()

	svcMgr, err := mgr.Connect()
	if err != nil {
		return trace.Wrap(err, "connecting to Windows service manager")
	}
	fmt.Println("succesfully connected to Windows service manager", svcMgr)
	return nil
}

// installServiceInElevatedChild uses `runas` to trigger a child process
// with elevated privileges. This is necessary in order to install the service
// with the service control manager.
func installServiceInElevatedChild(ctx context.Context) error {
	exe, err := os.Executable()
	if err != nil {
		return trace.Wrap(err, "determining current executable path")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return trace.Wrap(err, "determining current working directory")
	}
	return trace.Wrap(windowsexec.RunAsAndWait(exe, cwd, time.Second*10, os.Args),
		"invoking ShellExecute")
}
