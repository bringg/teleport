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
	"io"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/gravitational/teleport/lib/windowsexec"
)

// InstallService installs the VNet windows service.
func InstallService(ctx context.Context, username, logFile string) (err error) {
	// If not already running with elevated permissions, exec a child process of
	// the current executable with the current args with `runas`.
	if !windows.GetCurrentProcessToken().IsElevated() {
		return trace.Wrap(installServiceInElevatedChild(ctx, username),
			"elevating process to install VNet Windows service")
	}

	if logFile == "" {
		return trace.BadParameter("log-file is required")
	}
	defer func() {
		// Write any errors to logFile so the parent process can read it.
		if err != nil {
			// Not really any point checking the error from WriteFile since
			// noone will be able to read it.
			os.WriteFile(logFile, []byte(err.Error()), 0)
		}
	}()

	if username == "" {
		return trace.BadParameter("username is required")
	}
	u, err := user.Lookup(username)
	if err != nil {
		return trace.Wrap(err, "looking up user %s", username)
	}

	currentTshPath, err := os.Executable()
	if err != nil {
		return trace.Wrap(err, "getting current exe path")
	}
	currentWintunPath, err := wintunPath(currentTshPath)
	if err != nil {
		return trace.Wrap(err, "getting current wintun.dll path")
	}

	svcMgr, err := mgr.Connect()
	if err != nil {
		return trace.Wrap(err, "connecting to Windows service manager")
	}

	serviceName := "TeleportVNet-" + username
	serviceInstallDir := filepath.Join("C:", "Program Files", serviceName)
	targetTshPath := filepath.Join(serviceInstallDir, "tsh.exe")
	targetWintunPath := filepath.Join(serviceInstallDir, "wintun.dll")
	if err := os.Mkdir(serviceInstallDir, 0600); err != nil {
		return trace.Wrap(err, "creating service installation directory %s", serviceInstallDir)
	}
	if err := copyFile(targetTshPath, currentTshPath); err != nil {
		return trace.Wrap(err, "copying tsh.exe to service installation directory")
	}
	if err := copyFile(targetWintunPath, currentWintunPath); err != nil {
		return trace.Wrap(err, "copying wintun.dll to service installation directory")
	}

	if _, err := svcMgr.CreateService(serviceName, targetTshPath, mgr.Config{
		StartType: mgr.StartManual,
	}); err != nil {
		return trace.Wrap(err, "creating VNet Windows service")
	}
	// Uid is documented to be the user's SID on Windows.
	userSID := u.Uid
	if err := grantServiceRights(serviceName, userSID); err != nil {
		return trace.Wrap(err, "granting %s permissions to control the VNet Windows service", username)
	}
	return nil
}

func grantServiceRights(serviceName, userSID string) error {
	// Get the current security info for the service, requesting only the DACL
	// (discretionary access control list).
	si, err := windows.GetNamedSecurityInfo(serviceName, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return trace.Wrap(err, "getting current service security information")
	}
	// Get the DACL from the security info.
	dacl, _ /*defaulted*/, err := si.DACL()
	if err != nil {
		return trace.Wrap(err, "getting current service DACL")
	}
	// Build an explicit access entry allowing our user to start, stop, and
	// query the service.
	ea := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.SERVICE_QUERY_STATUS | windows.SERVICE_START | windows.SERVICE_STOP,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromString(userSID),
		},
	}}
	// Merge the new explicit access entry with the existing DACL.
	dacl, err = windows.ACLFromEntries(ea, dacl)
	if err != nil {
		return trace.Wrap(err, "merging service DACL entries")
	}
	// Set the DACL on the service security info.
	if err := windows.SetNamedSecurityInfo(
		serviceName,
		windows.SE_SERVICE,
		windows.DACL_SECURITY_INFORMATION,
		nil,  // owner
		nil,  // group
		dacl, // dacl
		nil,  // sacl
	); err != nil {
		return trace.Wrap(err, "setting service DACL")
	}
	return nil
}

func wintunPath(tshPath string) (string, error) {
	dir := filepath.Dir(tshPath)
	wintunPath := filepath.Join(dir, "wintun.dll")
	if _, err := os.Stat(wintunPath); err != nil {
		if os.IsNotExist(err) {
			return "", trace.Wrap(err, "wintun.dll not found")
		} else {
			return "", trace.Wrap(err, "checking for existence of wintun.dll")
		}
	}
	return wintunPath, nil
}

func copyFile(dstPath, srcPath string) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return trace.Wrap(err, "opening %s for reading", srcPath)
	}
	defer srcFile.Close()
	dstFile, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return trace.Wrap(err, "opening %s for writing", dstPath)
	}
	defer dstFile.Close()
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return trace.Wrap(err, "copying %s to %s", srcPath, dstPath)
	}
	return nil
}

// installServiceInElevatedChild uses `runas` to trigger a child process
// with elevated privileges. This is necessary in order to install the service
// with the service control manager.
func installServiceInElevatedChild(ctx context.Context, username string) error {
	if username == "" {
		u, err := user.Current()
		if err != nil {
			return trace.Wrap(err, "looking up current user")
		}
		username = u.Username
	}
	exe, err := os.Executable()
	if err != nil {
		return trace.Wrap(err, "determining current executable path")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return trace.Wrap(err, "determining current working directory")
	}
	f, err := os.CreateTemp("", "vnet-install-log")
	if err != nil {
		return trace.Wrap(err, "creating log file for VNet Windows service installation")
	}
	defer f.Close()
	args := append(os.Args[1:],
		"--username", username,
		"--log-file", f.Name())
	if err := windowsexec.RunAsAndWait(exe, cwd, time.Second*10, args); err != nil {
		err = trace.Wrap(err, "installing VNet Windows service in elevated process")
		output, readOutputErr := io.ReadAll(io.LimitReader(f, 1024))
		if readOutputErr != nil {
			return trace.NewAggregate(err, trace.Wrap(readOutputErr, "reading elevated process log"))
		}
		return trace.NewAggregate(err, fmt.Errorf("elevated process log: %s", string(output)))
	}
	return nil
}
