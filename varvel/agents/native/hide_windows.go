//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// hideWindow keeps a spawned child console-less (the sim agent's windowsHide:true).
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
