// This init is only for the disposable, networkless SDK test VM.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/peios/peios-go/file"
)

func main() {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "vm-init must be PID 1 in the test guest")
		os.Exit(2)
	}
	for _, m := range [][2]string{{"/proc", "proc"}, {"/sys", "sysfs"}, {"/dev", "devtmpfs"}, {"/tmp", "tmpfs"}} {
		os.MkdirAll(m[0], 0755)
		if e := syscall.Mount(m[1], m[0], m[1], 0, ""); e != nil {
			fmt.Println("mount", m, e)
		}
	}
	os.MkdirAll("/sys/kernel/security", 0755)
	if e := syscall.Mount("securityfs", "/sys/kernel/security", "securityfs", 0, ""); e != nil {
		fmt.Println("securityfs", e)
	}
	// securityfs is unclassified by FACS on this bare initramfs. Give only
	// this disposable mount its normal ephemeral descriptor policy.
	if fd, e := syscall.Open("/sys/kernel/security", 0x200000|syscall.O_CLOEXEC, 0); e != nil {
		fmt.Println("securityfs handle", e)
	} else {
		f := os.NewFile(uintptr(fd), "securityfs")
		e = file.SetMountPolicy(f, file.MountPolicy{Policy: 3})
		f.Close()
		if e != nil {
			fmt.Println("securityfs policy", e)
		}
	}
	c := exec.Command("/probe.test", "-test.v", "-test.timeout=60s")
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Env = []string{"PEIOS_NATIVE_TEST=1", "PEIOS_C_ORACLE=/c-oracle", "PEIOS_RUST_ORACLE=/rust-oracle", "LD_LIBRARY_PATH=/lib", "PATH=/", "TMPDIR=/tmp", "GOMAXPROCS=2"}
	if e := c.Run(); e != nil {
		fmt.Println("PEIOS_GO_NATIVE_FAIL", e)
	} else {
		fmt.Println("PEIOS_GO_NATIVE_PASS")
	}
	syscall.Sync()
	syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}
