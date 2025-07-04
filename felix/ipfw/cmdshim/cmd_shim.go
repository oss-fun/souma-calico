//go:build freebsd

package cmdshim

import (
	"fmt"
	"io"
	"os/exec"
)

var ADD_COMMAND = []string{"ipfw", "add"}

type CmdIface interface {
	SetStdin(io.Reader)
	SetStdout(io.Writer)
	SetStderr(io.Writer)
	Run() error
	Start() error
	Kill() error
	Wait() error
	Output() ([]byte, error)
	StdoutPipe() (io.ReadCloser, error)
	String() string
}

type CmdFactory func(name string, arg ...string) CmdIface

func NewRealCmd(name string, arg ...string) CmdIface {
	cmd := exec.Command(name, arg...)
	return (*cmdAdapter)(cmd)
}

type cmdAdapter exec.Cmd

func (c *cmdAdapter) SetStdin(r io.Reader) {
	c.Stdin = r
}

func (c *cmdAdapter) SetStdout(w io.Writer) {
	c.Stdout = w
}

func (c *cmdAdapter) SetStderr(w io.Writer) {
	c.Stderr = w
}

func (c *cmdAdapter) Run() error {
	return (*exec.Cmd)(c).Run()
}

func (c *cmdAdapter) Start() error {
	return (*exec.Cmd)(c).Start()
}

func (c *cmdAdapter) Kill() error {
	return (*exec.Cmd)(c).Process.Kill()
}

func (c *cmdAdapter) Wait() error {
	return (*exec.Cmd)(c).Wait()
}

func (c *cmdAdapter) Output() ([]byte, error) {
	return (*exec.Cmd)(c).Output()
}

func (c *cmdAdapter) StdoutPipe() (io.ReadCloser, error) {
	return (*exec.Cmd)(c).StdoutPipe()
}

func (c *cmdAdapter) String() string {
	return fmt.Sprintf("%v", (*exec.Cmd)(c))
}
