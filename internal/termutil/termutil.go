// Package termutil provides terminal helpers for interactive prompts.
package termutil

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Prompt prints prompt to stderr and reads one line from stdin (echo on).
func Prompt(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// Password prints prompt to stderr and reads one line from stdin with
// terminal echo disabled. Requires a TTY on
// stdin; falls back to a plain read when stdin is not a terminal.
func Password(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if !isTerminal(os.Stdin.Fd()) {
		// Not a TTY (piped stdin): read plainly, still strip the newline.
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", err
	}
	newState := *old
	newState.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &newState); err != nil {
		return "", err
	}
	defer func() {
		unix.IoctlSetTermios(fd, unix.TCSETS, old)
		fmt.Fprintln(os.Stderr)
	}()
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}
