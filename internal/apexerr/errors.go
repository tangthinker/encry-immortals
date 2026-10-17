// Package apexerr defines apex's stable error codes, their process exit codes
// and the single error type carried across package boundaries.
//
// Spec: docs/spec/10-cli-and-config.md §10.5 (exit codes) and §10.7 (message
// format). The code -> exit mapping is a stable contract: codes may be added,
// existing meanings must never change.
package apexerr

import (
	"errors"
	"fmt"
	"strings"
)

// Code is the human-facing, stable error identifier (E1, E10, ...).
type Code string

const (
	CodeInternal    Code = "E1"
	CodeUsage       Code = "E2"
	CodeUnlock      Code = "E10"
	CodeChain       Code = "E11"
	CodeCorrupt     Code = "E12"
	CodeIncomplete  Code = "E13"
	CodeNoSpace     Code = "E14"
	CodeArmor       Code = "E16"
	CodeLocked      Code = "E20"
	CodeUnsupported Code = "E21"
	CodeInterrupted Code = "E130"
)

// Process exit codes (spec §10.5).
const (
	ExitOK          = 0
	ExitInternal    = 1
	ExitUsage       = 2
	ExitUnlock      = 10
	ExitChain       = 11
	ExitCorrupt     = 12
	ExitIncomplete  = 13
	ExitNoSpace     = 14
	ExitLocked      = 20
	ExitUnsupported = 21
	ExitInterrupted = 130
)

var codeExit = map[Code]int{
	CodeInternal:    ExitInternal,
	CodeUsage:       ExitUsage,
	CodeUnlock:      ExitUnlock,
	CodeChain:       ExitChain,
	CodeCorrupt:     ExitCorrupt,
	CodeIncomplete:  ExitIncomplete,
	CodeNoSpace:     ExitNoSpace,
	CodeArmor:       ExitCorrupt, // ADR-006: E16 reuses the "corrupt/illegal format" exit code.
	CodeLocked:      ExitLocked,
	CodeUnsupported: ExitUnsupported,
	CodeInterrupted: ExitInterrupted,
}

// ExitFor reports the process exit code bound to c.
func ExitFor(c Code) int {
	if v, ok := codeExit[c]; ok {
		return v
	}
	return ExitInternal
}

// Error is the only error type apex produces at package boundaries.
//
// Message shape (spec §10.7): "<code> <what>。影响：<scope>。建议：<next>（<cause>）"
// with every optional part omitted when empty.
type Error struct {
	Code  Code
	Exit  int
	What  string // what happened
	Scope string // what it affects
	Next  string // one directly executable next step
	Err   error  // underlying cause, if any
}

// New builds an error with the exit code bound to code.
func New(code Code, what string) *Error {
	return &Error{Code: code, Exit: ExitFor(code), What: what}
}

// Newf is New with formatting.
func Newf(code Code, format string, args ...any) *Error {
	return New(code, fmt.Sprintf(format, args...))
}

// Wrap attaches a cause to a new error.
func Wrap(err error, code Code, what string) *Error {
	e := New(code, what)
	e.Err = err
	return e
}

// Wrapf is Wrap with formatting.
func Wrapf(err error, code Code, format string, args ...any) *Error {
	return Wrap(err, code, fmt.Sprintf(format, args...))
}

// WithScope returns a copy carrying the "影响" clause.
func (e *Error) WithScope(scope string) *Error { c := *e; c.Scope = scope; return &c }

// WithNext returns a copy carrying the "建议" clause.
func (e *Error) WithNext(next string) *Error { c := *e; c.Next = next; return &c }

// WithErr returns a copy carrying an underlying cause.
func (e *Error) WithErr(err error) *Error { c := *e; c.Err = err; return &c }

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(string(e.Code))
	b.WriteByte(' ')
	b.WriteString(trimStop(e.What))
	if e.Scope != "" {
		b.WriteString("。影响：")
		b.WriteString(trimStop(e.Scope))
	}
	if e.Next != "" {
		b.WriteString("。建议：")
		b.WriteString(trimStop(e.Next))
	}
	if e.Err != nil {
		b.WriteString("（")
		b.WriteString(e.Err.Error())
		b.WriteString("）")
	}
	return b.String()
}

// Unwrap exposes the cause for errors.Is / errors.As.
func (e *Error) Unwrap() error { return e.Err }

func trimStop(s string) string {
	return strings.TrimRight(s, "。 \t\n")
}

// As returns the *Error behind err, if any.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// CodeOf reports the error code behind err; unknown errors are E1.
func CodeOf(err error) Code {
	if err == nil {
		return ""
	}
	if e, ok := As(err); ok {
		return e.Code
	}
	return CodeInternal
}

// ExitCode maps any error to a process exit code. nil is 0, unknown errors are 1.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	if e, ok := As(err); ok {
		return e.Exit
	}
	return ExitInternal
}

// From converts any error into an *Error without losing the cause.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	if e, ok := As(err); ok {
		return e
	}
	return Wrap(err, CodeInternal, "未分类错误")
}
