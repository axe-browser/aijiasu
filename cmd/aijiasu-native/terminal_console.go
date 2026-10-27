package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

type consolePasswordKey struct {
	character uint16
	repeats   uint16
}

type passwordConsole interface {
	hideInput() (restore func() error, err error)
	readKeys(context.Context) ([]consolePasswordKey, error)
	flushInput() error
	Close() error
}

func readConsolePassword(ctx context.Context, console passwordConsole) (password []byte, resultErr error) {
	defer func() {
		if err := console.Close(); err != nil {
			clear(password)
			password = nil
			resultErr = errors.Join(resultErr, fmt.Errorf("close password console: %w", err))
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	restore, err := console.hideInput()
	if err != nil {
		return nil, fmt.Errorf("disable console echo: %w", err)
	}
	defer func() {
		flushErr := console.flushInput()
		restoreErr := restore()
		if flushErr != nil || restoreErr != nil {
			clear(password)
			password = nil
			resultErr = errors.Join(resultErr, errTerminalRestore, flushErr, restoreErr)
		}
	}()
	input := make([]byte, 0, maxPasswordBytes)
	var high uint16
	oversize := false
	defer func() {
		if resultErr != nil {
			clear(input)
		}
	}()
	appendRune := func(character rune) {
		if oversize {
			return
		}
		if len(input)+utf8.RuneLen(character) > maxPasswordBytes {
			clear(input)
			input = input[:0]
			oversize = true
			return
		}
		input = utf8.AppendRune(input, character)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		keys, err := console.readKeys(ctx)
		if err != nil {
			clear(keys)
			return nil, fmt.Errorf("read password console: %w", err)
		}
		if err := ctx.Err(); err != nil {
			clear(keys)
			return nil, err
		}
		// Clear the event copy even when an Enter/EOF returns mid-batch.
		finished, readErr := func() (bool, error) {
			defer clear(keys)
			for _, key := range keys {
				for repeat := uint16(0); repeat < key.repeats; repeat++ {
					character := key.character
					switch character {
					case '\r', '\n', '\x04', '\x1a':
						if high != 0 {
							appendRune(utf8.RuneError)
							high = 0
						}
						if oversize {
							return true, errPasswordTooLong
						}
						if len(input) == 0 {
							if character == '\x04' || character == '\x1a' {
								return true, io.EOF
							}
							return true, errPasswordEmpty
						}
						return true, nil
					case '\x03':
						return true, context.Canceled
					case '\b', '\x7f':
						if oversize {
							continue
						}
						if high != 0 {
							high = 0
						} else if len(input) > 0 {
							_, size := utf8.DecodeLastRune(input)
							clear(input[len(input)-size:])
							input = input[:len(input)-size]
						}
					case '\x15':
						if !oversize {
							clear(input)
							input = input[:0]
							high = 0
						}
					default:
						if oversize || character == 0 {
							continue
						}
						if high != 0 {
							if character >= 0xdc00 && character <= 0xdfff {
								appendRune(utf16.DecodeRune(rune(high), rune(character)))
								high = 0
								continue
							}
							appendRune(utf8.RuneError)
							high = 0
						}
						if character >= 0xd800 && character <= 0xdbff {
							high = character
						} else if character >= 0xdc00 && character <= 0xdfff {
							appendRune(utf8.RuneError)
						} else {
							appendRune(rune(character))
						}
					}
				}
			}
			return false, nil
		}()
		if finished {
			if readErr != nil {
				return nil, readErr
			}
			return input, nil
		}
	}
}
