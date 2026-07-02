//go:build !windows

package main

import "errors"

var errWindowsOnly = errors.New("pdfsign-bridge only supports Windows (CNG) in this build")

func listSigningCertificates() ([]any, error) { return nil, errWindowsOnly }

func signDigest(string, []byte) ([]byte, error) { return nil, errWindowsOnly }
