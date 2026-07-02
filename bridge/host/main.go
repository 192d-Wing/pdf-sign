// pdfsign-bridge: native-messaging host that signs digests with a smart
// card via Windows CNG.
//
// The browser extension relays requests from the pdf-sign web page to this
// process over stdin/stdout using Chrome's native messaging protocol
// (4-byte little-endian length prefix + JSON). Chrome spawns one process
// per request (sendNativeMessage), so the host is stateless.
//
// Commands:
//
//	{"cmd":"ping"}
//	  -> {"ok":true,"version":"..."}
//	{"cmd":"listCertificates"}
//	  -> {"certificates":[{"subject","issuer","notAfter","thumbprint","certificate"}]}
//	{"cmd":"signDigest","thumbprint":"<hex>","digest":"<b64 SHA-256>"}
//	  -> {"signature":"<b64>"}   (PKCS#1 v1.5 for RSA, ASN.1 DER for ECDSA)
//
// Errors are returned as {"error":"..."}.
//
// Debugging: run `pdfsign-bridge.exe -cli list` (or `-cli ping`) to invoke
// a command directly without the length-prefixed framing.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

const version = "0.1.0"

type request struct {
	Cmd        string `json:"cmd"`
	Thumbprint string `json:"thumbprint,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

func main() {
	cli := flag.String("cli", "", "run a command directly (ping|list) and print JSON, for debugging")
	flag.Parse()

	if *cli != "" {
		var req request
		switch *cli {
		case "ping":
			req.Cmd = "ping"
		case "list":
			req.Cmd = "listCertificates"
		default:
			fmt.Fprintln(os.Stderr, "usage: pdfsign-bridge -cli ping|list")
			os.Exit(2)
		}
		out, _ := json.MarshalIndent(handle(req), "", "  ")
		fmt.Println(string(out))
		return
	}

	if err := serve(os.Stdin, os.Stdout); err != nil && err != io.EOF {
		fmt.Fprintln(os.Stderr, "bridge:", err)
		os.Exit(1)
	}
}

func serve(in io.Reader, out io.Writer) error {
	for {
		var length uint32
		if err := binary.Read(in, binary.LittleEndian, &length); err != nil {
			return err
		}
		if length == 0 || length > 1<<20 {
			return fmt.Errorf("invalid message length %d", length)
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(in, buf); err != nil {
			return err
		}

		var req request
		var resp any
		if err := json.Unmarshal(buf, &req); err != nil {
			resp = errResp("invalid JSON: " + err.Error())
		} else {
			resp = handle(req)
		}

		payload, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		if err := binary.Write(out, binary.LittleEndian, uint32(len(payload))); err != nil {
			return err
		}
		if _, err := out.Write(payload); err != nil {
			return err
		}
	}
}

func errResp(msg string) map[string]string {
	return map[string]string{"error": msg}
}

func handle(req request) any {
	switch req.Cmd {
	case "ping":
		return map[string]any{"ok": true, "version": version}

	case "listCertificates":
		certs, err := listSigningCertificates()
		if err != nil {
			return errResp(err.Error())
		}
		return map[string]any{"certificates": certs}

	case "signDigest":
		digest, err := base64.StdEncoding.DecodeString(req.Digest)
		if err != nil {
			return errResp("digest is not valid base64")
		}
		if req.Thumbprint == "" {
			return errResp("thumbprint is required")
		}
		signature, err := signDigest(req.Thumbprint, digest)
		if err != nil {
			return errResp(err.Error())
		}
		return map[string]string{
			"signature": base64.StdEncoding.EncodeToString(signature),
		}

	default:
		return errResp("unknown command " + req.Cmd)
	}
}
