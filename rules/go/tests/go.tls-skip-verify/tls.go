package main

import "crypto/tls"

func insecure() {
	_ = tls.Config{InsecureSkipVerify: true}                // crit:expect go.tls-skip-verify
	_ = &tls.Config{InsecureSkipVerify: true, MinVersion: 0} // crit:expect go.tls-skip-verify
}

func secure() {
	_ = tls.Config{InsecureSkipVerify: false} // crit:expect-not go.tls-skip-verify
	_ = tls.Config{ServerName: "example.com"} // crit:expect-not go.tls-skip-verify
}
