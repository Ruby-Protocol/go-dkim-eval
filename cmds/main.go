package main

import (
	"fmt"
	"net"
	"os"

	"dkim"
)

func main() {
	// d, err := os.ReadFile("cmds/recovery.eml")
	d, err := os.ReadFile("cmds/recovery.eml")
	if err != nil {
		fmt.Println(err)
	}
	resolveTXT := dkim.DNSOptLookupTXT(func(name string) ([]string, error) {
		return net.LookupTXT(name)
	})
	output, err := dkim.Verify(&d, resolveTXT)
	fmt.Println(err)
	fmt.Println(output == dkim.SUCCESS && err == nil)
}
