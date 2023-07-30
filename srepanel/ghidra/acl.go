package ghidra

import (
	"bufio"
	"strings"
)

const (
	PermRead  = iota
	PermWrite = iota
	PermAdmin = iota
)

const (
	PermReadStr  = "READ_ONLY"
	PermWriteStr = "WRITE"
	PermAdminStr = "ADMIN"
)

const AnonAllowedStr = "=ANONYMOUS_ALLOWED"

// ACL is an in-memory representation of a repo access list.
type ACL struct {
	AnonymousAccess bool
	Users           map[string]int
}

// ReadACL deserializes an ACL from a given scanner stream.
func ReadACL(scn *bufio.Scanner) (acl *ACL, err error) {
	acl = &ACL{
		Users: make(map[string]int),
	}
	for scn.Scan() {
		line := scn.Text()
		if strings.HasPrefix(line, ";") {
			continue
		}
		line = strings.TrimSpace(line)

		if line == AnonAllowedStr {
			acl.AnonymousAccess = true
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		userName := strings.TrimSpace(parts[0])
		roleName := strings.TrimSpace(parts[1])
		switch roleName {
		case PermReadStr:
			acl.Users[userName] = PermRead
		case PermWriteStr:
			acl.Users[userName] = PermWrite
		case PermAdminStr:
			acl.Users[userName] = PermAdmin
		}
	}
	return acl, scn.Err()
}
