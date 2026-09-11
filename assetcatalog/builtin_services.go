package assetcatalog

import "strings"

// BuiltInServices is the shipped set of well-known services every tenant gets for free (so a rule's "Service"
// can be picked, not hand-typed). Standard IANA port assignments only — no tenant data. Install via
// Store.SetBuiltInServices; a tenant-authored service with the same alias shadows the built-in.
func BuiltInServices() []Service {
	tcp := func(p int) PortProto { return PortProto{Protocol: "tcp", Port: p} }
	udp := func(p int) PortProto { return PortProto{Protocol: "udp", Port: p} }
	svc := func(alias string, ports ...PortProto) Service {
		return Service{
			ID:      "builtin-svc-" + strings.ToLower(strings.ReplaceAll(alias, " ", "-")),
			Alias:   alias,
			Ports:   ports,
			BuiltIn: true,
		}
	}
	return []Service{
		// Web
		svc("HTTPS", tcp(443)),
		svc("HTTP", tcp(80)),
		// Remote access / management (common east-west lateral-movement vectors)
		svc("SSH", tcp(22)),
		svc("RDP", tcp(3389)),
		svc("VNC", tcp(5900)),
		svc("WinRM-HTTP", tcp(5985)),
		svc("WinRM-HTTPS", tcp(5986)),
		svc("Telnet", tcp(23)),
		// Windows / directory
		svc("SMB", tcp(445)),
		svc("NetBIOS", tcp(139)),
		svc("RPC Endpoint Mapper", tcp(135)),
		svc("LDAP", tcp(389)),
		svc("LDAPS", tcp(636)),
		svc("Kerberos", tcp(88), udp(88)),
		svc("DNS", tcp(53), udp(53)),
		// Mail
		svc("SMTP", tcp(25)),
		svc("SMTP Submission", tcp(587)),
		svc("SMTPS", tcp(465)),
		svc("IMAP", tcp(143)),
		svc("IMAPS", tcp(993)),
		svc("POP3", tcp(110)),
		svc("POP3S", tcp(995)),
		// File transfer
		svc("FTP", tcp(21)),
		// Databases
		svc("MySQL", tcp(3306)),
		svc("PostgreSQL", tcp(5432)),
		svc("MSSQL", tcp(1433)),
		svc("Oracle DB", tcp(1521)),
		svc("Redis", tcp(6379)),
		svc("MongoDB", tcp(27017)),
		// Ops
		svc("Syslog", udp(514)),
		svc("SNMP", udp(161)),
	}
}
