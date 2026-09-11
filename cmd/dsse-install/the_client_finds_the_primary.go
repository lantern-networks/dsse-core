package main

import "strings"

// ★★★ THE DOOR THAT WAS REMOVED WAS FINDING THE PRIMARY (2026-09-02, measured on the live lab).
//
// The operator retired the local haproxy in front of Postgres — "neither Postgres nor the control plane needs
// a haproxy in this shape" — and the pair it fronted on one machine really was pointless. But that door was
// doing a second thing nobody named: it health-checked Patroni's GET /primary across EVERY member of the
// deployment, in every region, and forwarded to the one that answered 200. This deployment has ONE Postgres
// cluster spanning three regions, so a region's own member is a replica most of the time:
//
//	ERROR:  cannot execute GRANT ROLE in a read-only transaction
//
// — dsse-postgres-init, restarting every few seconds against a follower, on a machine whose control plane
// could not have started either.
//
// The replacement is not another proxy. libpq finds the primary itself when it is given every member and
// target_session_attrs=read-write, which is what the control plane's DSN already said — it just had one host
// in it. This renders the whole list, from the deployment's own record of its peers, so an existing
// deployment gets it from a repair rather than from an operator editing a file.
const databaseHostsPlaceholder = "__PG_HOSTS__"

// databaseHostList is every member of this deployment's Postgres cluster, as libpq wants them: the local
// member by its compose name, then each peer this deployment records.
//
// ★ THE PEERS ARE host:port:patroni-api AND libpq WANTS THE FIRST TWO. The third is how the front door
// health-checked them and means nothing to a client that asks the server itself whether it can be written to.
func databaseHostList(dir string) string {
	hosts := []string{"dsse-postgres-a:5432"}
	for _, p := range databasePeers(dir) {
		fields := strings.Split(strings.TrimSpace(p), ":")
		switch len(fields) {
		case 0, 1:
			continue
		default:
			hosts = append(hosts, fields[0]+":"+fields[1])
		}
	}
	return strings.Join(hosts, ",")
}
