import Foundation

// Fixed test certificates, generated once and committed.
//
// These tests previously read a PEM out of the developer's own checkout by absolute path, which put a machine
// path — and a person's name — into the PUBLIC OSS package, and made the tests fail for anyone else. Throwaway
// CAs embedded here have neither problem: no filesystem, no environment, and the same input on every machine.
//
// They are test fixtures, not secrets. The private keys were discarded at generation.
enum DsseTestAnchors {
    /// Two CA certificates — the shape of a mid-rotation anchor bundle (previous + next).
    static let twoCABundlePEM = """
-----BEGIN CERTIFICATE-----
MIIBrzCCAVSgAwIBAgIUTgQTtfJIs+TW3Tw2M3TtSWDmEyUwCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYRFNTRSBUZXN0IFRyYW5zcG9ydCBDQSBBMB4XDTI2MDcyOTIz
NTQyMFoXDTM2MDcyNjIzNTQyMFowIzEhMB8GA1UEAwwYRFNTRSBUZXN0IFRyYW5z
cG9ydCBDQSBBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnjMonlmoX42fGgG0
QhAbKIp9sRJQssR1pfcZJpp0oRwzc6qkqt8DoginWQ1y9oyaTpwXqVGkWuxJDyzW
7Gxu9KNmMGQwHQYDVR0OBBYEFGTuFBik3GJeyUokBmdDCmnn5AzSMB8GA1UdIwQY
MBaAFGTuFBik3GJeyUokBmdDCmnn5AzSMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYD
VR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0kAMEYCIQCPN4qMzKN47lZze3o66cfO
HtcGE0CZTxybKwSMoF2iAwIhANgwBuAABUhT3X/EHy1s4Q6nQOyNZVrOOv95AFLg
LOM4
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBrjCCAVSgAwIBAgIUOA/jW+54r1rTGO0lCEFkshS/g6cwCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYRFNTRSBUZXN0IFRyYW5zcG9ydCBDQSBCMB4XDTI2MDcyOTIz
NTQyMFoXDTM2MDcyNjIzNTQyMFowIzEhMB8GA1UEAwwYRFNTRSBUZXN0IFRyYW5z
cG9ydCBDQSBCMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+j/8EGlSwo5BhDTd
ScJKFAW4SB677dqrHdb9NT72Wf0mqtYJQq0Nzag5ohsZBvUXBaQwySlOI4ua1tM4
s8I6SKNmMGQwHQYDVR0OBBYEFLf+FqrdjZxrn92DGcUueMWIHDVLMB8GA1UdIwQY
MBaAFLf+FqrdjZxrn92DGcUueMWIHDVLMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYD
VR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIE5GglWeMokHM9iiFXsb/wvq
bLjfHVh7WZVCslOLbNzIAiEAt+ZSXsHKsI1JX+Rtxr8OLbjbRyYoaI7goSOJhDnH
eWQ=
-----END CERTIFICATE-----
"""

    /// A certificate that is NOT a CA. Anchor parsing must drop it: accepting a leaf would let a bundle pin a
    /// device to one server certificate, which is the shape the CA layer exists to get away from.
    static let nonCALeafPEM = """
-----BEGIN CERTIFICATE-----
MIIBhDCCASqgAwIBAgIUMb2JZ1TSB7marcxUtzBd8DEftv0wCgYIKoZIzj0EAwIw
GTEXMBUGA1UEAwwORFNTRSBUZXN0IExlYWYwHhcNMjYwNzI5MjM1NDIwWhcNMzYw
NzI2MjM1NDIwWjAZMRcwFQYDVQQDDA5EU1NFIFRlc3QgTGVhZjBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABG1bAGe+0T01Rc5VvrSMJkfxDjdCFCVuJKZXgWqixHeA
Bt+zWC1v2x6nhY3Mmx9eIy9blkcPY68qz73OwlsFWTOjUDBOMB0GA1UdDgQWBBT/
XPHN6RCB2sKNF5Wb0e4pVjrpNzAfBgNVHSMEGDAWgBT/XPHN6RCB2sKNF5Wb0e4p
VjrpNzAMBgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIBnyHKNJ4hZzTrmR
ySmjZFMogZrIJaLwSPlGkA1IQNnZAiEAiVZ8CMeswlW5JIEnvSuWkFyWG1WlaSja
IKEcd1xTesc=
-----END CERTIFICATE-----
"""
}
