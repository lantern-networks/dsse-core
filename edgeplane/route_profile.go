// Application route profiles: the per-application data-plane routing contract
// (destination, port, protocol/service family, sensitivity, private path), the
// startup file loader, and the published-catalog overlay. Moved verbatim from
// cmd/edge (Phase 3 step 3a, advisory); shared with the admin plane through
// the allowed cmd/edge -> edgeplane direction.
package edgeplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// valueOrDefault is edgeplane's copy of the trivial cmd/edge helper (three lines;
// duplicated rather than exporting a util seam).
func valueOrDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

type ApplicationRouteProfile struct {
	Destination            string
	DestinationPort        int
	Protocol               string
	ServiceFamily          string
	DestinationRole        string
	ApplicationSensitivity string
	PrivatePath            string
	DatabaseProtocol       string
}

func ApplicationRouteProfileFor(applicationID string, routeProfiles map[string]ApplicationRouteProfile) ApplicationRouteProfile {
	if profile, ok := routeProfiles[applicationID]; ok {
		return profile.WithDefaults(applicationID)
	}
	switch applicationID {
	case "app_dummy_ssh":
		return ApplicationRouteProfile{
			Destination:            "dummy-ssh.local",
			DestinationPort:        22,
			Protocol:               "tcp",
			ServiceFamily:          "ssh",
			DestinationRole:        "ssh_server",
			ApplicationSensitivity: "high",
			PrivatePath:            "/private-app/dummy-ssh",
		}
	case "app_dummy_postgres":
		return ApplicationRouteProfile{
			Destination:            "dummy-postgres.local",
			DestinationPort:        5432,
			Protocol:               "tcp",
			ServiceFamily:          "database",
			DestinationRole:        "database_server",
			ApplicationSensitivity: "high",
			PrivatePath:            "/private-app/dummy-postgres",
			DatabaseProtocol:       "postgresql",
		}
	case "app_dummy_rdp":
		return ApplicationRouteProfile{
			Destination:            "dummy-rdp.local",
			DestinationPort:        3389,
			Protocol:               "tcp",
			ServiceFamily:          "rdp",
			DestinationRole:        "admin_server",
			ApplicationSensitivity: "high",
			PrivatePath:            "/private-app/dummy-rdp",
		}
	default:
		return ApplicationRouteProfile{
			Destination:            "dummy-private-app.local",
			DestinationPort:        443,
			Protocol:               "tcp",
			ServiceFamily:          "https",
			DestinationRole:        "private_app",
			ApplicationSensitivity: "medium",
			PrivatePath:            "/private-app/dummy",
		}
	}
}

func (profile ApplicationRouteProfile) WithDefaults(applicationID string) ApplicationRouteProfile {
	fallback := applicationRouteProfileForFallback(applicationID)
	if profile.Destination == "" {
		profile.Destination = fallback.Destination
	}
	if profile.DestinationPort == 0 {
		profile.DestinationPort = fallback.DestinationPort
	}
	profile.Protocol = valueOrDefault(profile.Protocol, fallback.Protocol)
	profile.ServiceFamily = valueOrDefault(profile.ServiceFamily, fallback.ServiceFamily)
	profile.DestinationRole = valueOrDefault(profile.DestinationRole, fallback.DestinationRole)
	profile.ApplicationSensitivity = valueOrDefault(profile.ApplicationSensitivity, fallback.ApplicationSensitivity)
	profile.PrivatePath = valueOrDefault(profile.PrivatePath, fallback.PrivatePath)
	profile.DatabaseProtocol = valueOrDefault(profile.DatabaseProtocol, fallback.DatabaseProtocol)
	return profile
}

func applicationRouteProfileForFallback(applicationID string) ApplicationRouteProfile {
	return ApplicationRouteProfileFor(applicationID, nil)
}

func ApplicationPrivatePath(applicationID string, routeProfiles map[string]ApplicationRouteProfile) string {
	return ApplicationRouteProfileFor(applicationID, routeProfiles).PrivatePath
}

// ApplicationRouteProfileFromPublishedEntry derives an application route profile from a published catalog
// entry. It returns ok=false when the entry has no destination (an un-routable record can never become a
// reachable route — fail-closed). withDefaults fills any remaining gaps from the built-in fallback.
func ApplicationRouteProfileFromPublishedEntry(entry appcatalog.Entry) (ApplicationRouteProfile, bool) {
	destination := strings.TrimSpace(entry.Destination)
	if destination == "" {
		return ApplicationRouteProfile{}, false
	}
	serviceFamily := ServiceFamilyForPublishProtocol(entry.PublishProtocol)
	if sf := strings.TrimSpace(entry.ServiceFamily); sf != "" && sf != "saas" {
		serviceFamily = sf
	}
	profile := ApplicationRouteProfile{
		Destination:            destination,
		DestinationPort:        entry.DestinationPort,
		Protocol:               "tcp",
		ServiceFamily:          serviceFamily,
		DestinationRole:        strings.TrimSpace(entry.DestinationRole),
		ApplicationSensitivity: strings.TrimSpace(entry.ApplicationSensitivity),
	}
	return profile.WithDefaults(entry.ApplicationID), true
}

func LoadApplicationRouteProfiles(path string) (map[string]ApplicationRouteProfile, error) {
	profiles := map[string]ApplicationRouteProfile{}
	if strings.TrimSpace(path) == "" {
		return profiles, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return profiles, fmt.Errorf("read protected app map: %w", err)
	}
	var appMap protectedRouteAppMap
	if err := json.Unmarshal(data, &appMap); err != nil {
		return profiles, fmt.Errorf("parse protected app map: %w", err)
	}
	for _, app := range appMap.Applications {
		if app.ApplicationID == "" {
			continue
		}
		profiles[app.ApplicationID] = ApplicationRouteProfile{
			Destination:            app.FQDN,
			DestinationPort:        app.DestinationPort,
			Protocol:               valueOrDefault(stringMetadataValue(app.Metadata, "protocol"), "tcp"),
			ServiceFamily:          app.ServiceFamily,
			DestinationRole:        valueOrDefault(stringMetadataValue(app.Metadata, "destination_role"), destinationRoleForServiceFamily(app.ServiceFamily)),
			ApplicationSensitivity: valueOrDefault(stringMetadataValue(app.Metadata, "sensitivity"), "medium"),
			PrivatePath:            stringMetadataValue(app.Metadata, "private_path"),
			DatabaseProtocol:       stringMetadataValue(app.Metadata, "database_protocol"),
		}
	}
	return profiles, nil
}

// RouteProfilesWithPublishedCatalog overlays runtime PUBLISH state (Connector UX Slice 2) onto the startup
// file route profiles (-protected-app-map). Each PUBLISHED private_app catalog entry contributes an
// application route profile so the edge can resolve a destination for an operator-published private app
// without a file entry. The startup file profiles remain the FALLBACK: an application that is not published in
// the catalog keeps whatever the file map / built-in switch resolves. Lab invariance: catalog entries that
// are NOT published (e.g. the boot seed mirror of the file routes) produce no overlay, so an edge with no
// published apps resolves exactly the same routes as before. Fail-closed: a catalog read error returns the
// base (file) routes unchanged — a publish overlay never widens reachability on error.
func RouteProfilesWithPublishedCatalog(base map[string]ApplicationRouteProfile, store appcatalog.RuntimeStore, tenantID string) map[string]ApplicationRouteProfile {
	tenantID = strings.TrimSpace(tenantID)
	if store == nil || tenantID == "" {
		return base
	}
	result, err := store.List(context.Background(), tenantID, appcatalog.ListOptions{ApplicationType: "private_app", Limit: 1000})
	if err != nil {
		return base
	}
	overlay := map[string]ApplicationRouteProfile{}
	for _, entry := range result.Applications {
		if !entry.Published {
			continue
		}
		profile, ok := ApplicationRouteProfileFromPublishedEntry(entry)
		if !ok {
			continue
		}
		overlay[entry.ApplicationID] = profile
	}
	if len(overlay) == 0 {
		return base
	}
	merged := make(map[string]ApplicationRouteProfile, len(base)+len(overlay))
	for id, profile := range base {
		merged[id] = profile
	}
	for id, profile := range overlay {
		merged[id] = profile // published overlay wins; file route stays the fallback for un-published apps
	}
	return merged
}

// ServiceFamilyForPublishProtocol maps the publish app type (web|tcp|network) to a non-secret service family
// used for policy matching and lateral-movement classification. Unknown/empty defaults to https (web).
func ServiceFamilyForPublishProtocol(publishProtocol string) string {
	switch strings.TrimSpace(publishProtocol) {
	case "tcp":
		return "tcp"
	case "network":
		return "network"
	default:
		return "https"
	}
}

type protectedRouteAppMap struct {
	Applications []protectedRouteApplication `json:"applications"`
}

type protectedRouteApplication struct {
	ApplicationID   string         `json:"application_id"`
	FQDN            string         `json:"fqdn"`
	ServiceFamily   string         `json:"service_family"`
	DestinationPort int            `json:"destination_port"`
	Metadata        map[string]any `json:"metadata"`
}

func stringMetadataValue(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata[key]
	if !ok {
		return ""
	}
	return fmt.Sprint(value)
}

func destinationRoleForServiceFamily(serviceFamily string) string {
	switch serviceFamily {
	case "ssh":
		return "ssh_server"
	case "database":
		return "database_server"
	case "rdp":
		return "admin_server"
	default:
		return "private_app"
	}
}

// Edge TCP CONNECT targets: what an authorized CONNECT is allowed to open through
// the connector tunnel, and the frame that opens it. Moved verbatim from cmd/edge
// main.go (Phase 3 step 3b, advisory).
type EdgeTCPConnectTarget struct {
	ApplicationID string
	Host          string
	Port          int
	ServiceFamily string
}

type EdgeTCPConnectLimits struct {
	ConnectTimeoutMillis        int
	MaxConnectionLifetimeMillis int
	IdleTimeoutMillis           int
	ByteCap                     int64
	ConcurrentConnectionCap     int
}

func EdgeTCPOpenFrameForTarget(RequestID string, target EdgeTCPConnectTarget, limits EdgeTCPConnectLimits) (tunnel.Frame, error) {
	frame := tunnel.Frame{
		Type:                        tunnel.FrameTCPOpen,
		RequestID:                   RequestID,
		ApplicationID:               target.ApplicationID,
		Host:                        target.Host,
		Port:                        target.Port,
		ConnectTimeoutMillis:        limits.ConnectTimeoutMillis,
		MaxConnectionLifetimeMillis: limits.MaxConnectionLifetimeMillis,
		IdleTimeoutMillis:           limits.IdleTimeoutMillis,
		ByteCap:                     limits.ByteCap,
		ConcurrentConnectionCap:     limits.ConcurrentConnectionCap,
	}
	if err := tunnel.ValidateTCPOpenFrame(frame); err != nil {
		return tunnel.Frame{}, err
	}
	return frame, nil
}

func EdgeTCPConnectTargetForApplication(applicationID, clientHost string, clientPort int, routeProfiles map[string]ApplicationRouteProfile) (EdgeTCPConnectTarget, error) {
	explicitProfile, ok := routeProfiles[applicationID]
	if !ok {
		return EdgeTCPConnectTarget{}, fmt.Errorf("tcp connect requires an explicit route profile for application %s", applicationID)
	}
	profile := explicitProfile.WithDefaults(applicationID)
	routeHost := strings.TrimSpace(profile.Destination)
	if routeHost == "" {
		return EdgeTCPConnectTarget{}, fmt.Errorf("tcp connect route destination is required for application %s", applicationID)
	}
	clientHost = strings.TrimSpace(clientHost)
	if parsedHost, _, err := net.SplitHostPort(clientHost); err == nil {
		clientHost = parsedHost
	}
	if clientHost != "" && !strings.EqualFold(clientHost, routeHost) {
		return EdgeTCPConnectTarget{}, fmt.Errorf("tcp connect host %s does not match application route", clientHost)
	}
	if clientPort != 0 && clientPort != profile.DestinationPort {
		return EdgeTCPConnectTarget{}, fmt.Errorf("tcp connect port %d does not match application route", clientPort)
	}
	return EdgeTCPConnectTarget{
		ApplicationID: applicationID,
		Host:          routeHost,
		Port:          profile.DestinationPort,
		ServiceFamily: profile.ServiceFamily,
	}, nil
}
