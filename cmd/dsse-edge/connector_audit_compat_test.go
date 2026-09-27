package main

import (
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"testing"
)

func readSiteActorAudits(t *testing.T, writer *logs.Writer) []model.AuditLog {
	return readSiteActorAuditsPublicBaseline(t, writer)
}
func readConnectorManagementAudits(t *testing.T, writer *logs.Writer) []model.AuditLog {
	return readConnectorManagementAuditsPublicBaseline(t, writer)
}
