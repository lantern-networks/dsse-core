package toolcallaudit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type RuntimeStore interface {
	List(context.Context, string, ListOptions) (ListResponse, error)
	Get(context.Context, string, string) (Event, bool, error)
	Upsert(context.Context, model.ToolCallEvent, string, time.Time) (Event, error)
}

type Store struct {
	mu     sync.RWMutex
	events map[string]Event
}

type ListOptions struct {
	ToolID     string
	ActorNHIID string
	Decision   string
	Status     string
	Limit      int
}

type ListResponse struct {
	Events []Event `json:"events"`
	Count  int     `json:"count"`
	Limit  int     `json:"limit"`
}

type Event struct {
	ID                         string  `json:"id"`
	TenantID                   string  `json:"tenant_id"`
	AgentTaskSessionID         *string `json:"agent_task_session_id,omitempty"`
	ActorNHIID                 string  `json:"actor_nhi_id"`
	SubjectUserIDPresent       bool    `json:"subject_user_id_present"`
	DelegatedAccessGrantID     *string `json:"delegated_access_grant_id,omitempty"`
	TaskIDPresent              bool    `json:"task_id_present"`
	RunIDPresent               bool    `json:"run_id_present"`
	ToolID                     string  `json:"tool_id"`
	MCPServerID                *string `json:"mcp_server_id,omitempty"`
	RuntimeEnvironmentID       *string `json:"runtime_environment_id,omitempty"`
	ActionType                 string  `json:"action_type"`
	ApplicationID              *string `json:"application_id,omitempty"`
	ContextBoundaryID          *string `json:"context_boundary_id,omitempty"`
	DataClassification         *string `json:"data_classification,omitempty"`
	DestinationPresent         bool    `json:"destination_present"`
	TokenAudiencePresent       bool    `json:"token_audience_present"`
	HumanApprovalEventID       *string `json:"human_approval_event_id,omitempty"`
	AccessDecisionID           *string `json:"access_decision_id,omitempty"`
	InspectionEventID          *string `json:"inspection_event_id,omitempty"`
	PolicyID                   *string `json:"policy_id,omitempty"`
	Decision                   *string `json:"decision,omitempty"`
	ResultSummaryPresent       bool    `json:"result_summary_present"`
	ResultSummaryScope         string  `json:"result_summary_scope"`
	Masked                     bool    `json:"masked"`
	PayloadRefPresent          bool    `json:"payload_ref_present"`
	RetentionPolicy            *string `json:"retention_policy,omitempty"`
	Timestamp                  string  `json:"timestamp"`
	Status                     *string `json:"status,omitempty"`
	MetadataKeyCount           int     `json:"metadata_key_count"`
	ToolCallMetadataValueScope string  `json:"tool_call_metadata_value_scope"`
}

func NewStore() *Store {
	return &Store{
		events: map[string]Event{},
	}
}

func (s *Store) List(_ context.Context, tenantID string, options ListOptions) (ListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ListResponse{}, fmt.Errorf("tenant_id is required")
	}
	toolID := strings.TrimSpace(options.ToolID)
	actorNHIID := strings.TrimSpace(options.ActorNHIID)
	decision := strings.TrimSpace(options.Decision)
	status := strings.TrimSpace(options.Status)
	limit := options.Limit
	if limit <= 0 {
		limit = 100
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	rows := []Event{}
	for _, event := range s.events {
		if event.TenantID != tenantID {
			continue
		}
		if toolID != "" && event.ToolID != toolID {
			continue
		}
		if actorNHIID != "" && event.ActorNHIID != actorNHIID {
			continue
		}
		if decision != "" && stringPtrValue(event.Decision) != decision {
			continue
		}
		if status != "" && stringPtrValue(event.Status) != status {
			continue
		}
		rows = append(rows, event)
	}
	sortEvents(rows)
	count := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return ListResponse{
		Events: rows,
		Count:  count,
		Limit:  limit,
	}, nil
}

func (s *Store) Get(_ context.Context, tenantID, eventID string) (Event, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	eventID = strings.TrimSpace(eventID)
	if tenantID == "" {
		return Event{}, false, fmt.Errorf("tenant_id is required")
	}
	if eventID == "" {
		return Event{}, false, fmt.Errorf("event_id is required")
	}
	if strings.Contains(eventID, "/") {
		return Event{}, false, fmt.Errorf("event_id cannot contain slash")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	event, ok := s.events[eventID]
	if !ok || event.TenantID != tenantID {
		return Event{}, false, nil
	}
	return event, true, nil
}

func (s *Store) Upsert(_ context.Context, event model.ToolCallEvent, tenantID string, now time.Time) (Event, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Event{}, fmt.Errorf("tenant_id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if strings.Contains(strings.TrimSpace(event.ID), "/") {
		return Event{}, fmt.Errorf("tool call event id cannot contain slash")
	}
	if err := Normalize(&event, tenantID, now); err != nil {
		return Event{}, err
	}
	adminEvent := fromModel(event)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[adminEvent.ID] = adminEvent
	return adminEvent, nil
}

func fromModel(event model.ToolCallEvent) Event {
	return Event{
		ID:                         strings.TrimSpace(event.ID),
		TenantID:                   strings.TrimSpace(event.TenantID),
		AgentTaskSessionID:         trimmedStringPtr(event.AgentTaskSessionID),
		ActorNHIID:                 strings.TrimSpace(event.ActorNHIID),
		SubjectUserIDPresent:       stringPtrValue(event.SubjectUserID) != "",
		DelegatedAccessGrantID:     trimmedStringPtr(event.DelegatedAccessGrantID),
		TaskIDPresent:              stringPtrValue(event.TaskID) != "",
		RunIDPresent:               stringPtrValue(event.RunID) != "",
		ToolID:                     strings.TrimSpace(event.ToolID),
		MCPServerID:                trimmedStringPtr(event.MCPServerID),
		RuntimeEnvironmentID:       trimmedStringPtr(event.RuntimeEnvironmentID),
		ActionType:                 strings.TrimSpace(event.ActionType),
		ApplicationID:              trimmedStringPtr(event.ApplicationID),
		ContextBoundaryID:          trimmedStringPtr(event.ContextBoundaryID),
		DataClassification:         trimmedStringPtr(event.DataClassification),
		DestinationPresent:         stringPtrValue(event.Destination) != "",
		TokenAudiencePresent:       stringPtrValue(event.TokenAudience) != "",
		HumanApprovalEventID:       trimmedStringPtr(event.HumanApprovalEventID),
		AccessDecisionID:           trimmedStringPtr(event.AccessDecisionID),
		InspectionEventID:          trimmedStringPtr(event.InspectionEventID),
		PolicyID:                   trimmedStringPtr(event.PolicyID),
		Decision:                   trimmedStringPtr(event.Decision),
		ResultSummaryPresent:       stringPtrValue(event.ResultSummary) != "",
		ResultSummaryScope:         strings.TrimSpace(event.ResultSummaryScope),
		Masked:                     event.Masked,
		PayloadRefPresent:          stringPtrValue(event.PayloadRef) != "",
		RetentionPolicy:            trimmedStringPtr(event.RetentionPolicy),
		Timestamp:                  strings.TrimSpace(event.Timestamp),
		Status:                     trimmedStringPtr(event.Status),
		MetadataKeyCount:           len(event.Metadata),
		ToolCallMetadataValueScope: "none",
	}
}

func trimmedStringPtr(value *string) *string {
	trimmed := strings.TrimSpace(stringPtrValue(value))
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func sortEvents(events []Event) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].Timestamp != events[j].Timestamp {
			return events[i].Timestamp > events[j].Timestamp
		}
		return events[i].ID < events[j].ID
	})
}

// stringPtrValue dereferences an optional string (nil => "").
func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
