package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang-auth/internal/domain"
	"golang-auth/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
)

var (
	ErrInvalidInput = errors.New("invalid audit query")
	ErrForbidden    = errors.New("audit access forbidden")
)

type Repository interface {
	Create(context.Context, domain.AuditEvent) (domain.AuditEvent, error)
	ListForOrganization(context.Context, bson.ObjectID, bson.ObjectID, string, int64) ([]domain.AuditEvent, error)
}

type MembershipRepository interface {
	ByUserAndOrganization(context.Context, bson.ObjectID, bson.ObjectID) (domain.Membership, error)
}

type Service struct {
	events      Repository
	memberships MembershipRepository
	now         func() time.Time
}

type Actor struct {
	UserID, OrganizationID string
}

type RecordInput struct {
	OrganizationID string
	ActorUserID    string
	Action         string
	TargetType     string
	TargetID       string
	RequestID      string
	IPAddress      string
	Metadata       map[string]any
}

type Page struct {
	Events     []domain.AuditEvent
	NextCursor string
}

func NewService(events Repository, memberships MembershipRepository) *Service {
	return &Service{events: events, memberships: memberships, now: time.Now}
}

func (s *Service) Record(ctx context.Context, input RecordInput) error {
	organizationID, err := bson.ObjectIDFromHex(input.OrganizationID)
	if err != nil || strings.TrimSpace(input.Action) == "" {
		return ErrInvalidInput
	}
	var actorID *bson.ObjectID
	if input.ActorUserID != "" {
		parsed, parseErr := bson.ObjectIDFromHex(input.ActorUserID)
		if parseErr != nil {
			return ErrInvalidInput
		}
		actorID = &parsed
	}
	_, err = s.events.Create(ctx, domain.AuditEvent{
		OrganizationID: organizationID, ActorUserID: actorID, Action: strings.TrimSpace(input.Action),
		TargetType: input.TargetType, TargetID: input.TargetID, RequestID: input.RequestID,
		IPAddress: input.IPAddress, Metadata: safeMetadata(input.Metadata), CreatedAt: s.now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

func (s *Service) List(ctx context.Context, actor Actor, cursor, action string, limit int) (Page, error) {
	userID, organizationID, err := parseActor(actor)
	if err != nil {
		return Page{}, err
	}
	membership, err := s.memberships.ByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Page{}, ErrForbidden
		}
		return Page{}, fmt.Errorf("find membership: %w", err)
	}
	if membership.State != domain.MembershipActive || (membership.Role != domain.RoleOwner && membership.Role != domain.RoleAdmin) {
		return Page{}, ErrForbidden
	}
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 {
		return Page{}, ErrInvalidInput
	}
	var before bson.ObjectID
	if cursor != "" {
		before, err = bson.ObjectIDFromHex(cursor)
		if err != nil {
			return Page{}, ErrInvalidInput
		}
	}
	events, err := s.events.ListForOrganization(ctx, organizationID, before, strings.TrimSpace(action), int64(limit+1))
	if err != nil {
		return Page{}, fmt.Errorf("list audit events: %w", err)
	}
	page := Page{Events: events}
	if len(events) > limit {
		page.NextCursor = events[limit-1].ID.Hex()
		page.Events = events[:limit]
	}
	return page, nil
}

func parseActor(actor Actor) (bson.ObjectID, bson.ObjectID, error) {
	userID, err := bson.ObjectIDFromHex(actor.UserID)
	if err != nil {
		return bson.NilObjectID, bson.NilObjectID, ErrInvalidInput
	}
	organizationID, err := bson.ObjectIDFromHex(actor.OrganizationID)
	if err != nil {
		return bson.NilObjectID, bson.NilObjectID, ErrInvalidInput
	}
	return userID, organizationID, nil
}

func safeMetadata(metadata map[string]any) map[string]any {
	allowed := map[string]bool{"role": true, "state": true, "email": true, "reason": true}
	clean := make(map[string]any)
	for key, value := range metadata {
		if allowed[key] {
			clean[key] = value
		}
	}
	if len(clean) == 0 {
		return nil
	}
	return clean
}
