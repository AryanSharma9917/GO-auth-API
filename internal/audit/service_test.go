package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"golang-auth/internal/domain"
	"golang-auth/internal/store"
)

type eventRepositoryStub struct {
	created        domain.AuditEvent
	listed         []domain.AuditEvent
	organizationID bson.ObjectID
	action         string
	limit          int64
}

func (s *eventRepositoryStub) Create(_ context.Context, event domain.AuditEvent) (domain.AuditEvent, error) {
	s.created = event
	return event, nil
}
func (s *eventRepositoryStub) ListForOrganization(_ context.Context, organizationID, _ bson.ObjectID, action string, limit int64) ([]domain.AuditEvent, error) {
	s.organizationID = organizationID
	s.action = action
	s.limit = limit
	return s.listed, nil
}

type membershipRepositoryStub struct {
	membership domain.Membership
	err        error
}

func (s membershipRepositoryStub) ByUserAndOrganization(context.Context, bson.ObjectID, bson.ObjectID) (domain.Membership, error) {
	return s.membership, s.err
}

func TestRecordFiltersSensitiveMetadata(t *testing.T) {
	repository := &eventRepositoryStub{}
	service := NewService(repository, membershipRepositoryStub{})
	service.now = func() time.Time { return time.Unix(100, 0) }
	organizationID, userID := bson.NewObjectID(), bson.NewObjectID()
	err := service.Record(context.Background(), RecordInput{OrganizationID: organizationID.Hex(), ActorUserID: userID.Hex(), Action: " auth.login ", Metadata: map[string]any{"role": "owner", "password": "secret", "token": "raw"}})
	if err != nil {
		t.Fatalf("record event: %v", err)
	}
	if repository.created.Action != "auth.login" || repository.created.Metadata["role"] != "owner" {
		t.Fatalf("unexpected event: %+v", repository.created)
	}
	if _, ok := repository.created.Metadata["password"]; ok {
		t.Fatal("password was retained")
	}
	if _, ok := repository.created.Metadata["token"]; ok {
		t.Fatal("token was retained")
	}
}

func TestListRequiresOrganizationAdministrator(t *testing.T) {
	actor := Actor{UserID: bson.NewObjectID().Hex(), OrganizationID: bson.NewObjectID().Hex()}
	for _, membership := range []domain.Membership{{Role: domain.RoleMember, State: domain.MembershipActive}, {Role: domain.RoleOwner, State: domain.MembershipDisabled}} {
		service := NewService(&eventRepositoryStub{}, membershipRepositoryStub{membership: membership})
		if _, err := service.List(context.Background(), actor, "", "", 20); !errors.Is(err, ErrForbidden) {
			t.Fatalf("expected forbidden, got %v", err)
		}
	}
	service := NewService(&eventRepositoryStub{}, membershipRepositoryStub{err: store.ErrNotFound})
	if _, err := service.List(context.Background(), actor, "", "", 20); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden for missing membership, got %v", err)
	}
}

func TestListIsScopedAndPaginated(t *testing.T) {
	organizationID := bson.NewObjectID()
	events := []domain.AuditEvent{{ID: bson.NewObjectID()}, {ID: bson.NewObjectID()}, {ID: bson.NewObjectID()}}
	repository := &eventRepositoryStub{listed: events}
	service := NewService(repository, membershipRepositoryStub{membership: domain.Membership{Role: domain.RoleAdmin, State: domain.MembershipActive}})
	page, err := service.List(context.Background(), Actor{UserID: bson.NewObjectID().Hex(), OrganizationID: organizationID.Hex()}, "", "auth.login", 2)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if repository.organizationID != organizationID || repository.action != "auth.login" || repository.limit != 3 {
		t.Fatalf("query was not scoped: %+v", repository)
	}
	if len(page.Events) != 2 || page.NextCursor != events[1].ID.Hex() {
		t.Fatalf("unexpected page: %+v", page)
	}
}
