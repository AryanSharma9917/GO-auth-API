package domain

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type User struct {
	ID            bson.ObjectID `bson:"_id,omitempty" json:"id"`
	Email         string        `bson:"email" json:"email"`
	DisplayName   string        `bson:"displayName" json:"displayName"`
	PasswordHash  string        `bson:"passwordHash" json:"-"`
	EmailVerified bool          `bson:"emailVerified" json:"emailVerified"`
	DisabledAt    *time.Time    `bson:"disabledAt,omitempty" json:"disabledAt,omitempty"`
	CreatedAt     time.Time     `bson:"createdAt" json:"createdAt"`
	UpdatedAt     time.Time     `bson:"updatedAt" json:"updatedAt"`
}

type Organization struct {
	ID        bson.ObjectID `bson:"_id,omitempty" json:"id"`
	Name      string        `bson:"name" json:"name"`
	Slug      string        `bson:"slug" json:"slug"`
	CreatedAt time.Time     `bson:"createdAt" json:"createdAt"`
	UpdatedAt time.Time     `bson:"updatedAt" json:"updatedAt"`
}

type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

type MembershipState string

const (
	MembershipActive   MembershipState = "active"
	MembershipDisabled MembershipState = "disabled"
)

type Membership struct {
	ID             bson.ObjectID   `bson:"_id,omitempty" json:"id"`
	OrganizationID bson.ObjectID   `bson:"organizationId" json:"organizationId"`
	UserID         bson.ObjectID   `bson:"userId" json:"userId"`
	Role           Role            `bson:"role" json:"role"`
	State          MembershipState `bson:"state" json:"state"`
	CreatedAt      time.Time       `bson:"createdAt" json:"createdAt"`
	UpdatedAt      time.Time       `bson:"updatedAt" json:"updatedAt"`
}

type Session struct {
	ID               bson.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID           bson.ObjectID `bson:"userId" json:"userId"`
	OrganizationID   bson.ObjectID `bson:"organizationId" json:"organizationId"`
	RefreshTokenHash string        `bson:"refreshTokenHash" json:"-"`
	UsedTokenHashes  []string      `bson:"usedTokenHashes,omitempty" json:"-"`
	TokenFamilyID    string        `bson:"tokenFamilyId" json:"-"`
	IPAddress        string        `bson:"ipAddress,omitempty" json:"ipAddress,omitempty"`
	UserAgent        string        `bson:"userAgent,omitempty" json:"userAgent,omitempty"`
	ExpiresAt        time.Time     `bson:"expiresAt" json:"expiresAt"`
	RevokedAt        *time.Time    `bson:"revokedAt,omitempty" json:"revokedAt,omitempty"`
	RevocationReason string        `bson:"revocationReason,omitempty" json:"revocationReason,omitempty"`
	CreatedAt        time.Time     `bson:"createdAt" json:"createdAt"`
	LastUsedAt       time.Time     `bson:"lastUsedAt" json:"lastUsedAt"`
}

type Invitation struct {
	ID             bson.ObjectID `bson:"_id,omitempty" json:"id"`
	OrganizationID bson.ObjectID `bson:"organizationId" json:"organizationId"`
	Email          string        `bson:"email" json:"email"`
	Role           Role          `bson:"role" json:"role"`
	Status         string        `bson:"status" json:"status"`
	TokenHash      string        `bson:"tokenHash" json:"-"`
	InvitedBy      bson.ObjectID `bson:"invitedBy" json:"invitedBy"`
	ExpiresAt      time.Time     `bson:"expiresAt" json:"expiresAt"`
	AcceptedAt     *time.Time    `bson:"acceptedAt,omitempty" json:"acceptedAt,omitempty"`
	RevokedAt      *time.Time    `bson:"revokedAt,omitempty" json:"revokedAt,omitempty"`
	ClaimedAt      *time.Time    `bson:"claimedAt,omitempty" json:"-"`
	CreatedAt      time.Time     `bson:"createdAt" json:"createdAt"`
}

const (
	InvitationPending  = "pending"
	InvitationAccepted = "accepted"
	InvitationRevoked  = "revoked"
)

type AuditEvent struct {
	ID             bson.ObjectID  `bson:"_id,omitempty" json:"id"`
	OrganizationID bson.ObjectID  `bson:"organizationId" json:"organizationId"`
	ActorUserID    *bson.ObjectID `bson:"actorUserId,omitempty" json:"actorUserId,omitempty"`
	Action         string         `bson:"action" json:"action"`
	TargetType     string         `bson:"targetType,omitempty" json:"targetType,omitempty"`
	TargetID       string         `bson:"targetId,omitempty" json:"targetId,omitempty"`
	RequestID      string         `bson:"requestId,omitempty" json:"requestId,omitempty"`
	IPAddress      string         `bson:"ipAddress,omitempty" json:"ipAddress,omitempty"`
	Metadata       map[string]any `bson:"metadata,omitempty" json:"metadata,omitempty"`
	CreatedAt      time.Time      `bson:"createdAt" json:"createdAt"`
}
