package mailer

import (
	"context"
	"errors"
	"log/slog"
	"strings"
)

type Invitation struct {
	Recipient        string
	OrganizationName string
	InviterName      string
	Role             string
	Token            string
}

type Sender interface {
	SendInvitation(context.Context, Invitation) error
}

type Development struct {
	baseURL string
}

func NewDevelopment(environment, baseURL string) (*Development, error) {
	if strings.EqualFold(environment, "production") {
		return nil, errors.New("development mailer cannot run in production")
	}
	return &Development{baseURL: strings.TrimRight(baseURL, "/")}, nil
}

func (m *Development) SendInvitation(_ context.Context, invitation Invitation) error {
	slog.Info("development invitation email",
		"recipient", invitation.Recipient,
		"organization", invitation.OrganizationName,
		"role", invitation.Role,
		"accept_url", m.baseURL+"/invitations/"+invitation.Token,
	)
	return nil
}
