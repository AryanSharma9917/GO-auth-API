package mailer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

type Invitation struct {
	Recipient        string
	OrganizationName string
	InviterName      string
	Role             string
	Token            string
}

type SMTP struct{ address, host, username, password, from, baseURL string }

func NewSMTP(host, port, username, password, from, baseURL string) (*SMTP, error) {
	if host == "" || port == "" || username == "" || password == "" || from == "" {
		return nil, errors.New("complete SMTP configuration is required")
	}
	return &SMTP{address: host + ":" + port, host: host, username: username, password: password, from: from, baseURL: strings.TrimRight(baseURL, "/")}, nil
}

func (m *SMTP) SendInvitation(_ context.Context, invitation Invitation) error {
	subject := "You have been invited to " + invitation.OrganizationName
	body := "Accept your invitation: " + m.baseURL + "/invitations/" + invitation.Token
	return m.send(invitation.Recipient, subject, body)
}

func (m *SMTP) SendPasswordReset(_ context.Context, reset PasswordReset) error {
	return m.send(reset.Recipient, "Reset your password", "Reset your password: "+m.baseURL+"/password-reset/"+reset.Token)
}

func (m *SMTP) send(recipient, subject, body string) error {
	if strings.ContainsAny(recipient+subject, "\r\n") {
		return errors.New("invalid email header")
	}
	message := []byte("From: " + m.from + "\r\nTo: " + recipient + "\r\nSubject: " + subject + "\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body)
	auth := smtp.PlainAuth("", m.username, m.password, m.host)
	if err := smtp.SendMail(m.address, auth, m.from, []string{recipient}, message); err != nil {
		return fmt.Errorf("send SMTP message: %w", err)
	}
	return nil
}

type PasswordReset struct{ Recipient, Token string }

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

func (m *Development) SendPasswordReset(_ context.Context, reset PasswordReset) error {
	slog.Info("development password reset email", "recipient", reset.Recipient, "reset_url", m.baseURL+"/password-reset/"+reset.Token)
	return nil
}
