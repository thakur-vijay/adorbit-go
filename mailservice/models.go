package mailservice

import "context"

// Message is a provider-independent email message. At least one body is required.
type Message struct {
	To       []string
	CC       []string
	BCC      []string
	ReplyTo  string
	Subject  string
	HTMLBody string
	TextBody string
}

// Service sends email messages.
type Service interface {
	Send(context.Context, Message) error
}
