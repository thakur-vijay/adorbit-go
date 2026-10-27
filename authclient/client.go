package authclient

import (
	"context"

	"github.com/thakur-vijay/adorbit-go/middleware"
	authv1 "github.com/thakur-vijay/adorbit-go/proto/authv1"
	"google.golang.org/grpc"
)

type Client struct {
	client authv1.AuthServiceClient
}

func New(conn *grpc.ClientConn) *Client {
	return &Client{
		client: authv1.NewAuthServiceClient(conn),
	}
}

func (c *Client) ValidateAccessToken(
	ctx context.Context,
	token string,
) (*middleware.Session, error) {
	resp, err := c.client.ValidateAccessToken(ctx, &authv1.ValidateAccessTokenRequest{
		AccessToken: token,
	})
	if err != nil {
		return nil, err
	}

	return &middleware.Session{
		UserID:    resp.GetUserId(),
		SessionID: resp.GetSessionId(),
	}, nil
}
