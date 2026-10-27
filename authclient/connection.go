package authclient

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func Dial(address string) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}
