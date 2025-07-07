package service

import (
	"context"

	pb "github.com/yandex-cloud/go-protobuf-mutator/testdata"
)

type service struct {
	pb.UnimplementedExampleServiceServer
}

func (s *service) Get(ctx context.Context, req *pb.RequestMessage) (*pb.ExampleResponse, error) {
	// do smth
	return &pb.ExampleResponse{}, nil
}
