package service

import (
	"context"

	pb "github.com/yandex-cloud/go-protobuf-mutator/testdata"

	"google.golang.org/protobuf/proto"
)

func FuzzGet(ctx context.Context, method string, req proto.Message) error {
	s := service{}
	_, err := s.Get(ctx, req.(*pb.RequestMessage))

	return err
}
