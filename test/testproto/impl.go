// Copyright (c) 2016 All Right Reserved, Improbable Worlds Ltd.

package mwitkow_testproto

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	PingDefaultValue   = "I like kittens."
	CountListResponses = 20
)

type testService struct {
}

func (s *testService) PingEmpty(ctx context.Context, _ *Empty) (*PingResponse, error) {
	return &PingResponse{Value: PingDefaultValue, Counter: 42}, nil
}

func (s *testService) Ping(ctx context.Context, ping *PingRequest) (*PingResponse, error) {
	// Send user trailers and headers.
	return &PingResponse{Value: ping.Value, Counter: 42}, nil
}

func (s *testService) PingError(ctx context.Context, ping *PingRequest) (*Empty, error) {
	code := codes.Code(ping.ErrorCodeReturned)
	return nil, grpc.Errorf(code, "Userspace error.")
}

func (s *testService) PingList(ping *PingRequest, stream TestService_PingListServer) error {
	if ping.ErrorCodeReturned != 0 {
		return grpc.Errorf(codes.Code(ping.ErrorCodeReturned), "foobar")
	}
	// Send user trailers and headers.
	for i := 0; i < CountListResponses; i++ {
		stream.Send(&PingResponse{Value: ping.Value, Counter: int32(i)})
	}
	return nil
}
