package ratelimit

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestLimiterBurstAndDeny(t *testing.T) {
	// Arrange
	l := New(rate.Every(time.Hour), 3)

	// Act + Assert
	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d denied within burst", i+1)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("request over burst allowed")
	}
}

func TestLimiterKeysAreIndependent(t *testing.T) {
	// Arrange
	l := New(rate.Every(time.Hour), 1)

	// Act + Assert
	if !l.Allow("1.1.1.1") {
		t.Fatal("first key denied")
	}
	if !l.Allow("2.2.2.2") {
		t.Fatal("second key denied after first exhausted its budget")
	}
	if l.Allow("1.1.1.1") {
		t.Fatal("exhausted key allowed")
	}
}

func TestLimiterPurgesStaleEntries(t *testing.T) {
	// Arrange
	l := New(rate.Every(time.Hour), 1)
	current := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return current }
	l.Allow("old-key")

	// Act
	current = current.Add(staleAfter + time.Minute)
	l.Allow("new-key")

	// Assert
	if _, ok := l.entries["old-key"]; ok {
		t.Fatal("stale entry was not purged")
	}
}

func peerCtx(addr string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(addr), Port: 12345},
	})
}

func TestInterceptorLimitsOnlyListedMethods(t *testing.T) {
	// Arrange
	limiter := New(rate.Every(time.Hour), 1)
	interceptor := UnaryInterceptor(limiter, map[string]bool{"/svc/Login": true})
	handler := func(context.Context, any) (any, error) { return "ok", nil }

	// Act + Assert
	if _, err := interceptor(peerCtx("9.9.9.9"), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Login"}, handler); err != nil {
		t.Fatalf("first limited call: %v", err)
	}
	_, err := interceptor(peerCtx("9.9.9.9"), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Login"}, handler)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second limited call = %v, want ResourceExhausted", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := interceptor(peerCtx("9.9.9.9"), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/GetSecret"}, handler); err != nil {
			t.Fatalf("unlisted method limited: %v", err)
		}
	}
}
