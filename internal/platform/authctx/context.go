package authctx

import (
	"context"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type userIDKey struct{}

func WithUserID(ctx context.Context, id vo.UserID) context.Context {
	return context.WithValue(ctx, userIDKey{}, id)
}

func UserIDFromContext(ctx context.Context) (vo.UserID, bool) {
	id, ok := ctx.Value(userIDKey{}).(vo.UserID)
	if !ok || id.IsZero() {
		return vo.UserID{}, false
	}
	return id, true
}
