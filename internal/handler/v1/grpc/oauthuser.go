package grpchandlerv1

import (
	"context"

	"github.com/google/uuid"
	authv1 "github.com/mandacode-com/accounts-proto/go/auth/v1"
	"github.com/mandacode-com/golib/errors"
	"github.com/mandacode-com/golib/errors/errcode"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
	"mandacode.com/accounts/auth/internal/usecase/authuser"
	"mandacode.com/accounts/auth/internal/util"
)

type OAuthUserHandler struct {
	authv1.UnimplementedOAuthUserServiceServer
	userUsecase authuser.OAuthUserUsecase
	logger      *zap.Logger
}

// CreateOAuthUser implements authv1.OAuthUserServiceServer.
func (o *OAuthUserHandler) CreateOAuthUser(ctx context.Context, req *authv1.CreateOAuthUserRequest) (*authv1.CreateOAuthUserResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, errors.Upgrade(err, "CreateOAuthUser request validation failed", errcode.ErrInvalidFormat)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, errors.Upgrade(err, "Invalid user ID format", errcode.ErrInvalidFormat)
	}

	entProvider, err := util.FromProtoToEnt(req.Provider)
	if err != nil {
		return nil, err
	}

	createdUser, err := o.userUsecase.CreateOAuthUser(ctx, userID, entProvider, req.AccessToken, req.Code)
	if err != nil {
		return nil, err
	}

	return &authv1.CreateOAuthUserResponse{
		UserId:     createdUser.UserID.String(),
		Provider:   req.Provider,
		ProviderId: createdUser.ProviderID,
		Email:      createdUser.Email,
		Verified:   createdUser.IsVerified,
		CreatedAt:  timestamppb.Now(),
	}, nil
}

// DeleteOAuthUser implements authv1.OAuthUserServiceServer.
func (o *OAuthUserHandler) DeleteOAuthUser(ctx context.Context, req *authv1.DeleteOAuthUserRequest) (*authv1.DeleteOAuthUserResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, errors.Upgrade(err, "DeleteOAuthUser request validation failed", errcode.ErrInvalidFormat)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, errors.Upgrade(err, "Invalid user ID format", errcode.ErrInvalidFormat)
	}

	err = o.userUsecase.DeleteOAuthUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &authv1.DeleteOAuthUserResponse{
		UserId:    req.UserId,
		Provider:  req.Provider,
		DeletedAt: timestamppb.Now(),
	}, nil
}

// SyncOAuthUser implements authv1.OAuthUserServiceServer.
func (o *OAuthUserHandler) SyncOAuthUser(ctx context.Context, req *authv1.SyncOAuthUserRequest) (*authv1.SyncOAuthUserResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, errors.Upgrade(err, "SyncOAuthUser request validation failed", errcode.ErrInvalidFormat)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, errors.Upgrade(err, "Invalid user ID format", errcode.ErrInvalidFormat)
	}

	entProvider, err := util.FromProtoToEnt(req.Provider)
	if err != nil {
		return nil, errors.Upgrade(err, "Invalid provider format", errcode.ErrInvalidFormat)
	}

	updatedUser, err := o.userUsecase.SyncOAuthUser(ctx, userID, entProvider, req.AccessToken, req.Code)
	if err != nil {
		return nil, err
	}
	return &authv1.SyncOAuthUserResponse{
		UserId:   updatedUser.UserID.String(),
		Provider: req.Provider,
		SyncedAt: timestamppb.Now(),
	}, nil
}

// NewUserHandler creates a new UserHandler with the provided use case and logger.
func NewOAuthUserHandler(userUsecase authuser.OAuthUserUsecase, logger *zap.Logger) authv1.OAuthUserServiceServer {
	return &OAuthUserHandler{
		userUsecase: userUsecase,
		logger:      logger,
	}
}
