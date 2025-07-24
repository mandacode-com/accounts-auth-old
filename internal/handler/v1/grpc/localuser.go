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
)

type LocalUserHandler struct {
	authv1.UnimplementedLocalUserServiceServer
	userUsecase authuser.LocalUserUsecase
	logger      *zap.Logger
}

// UpdateEmailVerification implements authv1.LocalUserServiceServer.
func (l *LocalUserHandler) UpdateEmailVerification(ctx context.Context, req *authv1.UpdateEmailVerificationRequest) (*authv1.UpdateEmailVerificationResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, errors.Upgrade(err, "UpdateEmailVerification request validation failed", errcode.ErrInvalidFormat)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, errors.Upgrade(err, "Invalid user ID format", errcode.ErrInvalidFormat)
	}

	err = l.userUsecase.UpdateLocalEmailVerificationStatus(ctx, userID, req.Verified)
	if err != nil {
		return nil, err
	}

	return &authv1.UpdateEmailVerificationResponse{
		UserId:    req.UserId,
		Verified:  req.Verified,
		UpdatedAt: timestamppb.Now(),
	}, nil
}

// CreateLocalUser implements authv1.LocalUserServiceServer.
func (l *LocalUserHandler) CreateLocalUser(ctx context.Context, req *authv1.CreateLocalUserRequest) (*authv1.CreateLocalUserResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, errors.Upgrade(err, "CreateLocalUser request validation failed", errcode.ErrInvalidFormat)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, errors.Upgrade(err, "Invalid user ID format", errcode.ErrInvalidFormat)
	}

	createdUser, err := l.userUsecase.CreateLocalAuthUser(ctx, userID, req.Email, req.Password)
	if err != nil {
		return nil, err
	}

	return &authv1.CreateLocalUserResponse{
		UserId:    createdUser.UserID.String(),
		CreatedAt: timestamppb.Now(),
	}, nil
}

// DeleteLocalUser implements authv1.LocalUserServiceServer.
func (l *LocalUserHandler) DeleteLocalUser(ctx context.Context, req *authv1.DeleteLocalUserRequest) (*authv1.DeleteLocalUserResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, errors.Upgrade(err, "DeleteLocalUser request validation failed", errcode.ErrInvalidFormat)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, errors.Upgrade(err, "Invalid user ID format", errcode.ErrInvalidFormat)
	}

	err = l.userUsecase.DeleteAuthUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &authv1.DeleteLocalUserResponse{
		UserId:    req.UserId,
		DeletedAt: timestamppb.Now(),
	}, nil
}

// UpdateLocalUserEmail implements authv1.LocalUserServiceServer.
func (l *LocalUserHandler) UpdateLocalUserEmail(ctx context.Context, req *authv1.UpdateLocalUserEmailRequest) (*authv1.UpdateLocalUserEmailResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, errors.Upgrade(err, "UpdateLocalUserEmail request validation failed", errcode.ErrInvalidFormat)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, errors.Upgrade(err, "Invalid user ID format", errcode.ErrInvalidFormat)
	}

	updatedUser, err := l.userUsecase.UpdateAuthUserEmail(ctx, userID, req.NewEmail)
	if err != nil {
		return nil, err
	}

	return &authv1.UpdateLocalUserEmailResponse{
		UserId:       updatedUser.UserID.String(),
		UpdatedEmail: updatedUser.Email,
		UpdatedAt:    timestamppb.Now(),
	}, nil
}

// NewUserHandler creates a new UserHandler with the provided use case and logger.
func NewLocalUserHandler(userUsecase authuser.LocalUserUsecase, logger *zap.Logger) authv1.LocalUserServiceServer {
	return &LocalUserHandler{
		userUsecase: userUsecase,
		logger:      logger,
	}
}
