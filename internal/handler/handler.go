package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/skpr/cloudtrail-filter/internal/cloudtrail"
)

// Params passed into this handler.
type Params struct {
	// Bucket which the filtered CloudTrail logs will be stored.
	TargetBucket string
}

// Handler for filtering CloudTrail events.
type Handler struct {
	// Client for interacting with AWS IAM.
	iam IAM
	// Client for interacting with AWS S3.
	s3 *s3.Client
	// Params provided to this handler.
	Params Params
}

// IAM client for determining if an ARN belongs to a platform user.
type IAM interface {
	// IsUser checks if an ARN belongs to a platform user.
	IsUser(context.Context, string) (bool, error)
}

// NewEventHandler for filtering CloudTrail events.
func NewEventHandler(iam IAM, s3 *s3.Client, params Params) *Handler {
	return &Handler{
		iam:    iam,
		s3:     s3,
		Params: params,
	}
}

// HandleEvent received from the Lambda.
func (h *Handler) HandleEvent(ctx context.Context, record events.S3EventRecord) error {
	original, err := h.pullObject(ctx, record)
	if err != nil {
		return fmt.Errorf("failed to pull original CloudTrail records: %w", err)
	}

	filtered, err := h.filterRecords(ctx, original)
	if err != nil {
		return fmt.Errorf("failed to filter CloudTrail records: %w", err)
	}

	err = h.pushObject(ctx, record, filtered)
	if err != nil {
		return fmt.Errorf("failed to push filtered CloudTrail records: %w", err)
	}

	return nil
}

// Helper function to pull CloudTrail Logs object from S3 bucket.
func (h *Handler) pullObject(ctx context.Context, record events.S3EventRecord) (cloudtrail.LogFile, error) {
	var file cloudtrail.LogFile

	head, err := h.s3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(record.S3.Bucket.Name),
		Key:    aws.String(record.S3.Object.Key),
	})
	if err != nil {
		return file, fmt.Errorf("unable to HEAD object: %w", err)
	}

	downloader := manager.NewDownloader(h.s3)

	input := &s3.GetObjectInput{
		Bucket: aws.String(record.S3.Bucket.Name),
		Key:    aws.String(record.S3.Object.Key),
	}

	// Pre-allocate buffer size.
	buf := make([]byte, int(head.ContentLength))

	w := manager.NewWriteAtBuffer(buf)

	_, err = downloader.Download(ctx, w, input)
	if err != nil {
		return file, fmt.Errorf("unable to download object: %w", err)
	}

	if err := json.Unmarshal(w.Bytes(), &file); err != nil {
		return file, fmt.Errorf("failed to marshal object: %w", err)
	}

	return file, nil
}

// Helper function to filter CloudTrail records.
func (h *Handler) filterRecords(ctx context.Context, original cloudtrail.LogFile) (cloudtrail.LogFile, error) {
	var filtered cloudtrail.LogFile

	for _, r := range original.Records {
		bodyBytes, err := json.Marshal(r)
		if err != nil {
			return filtered, err
		}

		var record cloudtrail.Record

		if err := json.Unmarshal(bodyBytes, &record); err != nil {
			return filtered, err
		}

		// Validate that this is an IAM user record. All Skpr users are IAM users.
		// @todo, Verify is this will work for assume role.
		if record.UserIdentity.Type != cloudtrail.UserIdentityTypeIAM {
			continue
		}

		ok, err := h.iam.IsUser(ctx, record.UserIdentity.ARN)
		if err != nil {
			return filtered, fmt.Errorf("failed to determine if ARN belongs to a platform user: %w", err)
		}

		if !ok {
			continue
		}

		// Save it to the new list of records.
		filtered.Records = append(filtered.Records, r)
	}

	return filtered, nil
}

// Helper function to push CloudTrail Logs object to S3 bucket.
func (h *Handler) pushObject(ctx context.Context, record events.S3EventRecord, file cloudtrail.LogFile) error {
	data, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("failed to marshal object: %w", err)
	}

	uploader := manager.NewUploader(h.s3)

	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(h.Params.TargetBucket),
		Key:    aws.String(record.S3.Object.Key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("failed to push object to target bucket: %w", err)
	}

	return nil
}
