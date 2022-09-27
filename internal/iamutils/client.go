package iamutils

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

const (
	// TagKeyRole is used to determine if an IAM user is a Skpr developer.
	TagKeyRole = "skpr.io/role"
)

// Client for interacting with AWS IAM.
type Client struct {
	iam IAM
	// Used for keeping track of IAM users who are Skpr users.
	Users []string
	// Used for keeping track of IAM users who are NOT Skpr users.
	NotUsers []string
}

type IAM interface {
	ListUserTags(context.Context, *iam.ListUserTagsInput, ...func(*iam.Options)) (*iam.ListUserTagsOutput, error)
}

func NewClient(iam IAM) *Client {
	return &Client{iam: iam}
}

// IsUser returns if an ARN references a Skpr platform user.
func (c *Client) IsUser(ctx context.Context, arn string) (bool, error) {
	username, err := extractUsernameFromARN(arn)
	if err != nil {
		return true, fmt.Errorf("failed to extract username: %w", err)
	}

	// Already checked and is not a Skpr user.
	if contains(c.NotUsers, arn) {
		return false, nil
	}

	// Already checked and is a Skpr user.
	if contains(c.Users, arn) {
		return true, nil
	}

	resp, err := c.iam.ListUserTags(ctx, &iam.ListUserTagsInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return false, fmt.Errorf("failed to list user (%s) tags: %w", username, err)
	}

	if hasTag(resp.Tags, TagKeyRole) {
		c.Users = append(c.Users, arn)
	} else {
		c.NotUsers = append(c.NotUsers, arn)
	}

	return c.IsUser(ctx, arn)
}
