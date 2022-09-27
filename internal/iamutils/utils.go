package iamutils

import (
	"fmt"
	"strings"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// Helper function to check if a string exists in a slice.
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}

	return false
}

// Helper function that checks if a user has a tag with a specific key.
func hasTag(tags []iamtypes.Tag, key string) bool {
	for _, tag := range tags {
		if *tag.Key == key {
			return true
		}
	}

	return false
}

// Helper function that returns the username from an ARN.
func extractUsernameFromARN(arn string) (string, error) {
	a, err := awsarn.Parse(arn)
	if err != nil {
		return "", fmt.Errorf("failed to parse ARN: %w", err)
	}

	sl := strings.Split(a.Resource, "/")

	if len(sl) != 2 {
		return "", fmt.Errorf("failed to parse ARN: %w", err)
	}

	if sl[0] != "user" {
		return "", fmt.Errorf("failed to parse ARN: %w", err)
	}

	return sl[1], nil
}
