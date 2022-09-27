package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/skpr/cloudtrail-filter/internal/handler"
	"github.com/skpr/cloudtrail-filter/internal/iamutils"
)

func main() {
	lambda.Start(HandleEvents)
}

// HandleEvents sent from AWS S3.
func HandleEvents(ctx context.Context, event events.S3Event) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to setup client: %d", err)
	}

	eventHandler := handler.NewEventHandler(
		iamutils.NewClient(iam.NewFromConfig(cfg)),
		s3.NewFromConfig(cfg),
		handler.Params{
			TargetBucket: os.Getenv("CLOUDTRAIL_FILTER_TARGET_BUCKET"),
		})

	for _, record := range event.Records {
		fmt.Printf("[%s - %s] Bucket = %s, Key = %s \n", record.EventSource, record.EventTime, record.S3.Bucket.Name, record.S3.Object.Key)

		err := eventHandler.HandleEvent(ctx, record)
		if err != nil {
			return err
		}
	}

	return nil
}
