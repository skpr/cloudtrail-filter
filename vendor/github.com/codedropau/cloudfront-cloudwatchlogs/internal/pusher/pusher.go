package pusher

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/prometheus/common/log"

	"github.com/codedropau/cloudfront-cloudwatchlogs/internal/types"
	"github.com/codedropau/cloudfront-cloudwatchlogs/internal/utils"
)

// BatchLogPusher cwLogsClient for handling log events.
// @TODO convert into lib reused by fluentbit-cloudwatchlogs
type BatchLogPusher struct {
	// log for logging.
	log log.Logger
	// BatchLogPusher for interacting with CloudWatch Logs.
	cwLogsClient types.CloudwatchLogsInterface
	// Amount of events to keep before flushing.
	batchSize int
	// input is the put log events input.
	input *cloudwatchlogs.PutLogEventsInput
	// eventsSize of the current batch in bytes.
	eventsSize int64
	// Lock to ensure logs are handled by only 1 process.
	lock sync.Mutex
}

// NewBatchLogPusher creates a new batch log pusher.
func NewBatchLogPusher(ctx context.Context, logger log.Logger, cwLogsClient types.CloudwatchLogsInterface, group, stream string, batchSize int) (*BatchLogPusher) {
	pusher := &BatchLogPusher{
		log:          logger,
		input: &cloudwatchlogs.PutLogEventsInput{
			LogEvents:     []awstypes.InputLogEvent{},
			LogGroupName:  aws.String(group),
			LogStreamName: aws.String(stream),
			SequenceToken: nil,
		},
		cwLogsClient: cwLogsClient,
		batchSize:    batchSize,
	}
	return pusher
}

// Add event to the cwLogsClient.
func (p *BatchLogPusher) Add(ctx context.Context, event awstypes.InputLogEvent) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if len(p.input.LogEvents) >= p.batchSize {
		err:= p.Flush(ctx)
		if err != nil {
			return err
		}
	}

	p.input.LogEvents = append(p.input.LogEvents, event)
	p.updateEventsSize(event)

	return nil
}

// Flush events stored in the cwLogsClient.
func (p *BatchLogPusher) Flush(ctx context.Context) error {
	// Return early if there are no events to push.
	if len(p.input.LogEvents) == 0 {
		return nil
	}

	payloadSize := p.calculatePayloadSize()
	p.log.Infof("Pushing %v log events with payload of %s", len(p.input.LogEvents), utils.ByteCountBinary(payloadSize))

	// Sort events chronologically.
	p.sortEvents()

	err := p.putLogEvents(ctx)
	if err != nil {
		return err
	}

	// Reset the events buffer.
	p.clearEvents()

	return nil
}

// PutLogEvents will attempt to execute and handle invalid tokens.
func (p *BatchLogPusher) putLogEvents(ctx context.Context) error {
	out, err := p.cwLogsClient.PutLogEvents(ctx, p.input)
	if err != nil {
		var seqTokenError *awstypes.InvalidSequenceTokenException
		if errors.As(err, &seqTokenError) {
			p.log.Infof("Invalid token. Refreshing", &p.input.LogGroupName, &p.input.LogStreamName)
			p.input.SequenceToken = seqTokenError.ExpectedSequenceToken
			return p.putLogEvents(ctx)
		}
		var alreadyAccErr *awstypes.DataAlreadyAcceptedException
		if errors.As(err, &alreadyAccErr) {
			p.log.Infof("Data already accepted. Refreshing", &p.input.LogGroupName, &p.input.LogStreamName)
			p.input.SequenceToken = alreadyAccErr.ExpectedSequenceToken
			return p.putLogEvents(ctx)
		}
		return err
	}
	// Set the next sequence token.
	p.input.SequenceToken = out.NextSequenceToken

	return nil
}

// CreateLogGroup will attempt to create a log group and not return an error if it already exists.
func (p *BatchLogPusher) CreateLogGroup(ctx context.Context, group string) error {
	_, err := p.cwLogsClient.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(group),
	})
	if err != nil {
		var awsErr *awstypes.ResourceAlreadyExistsException
		if errors.As(err, &awsErr) {
			return nil
		}
		return err
	}

	return nil
}

// CreateLogStream will attempt to create a log stream and not return an error if it already exists.
func (p *BatchLogPusher) CreateLogStream(ctx context.Context, group, stream string) error {
	_, err := p.cwLogsClient.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(group),
		LogStreamName: aws.String(stream),
	})
	if err != nil {
		var awsErr *awstypes.ResourceAlreadyExistsException
		if errors.As(err, &awsErr) {
			return nil
		}
		return err
	}

	return nil
}

func (p *BatchLogPusher) updateEventsSize(event awstypes.InputLogEvent) {
	line := int64(len(*event.Message))
	p.eventsSize = p.eventsSize + line
}

// calculatePayloadSize calculates the approximate payload size.
func (p *BatchLogPusher) calculatePayloadSize() int64 {
	// size is calculated as the sum of all event messages in UTF-8, plus 26 bytes for each log event.
	bytesOverhead := (len(p.input.LogEvents) + 1) * 26
	return p.eventsSize + int64(bytesOverhead)
}

// clearEvents clears the events buffer.
func (p *BatchLogPusher) clearEvents() {
	p.input.LogEvents = []awstypes.InputLogEvent{}
	p.eventsSize = 0
}

// sortEvents chronologically.
func (p *BatchLogPusher) sortEvents() {
	sort.Slice(p.input.LogEvents, func(i, j int) bool {
		a := *p.input.LogEvents[i].Timestamp
		b := *p.input.LogEvents[j].Timestamp
		return a < b
	})
}
