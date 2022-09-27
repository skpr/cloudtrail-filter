package processor

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/codedropau/cloudfront-cloudwatchlogs/internal/parser"
)

// ProcessLines processes the gzip buffer line by line.
func ProcessLines(gzipBytes []byte, processEvent func(event types.InputLogEvent) error) error {
	gzipReader, err := gzip.NewReader(bytes.NewBuffer(gzipBytes))
	if err != nil {
		return fmt.Errorf("error reading gzip: %w", err)
	}
	defer gzipReader.Close()

	scanner := bufio.NewScanner(gzipReader)
	for scanner.Scan() {
		if len(scanner.Text()) < 1 {
			// Nothing in this line - probably just a newline.
			continue
		}
		message := string(scanner.Text())
		if strings.HasPrefix(string(message), "#") {
			// Comment - ignore.
			continue
		}
		// Parse date out of cloudfront access log line.
		date, message, err := parser.ParseDateAndMessage(message)
		if err != nil {
			// Couldn't parse date, default to now.
			date = time.Now()
		}
		event := types.InputLogEvent{
			Message:   aws.String(message),
			Timestamp: aws.Int64(date.UnixNano() / int64(time.Millisecond/time.Nanosecond)),
		}
		err = processEvent(event)
		if err != nil {
			return fmt.Errorf("failed to push log event: %w", err)
		}
	}
	return nil
}
