package cloudtrail

// LogFile which contains a set of CloudTail records.
type LogFile struct {
	// This is defined as an interface so we don't have to manage all the records fields.
	Records []interface{} `json:"Records"`
}

// Record used to determine the type and ARN of the CloudTrail record.
type Record struct {
	UserIdentity UserIdentity `json:"userIdentity"`
}

// UserIdentity used to determine the type and ARN of the CloudTrail record.
type UserIdentity struct {
	ARN  string `json:"arn"`
	Type string `json:"type"`
}
