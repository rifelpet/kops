package awsinterfaces

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

type SSMAPI interface {
	GetParameter(ctx context.Context, input *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}
