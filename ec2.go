package ec2

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

type keys struct {
	AwsRegion          string
	AwsAccessKeyID     string
	AwsSecretAccessKey string
}

var secretKeys keys

// Init is for setting the aws secret keys
func Init(region, accessKey, secretKey string) {
	secretKeys = keys{region, accessKey, secretKey}
}

// RunInstance create a server instance, and return the instanceID, ip, or error if fails.
// You must provide the ami id, for example: "ami-0e4035ae3f70c400f", the instanceType too, such as "t2.micro"
// and your securityGroupID: "sg-00000000", also the gbSize is the disk space in gigabytes
func RunInstance(ami, instanceType, securityGroupID, deviceName, keyPairName string, gbSize int64) (string, string, error) {
	awsConnect, err := session.NewSession(&aws.Config{
		Region: aws.String(secretKeys.AwsRegion),
		Credentials: credentials.NewStaticCredentials(
			secretKeys.AwsAccessKeyID, secretKeys.AwsSecretAccessKey, ""),
	})

	if err != nil {
		return "", "", err
	}

	svc := ec2.New(awsConnect)

	input := &ec2.RunInstancesInput{
		BlockDeviceMappings: []*ec2.BlockDeviceMapping{
			{
				DeviceName: aws.String(deviceName),
				Ebs: &ec2.EbsBlockDevice{
					VolumeSize: aws.Int64(gbSize),
				},
			},
		},
		ImageId:      aws.String(ami),
		InstanceType: aws.String(instanceType),
		KeyName:      aws.String(keyPairName),
		MaxCount:     aws.Int64(1),
		MinCount:     aws.Int64(1),
		SecurityGroupIds: []*string{
			aws.String(securityGroupID),
		},
	}
	result, err := svc.RunInstances(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return "", "", err
	}
	//fmt.Println(result)
	fmt.Println("waiting for ip public address")
	inputDescribe := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(*result.Instances[0].InstanceId),
		},
	}
	ticker := time.NewTicker(10 * time.Second)
	quit := make(chan struct{})
	for {
		select {
		case <-ticker.C:
			resultDescribe, err := svc.DescribeInstances(inputDescribe)
			if err != nil {
				if aerr, ok := err.(awserr.Error); ok {
					switch aerr.Code() {
					default:
						fmt.Println(aerr.Error())
					}
				} else {
					// Print the error, cast err to awserr.Error to get the Code and
					// Message from an error.
					fmt.Println(err.Error())
				}
				return "", "", err
			}
			if *resultDescribe.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.Status != "attaching" {
				fmt.Println(resultDescribe)
				ticker.Stop()
				return *result.Instances[0].InstanceId, *resultDescribe.Reservations[0].Instances[0].PublicIpAddress, nil
			}
		case <-quit:
			ticker.Stop()
			return "", "", nil
		}
	}

	return *result.Instances[0].InstanceId, "no-ip", nil
}

// CreateAWSKeyPair allows you create your key pair if needed
func CreateAWSKeyPair(keyName string) (string, string, string, error) {
	awsConnect, err := session.NewSession(&aws.Config{
		Region: aws.String(secretKeys.AwsRegion),
		Credentials: credentials.NewStaticCredentials(
			secretKeys.AwsAccessKeyID, secretKeys.AwsSecretAccessKey, ""),
	})

	if err != nil {
		return "", "", "", err
	}

	svc := ec2.New(awsConnect)

	input := &ec2.CreateKeyPairInput{
		KeyName: aws.String(keyName),
	}
	result, err := svc.CreateKeyPair(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return "", "", "", err
	}

	return *result.KeyFingerprint, *result.KeyMaterial, *result.KeyPairId, nil
}
