package ec2

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

	//"github.com/aws/aws-sdk-go/service/ec2instanceconnect"
	"golang.org/x/crypto/ssh"
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

// RunInstance create a server instance, and return the instanceID, public dns, or error if fails.
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
			fmt.Println(err.Error())
		}
		return "", "", err
	}
	/*fmt.Println("Assigning ipv6 public address")
	inputIPV6 := &ec2.AssignIpv6AddressesInput{
		Ipv6AddressCount : aws.Int64(1),
		NetworkInterfaceId: aws.String(*result.Instances[0].NetworkInterfaces[0].NetworkInterfaceId),
	}
	resultIPV6, err := svc.AssignIpv6Addresses(inputIPV6)
	if err != nil {
		return "", "", err
	}
	fmt.Println(resultIPV6)
	*/

	fmt.Println("Waiting for public DNS")
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
					fmt.Println(err.Error())
				}
				return "", "", err
			}
			if *resultDescribe.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.Status != "attaching" {
				fmt.Println(resultDescribe)
				/*fmt.Println("Assigning ipv6 public address")
				inputIPV6 := &ec2.AssignIpv6AddressesInput{
					Ipv6AddressCount : aws.Int64(1),
					NetworkInterfaceId: aws.String(*result.Instances[0].NetworkInterfaces[0].NetworkInterfaceId),
				}
				fmt.Println(resultIPV6)
				resultIPV6, err := svc.AssignIpv6Addresses(inputIPV6)
				if err != nil {
					return "", "", err
				}
				fmt.Println(resultIPV6)*/
				ticker.Stop()
				return *result.Instances[0].InstanceId, *resultDescribe.Reservations[0].Instances[0].PublicDnsName, nil
			}
		case <-quit:
			ticker.Stop()
			return "", "", nil
		}
	}
	return *result.Instances[0].InstanceId, "no-ip", nil
}

// SendSSHPublicKey pushes an SSH public key to a particular OS user on a given EC2 instance for 60 seconds
/*func SendSSHPublicKey(instanceID, instanceOSUser, keyMaterial string) error {
	awsConnect, err := session.NewSession(&aws.Config{
		Region: aws.String(secretKeys.AwsRegion),
		Credentials: credentials.NewStaticCredentials(
			secretKeys.AwsAccessKeyID, secretKeys.AwsSecretAccessKey, ""),
	})

	if err != nil {
		return err
	}
	svc := ec2instanceconnect.New(awsConnect)
	fmt.Println("ssh-rsa "+keyMaterial)
	input := &ec2instanceconnect.SendSSHPublicKeyInput{
        AvailabilityZone: aws.String(secretKeys.AwsRegion),
        InstanceId:       aws.String(instanceID),
        InstanceOSUser:   aws.String(instanceOSUser),
        SSHPublicKey:     aws.String("ssh-rsa "+keyMaterial),
    }

    result, err := svc.SendSSHPublicKey(input)
    if err != nil {
        if aerr, ok := err.(awserr.Error); ok {
            switch aerr.Code() {
            case ec2instanceconnect.ErrCodeAuthException:
                fmt.Println(ec2instanceconnect.ErrCodeAuthException, aerr.Error())
            case ec2instanceconnect.ErrCodeInvalidArgsException:
                fmt.Println(ec2instanceconnect.ErrCodeInvalidArgsException, aerr.Error())
            case ec2instanceconnect.ErrCodeServiceException:
                fmt.Println(ec2instanceconnect.ErrCodeServiceException, aerr.Error())
            case ec2instanceconnect.ErrCodeThrottlingException:
                fmt.Println(ec2instanceconnect.ErrCodeThrottlingException, aerr.Error())
            case ec2instanceconnect.ErrCodeEC2InstanceNotFoundException:
                fmt.Println(ec2instanceconnect.ErrCodeEC2InstanceNotFoundException, aerr.Error())
            default:
                fmt.Println(aerr.Error())
            }
        } else {
            // Print the error, cast err to awserr.Error to get the Code and
            // Message from an error.
            fmt.Println(err.Error())
        }
        return err
    }

    fmt.Println(result)
    return nil
}*/

//InstallGo install golang in your server (under development)
func InstallGo(fileNamePem, user, publicDNS string) error {
	pemBytes, err := ioutil.ReadFile(fileNamePem)
	if err != nil {
		fmt.Println("0")
		return err
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		fmt.Println("1")
		return err
	}
	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
	}
	conn, err := ssh.Dial("tcp", publicDNS+":22", config)
	if err != nil {
		fmt.Println("2")
		return err
	}
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		fmt.Println("3")
		return err
	}
	defer session.Close()
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	executeShell("curl -O https://dl.google.com/go/go1.15.4.linux-amd64.tar.gz", session)
	executeShell("tar xvf go1.10.3.linux-amd64.tar.gz", session)
	executeShell("sudo chown -R root:root ./go", session)
	executeShell("sudo mv go /usr/local", session)
	executeShell("sudo nano ~/.profile", session)
	executeShell("export GOPATH=$HOME/work", session)
	executeShell("export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin", session)
	executeShell("source ~/.profile", session)

	fmt.Println("%s", stdoutBuf.String())
	return nil
}

func executeShell(cmd string, session *ssh.Session) error {
	err := (*session).Run(cmd)
	if err != nil {
		return err
	}
	return nil
}

// AssociateIAMRole allows you connect your IAM role to your instance
func AssociateIAMRole(instanceID, iamRole string) (string, error) {
	awsConnect, err := session.NewSession(&aws.Config{
		Region: aws.String(secretKeys.AwsRegion),
		Credentials: credentials.NewStaticCredentials(
			secretKeys.AwsAccessKeyID, secretKeys.AwsSecretAccessKey, ""),
	})

	if err != nil {
		return "", err
	}
	svc := ec2.New(awsConnect)
	input := &ec2.AssociateIamInstanceProfileInput{
		IamInstanceProfile: &ec2.IamInstanceProfileSpecification{
			Name: aws.String(iamRole),
		},
		InstanceId: aws.String(instanceID),
	}

	result, err := svc.AssociateIamInstanceProfile(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
		return "", err
	}
	fmt.Println(result)
	return *result.IamInstanceProfileAssociation.AssociationId, nil
}

// CreateAWSKeyPair allows you create your key pair if needed
// set option to 1 if you want to save the pem file to disk
func CreateAWSKeyPair(keyName string, option int) (string, string, string, error) {
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

	if option == 1 {
		f, _ := os.Create(keyName + ".pem")
		defer f.Close()
		w := bufio.NewWriter(f)
		fmt.Fprintf(w, "%v\n", *result.KeyMaterial)
		w.Flush()
		os.Chmod(keyName+".pem", 0700)
	}

	return *result.KeyFingerprint, *result.KeyMaterial, *result.KeyPairId, nil
}
