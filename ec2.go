package ec2

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/iam"

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

func newAWSSession() (*session.Session, error) {
	awsConnect, err := session.NewSession(&aws.Config{
		Region: aws.String(secretKeys.AwsRegion),
		Credentials: credentials.NewStaticCredentials(
			secretKeys.AwsAccessKeyID, secretKeys.AwsSecretAccessKey, ""),
	})
	if err != nil {
		return nil, err
	}
	return awsConnect, nil
}

//CreateRepository allows you create a new repository in aws ErrCodeResourceInUseException
func CreateRepository(name string) (string, error) {
	awsConnect, err := newAWSSession()
	if err != nil {
		return "", err
	}
	svc := ecr.New(awsConnect)
	input := &ecr.CreateRepositoryInput{
		RepositoryName: aws.String(name),
	}
	result, err := svc.CreateRepository(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ecr.ErrCodeServerException:
				fmt.Println(ecr.ErrCodeServerException, aerr.Error())
			case ecr.ErrCodeInvalidParameterException:
				fmt.Println(ecr.ErrCodeInvalidParameterException, aerr.Error())
			case ecr.ErrCodeInvalidTagParameterException:
				fmt.Println(ecr.ErrCodeInvalidTagParameterException, aerr.Error())
			case ecr.ErrCodeTooManyTagsException:
				fmt.Println(ecr.ErrCodeTooManyTagsException, aerr.Error())
			case ecr.ErrCodeRepositoryAlreadyExistsException:
				fmt.Println(ecr.ErrCodeRepositoryAlreadyExistsException, aerr.Error())
			case ecr.ErrCodeLimitExceededException:
				fmt.Println(ecr.ErrCodeLimitExceededException, aerr.Error())
			case ecr.ErrCodeKmsException:
				fmt.Println(ecr.ErrCodeKmsException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return "", err
	}
	fmt.Println(result)
	return "", nil
}

//GetIAMRoleARN allows you create a new Kubernetes cluster
func GetIAMRoleARN(name string) (string, error) {
	awsConnect, err := newAWSSession()
	if err != nil {
		return "", err
	}
	svc := iam.New(awsConnect)
	input := &iam.GetRoleInput{
		RoleName: aws.String(name),
	}

	result, err := svc.GetRole(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return "", err
	}

	fmt.Println(result)
	return *result.Role.Arn, nil
}

//CreateKubernetesCluster allows you create a new Kubernetes cluster
func CreateKubernetesCluster(version, securityGroupID, name, roleArn, uuid, subnetIds string) (string, error) {
	awsConnect, err := newAWSSession()
	if err != nil {
		return "", err
	}
	svc := eks.New(awsConnect)
	subnets := make([]*string, 0)
	for _, v := range strings.Split(subnetIds, "|") {
		subnets = append(subnets, aws.String(v))
	}
	input := &eks.CreateClusterInput{
		ClientRequestToken: aws.String(uuid),
		Name:               aws.String(name),
		ResourcesVpcConfig: &eks.VpcConfigRequest{
			SecurityGroupIds: []*string{
				aws.String(securityGroupID),
			},
			SubnetIds: subnets,
		},
		RoleArn: aws.String(roleArn),
		Version: aws.String(version),
	}

	result, err := svc.CreateCluster(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case eks.ErrCodeResourceInUseException:
				fmt.Println(eks.ErrCodeResourceInUseException, aerr.Error())
			case eks.ErrCodeResourceLimitExceededException:
				fmt.Println(eks.ErrCodeResourceLimitExceededException, aerr.Error())
			case eks.ErrCodeInvalidParameterException:
				fmt.Println(eks.ErrCodeInvalidParameterException, aerr.Error())
			case eks.ErrCodeClientException:
				fmt.Println(eks.ErrCodeClientException, aerr.Error())
			case eks.ErrCodeServerException:
				fmt.Println(eks.ErrCodeServerException, aerr.Error())
			case eks.ErrCodeServiceUnavailableException:
				fmt.Println(eks.ErrCodeServiceUnavailableException, aerr.Error())
			case eks.ErrCodeUnsupportedAvailabilityZoneException:
				fmt.Println(eks.ErrCodeUnsupportedAvailabilityZoneException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return "", err
	}
	fmt.Println(result)
	return "", nil
}

// CreateInstanceAndUploadDockerImage create a server instance, and return the instanceID, public dns, or error if fails.
// You must provide the ami id, for example: "ami-0e4035ae3f70c400f", the instanceType too, such as "t2.micro"
// and your securityGroupID: "sg-00000000", also the gbSize is the disk space in gigabytes
func CreateInstanceAndUploadDockerImage(ami, instanceType, securityGroupID, deviceName, keyPairName, dockerUser, passDocker, dockerImgName string, gbSize int64) (string, string, error) {
	awsConnect, err := newAWSSession()
	if err != nil {
		return "", "", err
	}
	svc := ec2.New(awsConnect)
	//#!/bin/bash -ex
	sh := `mkdir hello
	sudo yum update -y
	sudo amazon-linux-extras install docker
	sudo service docker start
	sudo usermod -a -G docker ec2-user
	sudo yum install -y golang
	mkdir src
	cd src
	cat > main.go << EOF
	package main
import (
	    "fmt"
	    "net/http"
)
	func main() {
	    http.HandleFunc("/", HelloServer)
	    http.ListenAndServe(":8080", nil)
	    fmt.Println("server running in 8080")
	}
	func HelloServer(w http.ResponseWriter, r *http.Request) {
	    fmt.Fprintf(w, "Hello, DevOps!")
	    fmt.Println("awesome!")
	}
	EOF
	go build -o bin/main
	cat > Dockerfile << EOF
	FROM golang:latest
	LABEL author="` + dockerUser + `"
	# Set the Current Working Directory inside the container
	WORKDIR /
	# Copy the source from the current directory to the Working Directory inside the container
	COPY . .
	# Build the Go app
	RUN go build -o main .
	# Expose port 8080 to the outside world
	EXPOSE 8080
	# Command to run the executable
	CMD ["./main"]
	EOF
	sudo groupadd docker
	sudo docker build --tag testimage1 .
	sudo docker run -d -p 8080:8080 testimage1
	sudo docker login --username=` + dockerUser + ` --password=` + passDocker + `
	export DOCKER_IMAGE_IDS=$(sudo docker images --format "{{.ID}}")
	IFS=' ' read -ra ADDR <<< "$DOCKER_IMAGE_IDS"
	for i in "${ADDR[@]}"; do
	sudo docker tag $ADDR alonsopf/` + dockerImgName + `:0.1
	sudo docker push ` + dockerUser + `/` + dockerImgName + ``
	base64Text := base64.StdEncoding.EncodeToString([]byte(sh))
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
		UserData: aws.String(base64Text),
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
				ticker.Stop()
				return *result.Instances[0].InstanceId, *resultDescribe.Reservations[0].Instances[0].PublicDnsName, nil
			}
		case <-quit:
			ticker.Stop()
			return "", "", nil
		}
	}
	//return *result.Instances[0].InstanceId, "no-ip", nil
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
		fmt.Println("the instance is just starting.. please wait")
		select {
		case <-time.After(15 * time.Second):
			return InstallGo(fileNamePem, user, publicDNS)
		}
	}
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		fmt.Println("3")
		return err
	}
	defer session.Close()
	//var stdoutBuf bytes.Buffer
	//session.Stdout = &stdoutBuf

	executeShell("sudo snap install go --classic", session)
	executeShell("mkdir src", session)
	executeShell("cd src", session)
	executeShell("mkdir main", session)
	executeShell("cd main", session)

	/*executeShell("curl -O https://dl.google.com/go/go1.15.4.linux-amd64.tar.gz", session)
	executeShell("tar xvf go1.15.4.linux-amd64.tar.gz", session)
	executeShell("sudo chown -R root:root ./go", session)
	executeShell("sudo mv go /usr/local", session)
	executeShell("sudo nano ~/.profile", session)
	executeShell("\033[B", session)
	executeShell("\033[B", session)
	executeShell("\033[B", session)
	executeShell("\033[B", session)
	executeShell("\033[B", session)
	executeShell("\033[B", session)
	executeShell("\033[B", session)
	executeShell("\033[B", session)
	executeShell("\033[B", session)
	executeShell("\033[B", session)
	executeShell("export GOPATH=$HOME/work", session)
	executeShell("export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin", session)
	executeShell("source ~/.profile", session)
	/*executeShell("mkdir work", session)

	executeShell("cd work", session)
	executeShell("mkdir src", session)
	executeShell("cd src", session)
	executeShell("mkdir main", session)
	executeShell("cd main", session)
	executeShell("sudo nano main.go", session)
	executeShell("sudo nano main.go", session)*/
	err = session.Run("go version")
	if err != nil {
		return err
	}
	//fmt.Println("%s", stdoutBuf.String())
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
	awsConnect, err := newAWSSession()
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
	awsConnect, err := newAWSSession()
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
