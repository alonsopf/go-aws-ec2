# go-aws-ec2

# Golang aws ec2 api wrapper

Example of use
```golang
package main

import (
    "fmt"
    ec2 "github.com/alonsopf/go-aws-ec2"
)

func main() {
	ec2.Init("us-west-1","AwsAccessKeyID", "AwsSecretAccessKey")
	//only if needed create a key pair
	keyPairName := "my-new-secret-key"
	fmt.Println("Creating key pair...")
	keyFingerprint, keyMaterial, keyPairId, err := ec2.CreateAWSKeyPair(keyPairName, 1) // 1 is create pem file
	fmt.Println(keyFingerprint, keyMaterial, keyPairId)

	fmt.Println("Creating server instance...")
	mySecurityGroup := "sg-00000000"
	instanceID, publicDNS, err := aws.CreateInstanceAndUploadDockerImage("ami-0e4035ae3f70c400f", "t2.micro", mySecurityGroup, "/dev/sdh", keyPairName, "dockerUser", "dockerPass", "nameImgDocker", int64(8))
	fmt.Println(instanceID, ip, err)
	fmt.Println("Associating server instance to IAM Profile...")
        // AmazonSSMRoleForInstancesQuickSetup is the automatic role that was created in the IAM quick setup
	AssociationId, err := ec2.AssociateIAMRole(instanceID, "AmazonSSMRoleForInstancesQuickSetup") 
	fmt.Println(AssociationId, err)
	
	/*
	//create ecr repository
	res, err := aws.CreateRepository("alonsopf/test")
	fmt.Println(res, err)

	//create kubernetes cluster
	subnetIds := "subnet-b061adea|subnet-d7dd6eb1"
	roleArn, err := aws.GetIAMRoleARN("testIAM")
	fmt.Println(roleArn, err)
	status, err := aws.CreateKubernetesCluster("1.17", mySecurityGroup, "tekton", roleArn, uid, subnetIds) 
	fmt.Println(status, err)
	*/
}
```
