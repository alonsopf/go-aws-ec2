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
	instanceID, ip, err := ec2.RunInstance("ami-021809d9177640a20", "t2.micro", mySecurityGroup, "/dev/sdh", keyPairName, int64(8))
	fmt.Println(instanceID, ip, err)
	fmt.Println("Associating server instance to IAM Profile...")
        // AmazonSSMRoleForInstancesQuickSetup is the automatic role that was created in the IAM quick setup
	AssociationId, err := ec2.AssociateIAMRole(instanceID, "AmazonSSMRoleForInstancesQuickSetup") 
	fmt.Println(AssociationId, err)
}
```
