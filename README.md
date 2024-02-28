# Trend Micro Vision File Security (Aka Antimalware as a Service or AmaaS)

This project demonstrates a custom use case utilizing Trend Micro File Security SDK to scan files for malware on a host without any agent. The provided Python script serves as a reference implementation.

## Prerequisites

- Ensure you have an API key with a role that allows scanning files in the File Security service in Vision One.
- Install the File Security SDK:

Usage
```bash
python -m pip install visionone-filesecurity
```

## Script Description

The script scans files in a specified directory with optional exclusion of certain file types. It connects to the Trend Micro File Security service using gRPC.

## Script Features

- Dynamic Logging: Logs are generated dynamically with each run, timestamped for reference.
- Metadata Retrieval: Retrieves instance metadata and fully qualified domain name (FQDN) if available.
- AWS Integration: Utilizes boto3 library to access AWS services and fetch EC2 instance metadata.

## Script Arguments

```--directory (-d): Specify the directory to scan.
--exclude (-e): Specify file types to exclude from scanning.
--addr: Specify the gRPC server address and port (default 127.0.0.1:50051).
--region: Specify the AMaaS service region (e.g., us-1 or dev).
--api_key: Provide the API key for authentication.
--tls: Enable TLS for gRPC communication.
--ca_cert: Provide the CA certificate if TLS is enabled.
--tags: Specify tags in the format "key=value" for file scanning.
```

## Usage example

bash
```
python3 client_dir_hostname_ec2.py --region us-east-1 --tls=true --directory /tmp/v1fs/test_files003/ --api_key YOUR_API_KEY --tags "project=firefly" --exclude git ova
```

Output Summary

Upon completion, the script provides a summary including:

- Host information
- Scan details (scanned files, excluded files, malicious files, clean files)
- Execution time
- Log file location

### Output example
bash
```
$ python3 client_dir_hostname_ec2.py --region us-east-1 --tls=true --directory /tmp/v1fs/test_files003/ --api_key $TMFS_API_KEY --tags "project=firefly" --exclude git ova
Scanning files...
/tmp/v1fs/test_files003/eicar.com ...
/tmp/v1fs/test_files003/file_119.txt ...
/tmp/v1fs/test_files003/file_118.txt ...
/tmp/v1fs/test_files003/file_117.txt ...
/tmp/v1fs/test_files003/file_116.txt ...
/tmp/v1fs/test_files003/file_115.txt ...
/tmp/v1fs/test_files003/file_114.txt ...
/tmp/v1fs/test_files003/file_113.txt ...
/tmp/v1fs/test_files003/file_112.txt ...
/tmp/v1fs/test_files003/file_111.txt ...
/tmp/v1fs/test_files003/file_110.txt ...
/tmp/v1fs/test_files003/file_11.txt ...

########## SUMMARY ##########

 ********** HOST INFO **********
Hostname (FQDN): ip-192-168-93-5.us-west-2.compute.internal
Instance Metadata:
	Instance ID: i-079a5c4253e75cc24
	Instance Type: t3a.medium
	AMI ID: ami-039032381bf6cb65c
	Public IP: 34.217.124.101
	Private IP: 192.168.6.107
	Region: us-west-2
	VPC ID: vpc-024c74657c8916c31
	Tags: [{'Key': 'eks:cluster-name', 'Value': 'V1CSDemoSTG'}, {'Key': 'Project', 'Value': 'V1CSDemoSTG'}, {'Key': 'aws:ec2launchtemplate:id', 'Value': 'lt-0bb3b96a74661638d'}, {'Key': 'Name', 'Value': 'V1CSDemoSTG-ng-e6bb306c-Node'}, {'Key': 'aws:autoscaling:groupName', 'Value': 'eks-ng-e6bb306c-c0c6b148-68b6-f689-5c53-a0db904f90af'}, {'Key': 'aws:ec2:fleet-id', 'Value': 'fleet-9207a124-abb4-e33e-8cb8-24a02f6fb7fc'}, {'Key': 'eks:nodegroup-name', 'Value': 'ng-e6bb306c'}, {'Key': 'aws:eks:cluster-name', 'Value': 'V1CSDemoSTG'}, {'Key': 'k8s.io/cluster-autoscaler/enabled', 'Value': 'true'}, {'Key': 'alpha.eksctl.io/nodegroup-name', 'Value': 'ng-e6bb306c'}, {'Key': 'alpha.eksctl.io/nodegroup-type', 'Value': 'managed'}, {'Key': 'kubernetes.io/cluster/V1CSDemoSTG', 'Value': 'owned'}, {'Key': 'aws:ec2launchtemplate:version', 'Value': '2'}, {'Key': 'k8s.io/cluster-autoscaler/V1CSDemoSTG', 'Value': 'owned'}, {'Key': 'owner', 'Value': 'franzf'}]
******************************

********** SCAN **********
Total files scanned: 12
Files excluded: 3
Malicious files: 1
Clean files: 11
Total scan time: 2.05 seconds
Total execution time: 2.07 seconds
Log file: /home/ec2-user/v1fs/python_sdk/examples/logs/log_2024-02-28_22-21-10.txt
******************************

********** EXCLUSIONS **********
Excluded Files:
	/tmp/v1fs/test_files003/image.ova
	/tmp/v1fs/test_files003/exfile002.git
	/tmp/v1fs/test_files003/exfile001.git
******************************

********** DETECTIONS **********
Malicious Files:
	/tmp/v1fs/test_files003/eicar.com
******************************
#############################
```
