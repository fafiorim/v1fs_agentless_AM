import argparse
import os
import sys
import time
import logging
import json
from datetime import datetime
import amaas.grpc
from distutils.util import strtobool
import socket  # Import socket module

# Import boto3 library to access AWS services
import boto3

def setup_logging(hostname, instance_metadata):
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"logs/log_{now}.txt"
    os.makedirs(os.path.dirname(log_filename), exist_ok=True)
    logging.basicConfig(filename=log_filename, level=logging.INFO,
                        format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    # Write host information in log format at the beginning of the log file
    with open(log_filename, 'w') as log_file:
        log_file.write("########## HOST INFO ##########\n")
        log_file.write(f"Hostname: {hostname}\n")
        if instance_metadata:
            for key, value in instance_metadata.items():
                log_file.write(f"{key}: {value}\n")
        log_file.write("*******************************\n")
    return os.path.abspath(log_filename)

def get_instance_metadata():
    try:
        # Use boto3 to get instance metadata
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_instances()
        instance_data = response['Reservations'][0]['Instances'][0]
        instance_metadata = {
            'Instance ID': instance_data.get('InstanceId', 'N/A'),
            'Instance Type': instance_data.get('InstanceType', 'N/A'),
            'AMI ID': instance_data.get('ImageId', 'N/A'),
            'Public IP Address': instance_data.get('PublicIpAddress', 'N/A'),
            'Private IP Address': instance_data.get('PrivateIpAddress', 'N/A'),
            'Region': instance_data['Placement']['AvailabilityZone'][:-1],
            'VPC ID': instance_data.get('VpcId', 'N/A'),
            'Tags': instance_data.get('Tags', 'N/A')
        }
        return instance_metadata
    except Exception as e:
        logging.error(f"Error retrieving EC2 instance metadata: {e}")
        return None

def get_fqdn():
    try:
        return socket.getfqdn()
    except Exception as e:
        logging.error(f"Error retrieving FQDN: {e}")
        return None

def scan_directory(directory, exclude, addr, region, api_key, tls, ca_cert, tags):
    scanned_files = []
    excluded_files = []
    malicious_files = []
    clean_files = []
    grpc_time = 0

    if region:
        handle = amaas.grpc.init_by_region(region, api_key, tls, ca_cert)
    else:
        handle = amaas.grpc.init(addr, api_key, tls, ca_cert)

    print("Scanning files...")
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in exclude):
                excluded_files.append(os.path.join(root, file))
                continue
            file_path = os.path.join(root, file)
            print(f"{file_path} ...")
            try:
                s = time.perf_counter()
                result = amaas.grpc.scan_file(handle, file_path, tags)
                elapsed = time.perf_counter() - s
                grpc_time += elapsed
                result_json = json.loads(result)  # Assume result is a JSON string
                if result_json["foundMalwares"]:
                    malicious_files.append(file_path)
                    logging.info(f"Malicious: {file_path}, Malware: {result_json['foundMalwares'][0]['malwareName']}")
                else:
                    clean_files.append(file_path)
                    logging.info(f"Clean: {file_path}")
                scanned_files.append(file_path)
            except Exception as e:
                logging.error(f"Error scanning {file_path}: {e}")

    amaas.grpc.quit(handle)
    return scanned_files, excluded_files, malicious_files, clean_files, grpc_time

if __name__ == "__main__":
    fqdn = get_fqdn()
    instance_metadata = get_instance_metadata()  # Retrieve EC2 instance metadata
    hostname = fqdn if fqdn else socket.gethostname()

    log_file_path = setup_logging(hostname, instance_metadata)

    parser = argparse.ArgumentParser(description="Scan files in a directory with optional exclusion of file types.")
    parser.add_argument('--directory', '-d', required=True, help='Directory to scan')
    parser.add_argument('--exclude', '-e', nargs='+', default=[], help='File types to exclude')
    parser.add_argument('--addr', default='127.0.0.1:50051', help='gRPC server address and port (default 127.0.0.1:50051)')
    parser.add_argument('--region', help='AMaaS service region; e.g. us-1 or dev')
    parser.add_argument('--api_key', help='API key for authentication')
    parser.add_argument('--tls', type=lambda x: bool(strtobool(x)), default=False, help='Enable TLS for gRPC')
    parser.add_argument('--ca_cert', help='CA certificate')
    parser.add_argument('--tags', nargs='+', help='List of tags in the format "key=value"')

    args = parser.parse_args()

    total_start_time = time.perf_counter()
    scanned_files, excluded_files, malicious_files, clean_files, grpc_time = scan_directory(args.directory, args.exclude, args.addr, args.region, args.api_key, args.tls, args.ca_cert, args.tags)
    total_elapsed = time.perf_counter() - total_start_time
