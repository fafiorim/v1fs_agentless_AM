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

def setup_logging():
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"logs/log_{now}.txt"
    os.makedirs(os.path.dirname(log_filename), exist_ok=True)
    logging.basicConfig(filename=log_filename, level=logging.INFO,
                        format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    return os.path.abspath(log_filename)

def get_fqdn():
    try:
        return socket.getfqdn()
    except Exception as e:
        logging.error(f"Error retrieving FQDN: {e}")
        return None

def print_summary(scanned_files, excluded_files, malicious_files, clean_files, grpc_time, total_elapsed, log_file_path, detailed_results_file, fqdn=None):
    print(f"\n########## SUMMARY ##########")
    print(f"\n ********** HOST INFO **********")
    if fqdn:
        print(f"Hostname (FQDN): {fqdn}")
    print(f"******************************")
    print(f"\n********** SCAN **********")
    print(f"Total files scanned: {len(scanned_files)}")
    print(f"Files excluded: {len(excluded_files)}")
    print(f"Malicious files: {len(malicious_files)}")
    print(f"Clean files: {len(clean_files)}")
    print(f"Total scan time: {grpc_time:0.2f} seconds")
    print(f"Total execution time: {total_elapsed:0.2f} seconds")
    print(f"Log file: {log_file_path}")
    print(f"Detailed results file: {detailed_results_file}")
    print(f"******************************")

    if excluded_files:
        print(f"\n********** EXCLUSIONS **********")
        print("Excluded Files:")
        for file_path in excluded_files:
            print(f"\t{file_path}")
        print(f"******************************")
    if malicious_files:
        print(f"\n********** DETECTIONS **********")
        print("Malicious Files:")
        for file_path in malicious_files:
            print(f"\t{file_path}")
        print(f"******************************")
    print(f"\n#############################\n")

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

    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    detailed_results_file = os.path.join(os.path.dirname(log_file_path), f"detailed_scan_results_{now}.json")
    with open(detailed_results_file, 'w') as f:
        f.write("[")

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

                # Write handle response to the detailed results file
                with open(detailed_results_file, 'a') as f:
                    f.write(result + ",\n")

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

    # Close the JSON array in the detailed results file
    with open(detailed_results_file, 'a') as f:
        f.write("]")

    amaas.grpc.quit(handle)
    return scanned_files, excluded_files, malicious_files, clean_files, grpc_time

if __name__ == "__main__":
    log_file_path = setup_logging()

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

    fqdn = get_fqdn()
    if fqdn:
        hostname_tag = f"hostname={fqdn}"
        if args.tags:
            args.tags.append(hostname_tag)
        else:
            args.tags = [hostname_tag]

    total_start_time = time.perf_counter()
    scanned_files, excluded_files, malicious_files, clean_files, grpc_time = scan_directory(args.directory, args.exclude, args.addr, args.region, args.api_key, args.tls, args.ca_cert, args.tags)
    total_elapsed = time.perf_counter() - total_start_time

    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    detailed_results_file = os.path.join(os.path.dirname(log_file_path), f"detailed_scan_results_{now}.json")
    print_summary(scanned_files, excluded_files, malicious_files, clean_files, grpc_time, total_elapsed, log_file_path, detailed_results_file, fqdn)
