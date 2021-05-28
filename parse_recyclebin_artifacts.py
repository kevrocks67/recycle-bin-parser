r"""
Author: Kevin Diaz
Description: Parses Windows recycle bin artifacts ($I and $R files from C:\$Recycle.Bin)
Supports Windows Vista and up
"""
import csv
import json
import os
import re
import struct
import sys

from datetime import datetime, timedelta
from optparse import OptionParser

import mimetypes

def check_file_validity(paths: list[str], verbose=False) -> tuple[list[str], list[str]]:
    """
    Checks that file has the proper filename and contains data

    Proper filename: $I{6 random chars}.{File Extension}
    Example: $ISLCD5H.exe

    Args:
        paths (list[str]): List of file paths

    Returns:
        (valid_files, invalid_files) (tuple[list[str], list[str]]):
            A list of the valid files and the invalidated files
    """
    if verbose:
        print("Checking file validity...")

    valid_files = []
    invalid_files = []
    for path in paths:
        fname = os.path.basename(path)

        if re.match(r'^\$I\w{6}\.\w+', fname) and (os.stat(path).st_size > 24):
            valid_files.append(path)
        else:
            invalid_files.append(path)
    return (valid_files, invalid_files)

def parse_fp_data(fp_raw_bytes: bytearray) -> str:
    """
    Parses the unicode file path from the given bytearray

    Args:
        fp_raw_bytes (bytearray): An array of bytes containing unicode data in LE

    Returns:
        file_path (str) : A unicode string representing a file path
    """
    file_path = ""
    # Convert raw bytes to hex strings
    fp_hex = ['{:02X}'.format(b) for b in fp_raw_bytes]

    # Convert 2 byte unicode hex strings into chars
    for i in range(0, len(fp_hex), 2):
        file_path += chr(int(''.join(fp_hex[i:i+2][::-1]), 16))

    # Remove null terminator
    file_path = file_path[:-1]
    return file_path

def filetime_to_datetime(filetime: int) -> datetime:
    """
    Converts Windows 64-bit filetime to date time format

    Args:
        filetime (int): Time in Windows 64-bit filetime format

    Returns:
        hr_time (datetime): Human readable datetime
    """
    microsecs = filetime / 10
    hr_time = datetime(1601, 1, 1) + timedelta(microseconds=microsecs)
    return hr_time

def parse_metadata(path: str, verbose=False) -> dict:
    """
    Parses the metadata inside the $I file

    Args:
        fname (str): File path of $I file

    Returns:
        data (dict): Contains the parsed metadata. Below is an example:
            {
                'file_path': "C:\test.txt",
                'file_path_len': "12"
                'file_ext': 'txt',
                'file_size': '5',
                'deleted_ts': 132664568702770000,
                'win_version_code': 2,
                'win_version': "Windows 10"
            }
    """
    data =  {
              'file_path':  "",
              'file_ext': path.split('.')[-1]
            }

    if verbose:
        print(f"Parsing {path}...")

    with open(path, 'rb') as file:
        data['win_version_code'] = struct.unpack("<Q", file.read(8))[0]
        data['file_size'] = struct.unpack("<Q", file.read(8))[0]
        data['deleted_ts'] = struct.unpack("<Q", file.read(8))[0]
        data['deleted_ts_dt'] = str(filetime_to_datetime(data['deleted_ts']))

        if data['win_version_code'] == 1:
            data['win_version'] = "Windows Vista/7/8/8.1"
        elif data['win_version_code'] == 2:
            data['win_version'] = "Windows 10"
            data['file_path_len'] = int(struct.unpack("<i", file.read(4))[0])
        else:
            data['win_version'] = "Unknown"

        fp_raw_bytes = file.read()
        data['file_path'] = parse_fp_data(fp_raw_bytes)

    return data

def check_file_mimetype(path) -> None:
    """
    Checks the mimetype of a file

    Args:
        fname (str): The file path of the $R file

    Returns
        mime (str): The mimetype of the file. If the file does not exist an error
                    message is returned
    """
    if os.path.exists(path):
        if re.match(r'^\$R\w{6}\.\w+', os.path.basename(path)):
            mime = mimetypes.guess_type(path)[0]
        else:
            mime = "Could not find $R file"
    else:
        mime = "Could not find $R file"
    return mime


def print_findings(findings: list[dict], out_format: str) -> None:
    """
    Pretty prints programs findings

    Args:
        findings: list[dict]
    """
    if out_format == "json":
        print(json.dumps(findings, indent=2))
    else:
        for finding in findings:
            print('-' * 10)
            print(f"$I File: {finding['meta_file_path']}")
            print(f"$R File: {finding['data_file_path']}")
            print(f"File Extension: {finding['metadata']['file_ext']}")
            print(f"FileType Guess (MIME): {finding['data_file_mime']}")
            print(f"Windows Version: {finding['metadata']['win_version']}")
            print(f"File Size: {finding['metadata']['file_size']} bytes")
            print(f"Timestamp (FILETIME): {finding['metadata']['deleted_ts']}")
            print(f"Timestamp (DateTime): {finding['metadata']['deleted_ts_dt']}")
            if finding['metadata']['win_version_code'] == 2:
                print(f"File Path Len: {finding['metadata']['file_path_len'] - 1} chars")
            print(f"File Path: {finding['metadata']['file_path']}")

def convert_to_csv(findings: list[dict]) -> list[str]:
    """
    Convert findings into a list of csv rows

    Args:
        findings (list[dict]): Dictionary containing the findings

    Returns:
        csv_list (list[str]): List of csv strings
    """
    header = ["Timestamp(FILETIME)", "Timestamp(DateTime)", "$I", "$R",
              "FilePath"," FilePathLen", "FileExtension", "FileType(MIME)",
              "WindowsVersion", "WindowsVersionCode"]
    csv_list = [header]

    for finding in findings:
        csv_list.append([
                          f"{finding['metadata']['deleted_ts']}",
                          f"{finding['metadata']['deleted_ts_dt']}",
                          f"{finding['meta_file_path']}",
                          f"{finding['data_file_path']}",
                          f"{finding['metadata']['file_path']}",
                          f"{finding['metadata']['file_path_len']}",
                          f"{finding['metadata']['file_ext']}",
                          f"{finding['data_file_mime']}",
                          f"{finding['metadata']['win_version']}",
                          f"{finding['metadata']['win_version_code']}"
                        ])
    return csv_list

def write_to_file(out_format: str, filename: str, findings: list[dict]) -> None:
    """
    Output findings to a json or CSV file. CSV is the default format if none or an
    unsupported type is provided

    Args:
        out_format (str): The expected file format (json or csv)
        filename (str): The name of the file to be written to
        findings (dict): Dictionary containing the findings
    """
    with open(filename, 'w') as file:
        if out_format == "json":
            json.dump(findings, file)
        else:
            csv_list = convert_to_csv(findings)
            writer = csv.writer(file)
            writer.writerows(csv_list)


def main() -> None:
    """
    Main entrypoint for this script.

    Note: You will not recieve notification of invalid files when using json formatted
          output unless you use the verbose flag

    Args:
        args (str): Commandline arguments (list of file paths)
    """
    usage = "Usage: %prog [options] arg"
    parser = OptionParser(usage)

    parser.add_option("-o", "--output", dest="output")
    parser.add_option("-f", "--format", dest="format")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose")
    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.error("Incorrect number of arguments. Provide a file to analyze")
        sys.exit(1)

    file_paths = check_file_validity(args, options.verbose)
    findings = []

    for file_path in file_paths[0]:
        metadata = parse_metadata(file_path, options.verbose)
        data_file_path = os.path.join(os.path.dirname(file_path),
                                      f'$R{os.path.basename(file_path)[2:]}')
        data_file_mime = check_file_mimetype(data_file_path)
        finding = {
                    'meta_file_path': file_path,
                    'data_file_path': data_file_path,
                    'data_file_mime': data_file_mime,
                    'metadata': metadata
                  }
        findings.append(finding)

    if not options.output:
        print_findings(findings, options.format)

    if file_paths[1] and (options.format != "json" or options.verbose):
        print("\nThe following files could not be parsed:")
        for invalid_file in file_paths[1]:
            print("\t", invalid_file)

    if options.output:
        write_to_file(options.format, options.output, findings)

if __name__ == "__main__":
    main()
