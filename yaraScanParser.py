"""
Author: Shelly Raban
Date: January 2021

* This scripts parses json files produced by yara scan service: https://riskmitigation.ch/yara-scan/
* It prints:
- Number of matches to the wanted malware
- Number of false positives 
(matched samples which are not the malware intended to be identified by the yara rule (given by parameter -m))
* It saves the results:
- Output file: Contains matches of the wanted malware (given by parameter -o)
- False positives file: If there are suspected FPs, contains the false positives (located in the script's directory).
"""

import json
import argparse
import os
import sys

def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

def welcome():
    banner_file = open(r"{}".format(os.path.join(get_script_path(),"cli_banner.txt")))
    ascii_banner = banner_file.read()

    print("{}\n{}\n".format(ascii_banner, "Shelly Raban (Sh3llyR), January 2021, Version 0.1\nYara Scan Service \
Repository: https://github.com/cocaman/yara-scan-service"))

def parse_args():
    malware_name = None
    
    # Get arguements from the user
    parser = argparse.ArgumentParser(description="Parser script for Yara Scan Service")
    parser.add_argument('-i', dest='input_file', help='Path to the json file produced by Yara Scan Service')
    parser.add_argument('-o', dest='output_file', help='''Path to an output file to contain hash values in a format that can be easily inserted to the metadata section of yara rules:
    hash1 = "<sha256>"
    hash2 = "<sha256>"
    etc.
    If not provided, the output will be saved as "<malware_name>_hashList.txt" in the script's directory''', default=malware_name)
    parser.add_argument('-m', dest='malware_name', help='Malware name as appears in the json file. If not provided, the value of the first \'malware\' key in the the json file will be used', default=malware_name)

    # Parse the arguements
    args = parser.parse_args()
    
    # Return args
    return args

def load_json(args):
    
    # Load the file into a python json object
    with open(r"{}".format(args.input_file),'r') as a:
        data = json.load(a)
        return data

def set_default_args():

    # Set the default malware name and output file arguments
    if args.malware_name is None:
        malware_name = data[0]['malware']
    else:
        malware_name = args.malware_name
    if args.output_file is None:
        file_name = "{}_hashList.txt".format(malware_name)
        output_file = r"{}".format(os.path.join(get_script_path(), file_name))
    else:
        output_file = args.output_file
    return malware_name, output_file

def find_malware_occurrences(malware_name, data, output_file):
    
    # Search for the keyword of the malware in the json data
    # Write the matched hash values to a file in a format that can be inserted to the metadata section of yara rules

    counter_malware = 0
    counter_false = 0
    false_list = []
    false_file = r"{}".format(os.path.join(get_script_path(), "false_positives.txt"))
    
    with open(r"{}".format(output_file),'a') as o:
        for i,sample in enumerate(data):
            if malware_name in sample['malware']:
                counter_malware += 1
                o.write('hash{} = \"{}\"\n'.format(str(i+1),sample['sha256']))
            else:
                counter_false += 1
                if malware_name not in false_list:
                    false_list.append((sample['malware']))
                    with open(false_file,'a') as f:
                        f.write("{} - {}\n".format(sample['malware'],sample['sha256']))
    print("""
    Results:
    
    - Found {} Occurrences of {}
    - Found {} Occurrences of other samples
    - Hash list of {} matches can be found in:\n    - {}\n
    """.format(str(counter_malware), malware_name, str(counter_false), malware_name, output_file))

    if len(false_list) > 0:
        print("- Suspected false positives:\n- {}".format("\n- ".join(list(set(false_list)))))
        print("- Hash list of suspected false positives can be found in:\n- {}\n".format(false_file))

# Main
if __name__ == '__main__':

    # Print welcome message
    welcome()

    # Parse arguments
    args = parse_args()

    # Show only the error message when an exception occurs
    sys.tracebacklimit = 0
    
    # Load json file
    try:
        data = load_json(args)
    except:
        raise ValueError("Please enter a valid .json input file")

    # Set default arguments
    malware_name, output_file = set_default_args()

    # Find matches and false positives. Print to screen and save results to a file
    find_malware_occurrences(malware_name, data, output_file)
    
