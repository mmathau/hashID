import json
import subprocess

# This script runs `john --list=format-details` and extracts the name and hash of each format,
# skipping the dynamic formats.

# run the command and capture the output
result = subprocess.run(['john', '--list=format-details'], capture_output=True, text=True)
# split it into lines
lines = result.stdout.splitlines()

# skip the dynamic formats and dummy
excluded = ['dynamic_', 'dynamic=', "dummy", "plaintext"]

data = []
for line in lines:
    # split the line into columns
    columns = line.split()
    # extract the name and hash
    # the name is the first column
    # the hash is the last column
    name = columns[0]
    hash = columns[-1]
    if not any(name.startswith(prefix) for prefix in excluded):
        item = {'name': name, 'hash': hash}
        data.append(item)

    # sort the data by name (case-insensitive)
    data = sorted(data, key=lambda x: x['name'].lower())

    # write list to a JSON file
    with open('output/john_hashes.json', 'w') as outfile:
        json.dump(data, outfile, indent=2)
