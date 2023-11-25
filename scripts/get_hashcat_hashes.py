import json
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

# This script sends a GET request to the Hashcat wiki page, parses the HTML response and finds all the tables in the page.
# For each table, it extracts the rows and cells, storing the data from the cells if the row contains more than two cells.
# It specifically skips the superseded hash types table.

# send a GET request to the hashcat wiki page
response = requests.get('https://hashcat.net/wiki/doku.php?id=example_hashes')

# parse the response as HTML
soup = BeautifulSoup(response.text, 'html.parser')

# find the superseded hash types table
superseded_table = soup.find('h1', id='superseded_hash_types').find_next('table')

# find all the tables on the page
tables = soup.find_all('table')

data = []
for table in tables:
    # skip the superseded hash types table
    if table == superseded_table:
        continue

    # extract the rows
    rows = table.find_all('tr')
    for row in rows:
        # extract the cells
        cells = row.find_all('td')
        if len(cells) > 2:  # ensure there are enough cells
            data.append({
                'hash-mode': cells[0].text.strip(),
                'hash-name': cells[1].text.strip(),
                'example': cells[2].text.strip()
            })

# remove the rows that have a URL in the example hash field
data = [item for item in data if not urlparse(item['example']).scheme]

# sort the list by the hash-mode field's value (numeric sort)
data = sorted(data, key=lambda x: int(x['hash-mode']))

# write the sorted list to a new file
with open('output/hashcat_hashes.json', 'w') as f:
    json.dump(data, f, indent=2)
