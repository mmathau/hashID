import json

# open the JSON file and load the data
with open('../hashid/pkg/hashtypes/hashes.json', 'r') as f:
    data = json.load(f)

# ensure data is a list
if not isinstance(data, list):
    raise ValueError("data should be a list")

# sort the list by the name field's value (case-insensitive alphabetic sort)
sorted_data = sorted(data, key=lambda item: item.get('name', '').lower())

# write the sorted list back to a new file
with open('../hashid/pkg/hashtypes/hashes_sorted.json', 'w') as f:
    json.dump(sorted_data, f, indent=2)