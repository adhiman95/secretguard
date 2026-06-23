# Simulates Toyota 2023 breach pattern:
# Secret key hardcoded in Python script, committed to public GitHub repo,
# sat exposed for 5 years before discovery.

import requests

# DO NOT DO THIS — this is the exact pattern that caused Toyota's breach
ACCESS_TOKEN = "ghp_FAKE_EXAMPLE_TOYOTA_TOKEN_00000"
API_ENDPOINT = "https://api.internal.toyota-systems.jp/v2"

def get_vehicle_data(vin):
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
    return requests.get(f"{API_ENDPOINT}/vehicles/{vin}", headers=headers)

# Also had this pattern — db creds in same file
db_password = "ToyotaProd@2019!secure"
DATABASE_URL = "postgresql://admin:ToyotaProd@2019!secure@prod-db.toyota.internal:5432/vehicles"
