import requests
from django.contrib.gis.geometry import json_regex

url = 'http://127.0.0.1:8000/login'
json_data = {
    "screenName": "pqx-test",
    "password": "4*4NigbCpW7L^eKNBkzz"
}

session = requests.Session()
session.get('http://127.0.0.1:8000/init')
csrf_token = session.cookies.get('csrftoken')
# print(f"CSRF token: {csrf_token}")

headers = {
    'X-CSRFToken': csrf_token,
    'Content-Type': 'application/json',
}

response = session.post(
    url,
    headers=headers,
    json=json_data
)
print(f'Response status code: {response.status_code}')
print(f'Response: {response.text}')