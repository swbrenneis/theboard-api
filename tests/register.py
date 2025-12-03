import requests

screen_name = 'pqx-test'

url = f'http://127.0.0.1:8000/register/{screen_name}'

response = requests.get(url)
print(f'Registration response: {response.json()}')