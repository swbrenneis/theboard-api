import requests

url = 'http://127.0.0.1:8000/login'
data = {
    'username': 'pqx-test',
    'password': '8xu1naGrRrwhSUgDyiy0'
}

response = requests.post(url, data=data)
print(response.json())