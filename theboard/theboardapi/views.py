import json

from django.http import JsonResponse, HttpResponseBadRequest
from .TheBoardBackend import TheBoardBackend
from .exceptions.MemberNotFound import MemberNotFound


def register(request, screen_name):
    backend = TheBoardBackend()
    passphrase = backend.register(screen_name)
    data = {'registered': True, 'passphrase': passphrase}
    return JsonResponse(data)


def login(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("Method not allowed")

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return HttpResponseBadRequest("invalid JSON")

    backend = TheBoardBackend()
    screen_name = data['screen_name']
    password = data['password']

    try:
        json = backend.login(screen_name, password)
    except MemberNotFound as e:
        print(f'Member {screen_name }not found')
        json = {'authenticated': False}
    return JsonResponse(json)