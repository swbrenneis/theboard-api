import json

from django.http import JsonResponse, HttpResponseBadRequest
from .TheBoardBackend import TheBoardBackend
from .exceptions.InvalidPassword import InvalidPassword
from .exceptions.MemberNotFound import MemberNotFound
from .exceptions.ScreenNameInUse import ScreenNameInUse
from .exceptions.SessionIdMismatch import SessionIdMismatch


def register(request, screen_name):
    backend = TheBoardBackend()
    try:
        passphrase = backend.register(screen_name)
        data = {'registered': True, 'passphrase': passphrase}
    except ScreenNameInUse:
        data = {'registered': False, 'reason': 'Screen name in use'}
    return JsonResponse(data)


def login(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("Method not allowed")

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return HttpResponseBadRequest("Invalid JSON")

    backend = TheBoardBackend()
    screen_name = data['screenName']
    password = data['password']

    try:
        data = backend.login(screen_name, password)
    except MemberNotFound:
        print(f'Member {screen_name } not found')
        data = {'authenticated': False, 'reason': 'Member not found'}
    except InvalidPassword:
        print(f'Invalid password for {screen_name}')
        data = {'authenticated': False, 'reason': 'Invalid password'}
    return JsonResponse(data)


def logout(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("Method not allowed")

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return HttpResponseBadRequest("Invalid JSON")

    backend = TheBoardBackend()
    screen_name = data['screenName']
    session_id = data['sessionId']

    try:
        data = backend.logout(screen_name, session_id)
    except MemberNotFound:
        return HttpResponseBadRequest("Member not found")
    except SessionIdMismatch:
        return HttpResponseBadRequest("Session ID mismatch")
    return JsonResponse(data)