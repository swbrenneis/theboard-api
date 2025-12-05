import base64
import hashlib
import json

from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
from django.views.decorators.csrf import ensure_csrf_cookie

from .TheBoardBackend import TheBoardBackend
from .exceptions.InvalidPassword import InvalidPassword
from .exceptions.MemberNotFound import MemberNotFound
from .exceptions.ScreenNameInUse import ScreenNameInUse
from .exceptions.SessionIdMismatch import SessionIdMismatch
from .models import TheBoardMember


def register(request, screen_name):
    backend = TheBoardBackend()
    try:
        passphrase = backend.register(screen_name)
        data = {'registered': True, 'passphrase': passphrase}
    except ScreenNameInUse:
        data = {'registered': False, 'reason': 'Screen name in use'}
    return JsonResponse(data)

def do_handshake(backend, the_board_member):
    backend.do_handshake(the_board_member.public_id)

@ensure_csrf_cookie
def init(request):
    if request.method != 'GET':
        return HttpResponseBadRequest("Method not allowed")
    return JsonResponse({"status": "ok"})


def login(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("Method not allowed")

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        print(f'Invalid request JSON')
        return HttpResponseBadRequest("Invalid JSON")

    backend = TheBoardBackend()
    screen_name = data['screenName']
    password = data['password']

    try:
        the_board_member = TheBoardMember.objects.get(screen_name=screen_name)
    except TheBoardMember.DoesNotExist:
        return HttpResponseBadRequest("Invalid screen name")

    session_context = backend.do_handshake(the_board_member)

    try:
        data = backend.login(screen_name, password, session_context.session_id)
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