from __future__ import annotations

import time
from typing import Any
import jwt
from decouple import config

JWT_SECRET = config('secret')
JWT_ALGORITHM = config('algorithm')


def token_response(token: str):
    return {
        "access_token": token
    }


def signJWT(user_id: str) -> tuple[Any, float]:
    expiration_time = time.time() + 365 * 24 * 60 * 60  # 365 days * 24 hours * 60 minutes * 60 seconds
    payload = {
        "user_id": user_id,
        "expires": expiration_time
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return token, expiration_time


def decodeJWT(token: str) -> Any | None:
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if decoded_token["expires"] >= time.time():
            return decoded_token
        else:
            return None
    except jwt.ExpiredSignatureError:
        return None
    except jwt.DecodeError:
        return None
