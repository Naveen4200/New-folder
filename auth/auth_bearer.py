from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.auth_handler import decodeJWT


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    @staticmethod
    def verify_jwt(jwt_token: str) -> bool:
        try:
            payload = decodeJWT(jwt_token)
            return payload is not None
        except Exception as e:
            print(str(e))
            return False


def get_user_id_from_token(token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)

    if payload:
        return payload.get("user_id")
    else:
        raise HTTPException(status_code=403, detail="Invalid or expired token")
