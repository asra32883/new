from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from app.config import Settings
from app.deps import AuthContext, cookie_name, current_auth, get_db, require_csrf
from app.security import policy, pow as powmod
from app.services import auth as svc

router = APIRouter(prefix="/api/auth", tags=["auth"])


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterIn(Strict):
    username: str = Field(max_length=64)
    password: str = Field(max_length=policy.MAX_PASSWORD)
    pow_challenge: str = Field(max_length=512)
    pow_nonce: str = Field(max_length=32)

    @model_validator(mode="after")
    def _policy(self) -> "RegisterIn":
        policy.validate_username(self.username)
        policy.validate_password(self.password, self.username)
        return self


class LoginIn(Strict):
    username: str = Field(max_length=64)
    password: str = Field(max_length=policy.MAX_PASSWORD)


def set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    response.set_cookie(
        cookie_name(settings), token, max_age=settings.session_absolute_hours * 3600,
        httponly=True, secure=settings.cookie_secure, samesite="strict", path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        cookie_name(settings), path="/", httponly=True, secure=settings.cookie_secure, samesite="strict"
    )


def rate_limited(exc: svc.RateLimited) -> HTTPException:
    return HTTPException(429, "Too many attempts. Try again later.", headers={"Retry-After": str(exc.retry_after)})


@router.get("/pow-challenge")
def pow_challenge(request: Request) -> dict:
    s: Settings = request.app.state.settings
    return {"challenge": powmod.issue(request.app.state.secret, s.pow_difficulty_bits), "difficulty_bits": s.pow_difficulty_bits}


@router.post("/register", status_code=201)
def register(body: RegisterIn, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    st = request.app.state
    try:
        user = svc.register(db, st.settings, st.secret, st.passwords, body.username, body.password,
                            body.pow_challenge, body.pow_nonce)
        token, session = svc.create_session(db, st.settings, user)
        db.commit()
    except svc.PowRejected:
        raise HTTPException(400, "Proof of work missing, invalid, expired or already used") from None
    except svc.UsernameTaken:
        raise HTTPException(409, "Username unavailable") from None
    except svc.RateLimited as e:
        raise rate_limited(e) from None
    set_session_cookie(response, st.settings, token)
    return {"username": user.username, "csrf_token": svc.csrf_token(st.secret, session)}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    st = request.app.state
    old = request.cookies.get(cookie_name(st.settings))
    try:
        user, token, session = svc.login(db, st.settings, st.secret, st.passwords, body.username, body.password)
    except svc.InvalidCredentials:
        raise HTTPException(401, "Invalid username or password") from None
    except svc.RateLimited as e:
        raise rate_limited(e) from None
    if old:  # drop any session cookie presented at login (fixation hygiene)
        svc.revoke_token(db, old)
    set_session_cookie(response, st.settings, token)
    return {"username": user.username, "csrf_token": svc.csrf_token(st.secret, session)}


@router.get("/me")
def me(auth: AuthContext = Depends(current_auth)) -> dict:
    return {"username": auth.user.username, "csrf_token": auth.csrf}


@router.post("/logout", status_code=204)
def logout(request: Request, auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> Response:
    svc.revoke_token(db, auth.token)
    out = Response(status_code=204)
    clear_session_cookie(out, request.app.state.settings)
    return out


@router.post("/logout-all", status_code=204)
def logout_all(request: Request, auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> Response:
    svc.revoke_all(db, auth.user.id)
    out = Response(status_code=204)
    clear_session_cookie(out, request.app.state.settings)
    return out
