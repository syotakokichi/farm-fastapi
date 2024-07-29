from fastapi import APIRouter
from fastapi import Response, Request, Depends
from fastapi.encoders import jsonable_encoder
from schemas import SuccessMsg, UserInfo, UserBody, Csrf
from database import (
  db_signup,
  db_login,
)
from auth_utils import AuthJwtCsrf
from fastapi_csrf_protect import CsrfProtect

router = APIRouter()
auth = AuthJwtCsrf()

@router.get("/api/csrftoken", response_model=Csrf)
def get_csrf(request: Request, csrf_protect: CsrfProtect = Depends()):
    # CSRFトークンを生成して返すエンドポイント。
    # フロントエンドがこのトークンを使用して、CSRF攻撃から保護する。
    csrf_token = csrf_protect.generate_csrf_tokens()
    res = {"csrf_token": csrf_token}
    return res


@router.post("/api/register", response_model=UserInfo)
async def signup(request: Request, user: UserBody, csrf_protect: CsrfProtect = Depends()):
    # 新しいユーザーを登録するエンドポイント。
    # - CSRFトークンを検証し、リクエストが正当であることを確認。
    # - ユーザー情報をエンコードし、データベースに新しいユーザーを作成。
    # - 作成されたユーザー情報を返す。

    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.verify_csrf(csrf_token)
    user = jsonable_encoder(user)
    new_user = await db_signup(user)
    return new_user


@router.post("/api/login", response_model=SuccessMsg)
async def login(request: Request, response: Response, user: UserBody, csrf_protect: CsrfProtect = Depends()):
    #  ユーザーのログインを処理するエンドポイント。
    # - CSRFトークンを検証し、リクエストが正当であることを確認。
    # - ユーザー情報をエンコードし、データベースで認証を行う。
    # - 成功した場合、JWTトークンを生成し、クッキーにセットして返す。
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.verify_csrf(csrf_token)
    user = jsonable_encoder(user)
    token = await db_login(user)
    response.set_cookie(
        key="access_token", value=f"Bearer {token}", httponly=True, samesite="none", secure=True
      )
    return {"message": "Successfully logged in"}


@router.post("/api/logout", response_model=SuccessMsg)
def logout(response: Response, request: Request, csrf_protect: CsrfProtect = Depends()):
    #   ユーザーのログアウトを処理するエンドポイント。
    # - CSRFトークンを検証し、リクエストが正当であることを確認。
    # - クッキーに保存されているJWTトークンを削除し、ユーザーをログアウトさせる。
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.verify_csrf(csrf_token)
    response.set_cookie(
        key="access_token", value="", httponly=True, samesite="none", secure=True
    )
    return {"message": "Successfully logged out"}


@router.get("/api/user", response_model=UserInfo)
def get_user_refresh_jwt(request: Request, response: Response):
    #  ユーザー情報を取得し、新しいJWTトークンを発行するエンドポイント。
    # - リクエストに含まれるJWTトークンを検証し、更新する。
    # - 新しいJWTトークンをクッキーにセットして返す。
    new_token, subject = auth.verify_update_jwt(request)
    response.set_cookie(
        key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True
    )
    return {"email": subject}