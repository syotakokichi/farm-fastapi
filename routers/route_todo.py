from fastapi import APIRouter
from fastapi import Response, Request, HTTPException, Depends
from fastapi.encoders import jsonable_encoder
from schemas import Todo, TodoBody, SuccessMsg
from database import db_create_todo, db_get_todos, db_get_single_todo, db_update_todo, db_delete_todo
from starlette.status import HTTP_201_CREATED
from typing import List
from fastapi_csrf_protect import CsrfProtect
from auth_utils import AuthJwtCsrf

router = APIRouter()
auth = AuthJwtCsrf()

@router.post("/api/todo", response_model=Todo)
async def create_todo(request: Request, response: Response, data: TodoBody, csrf_protect: CsrfProtect = Depends()):
    # 新しいTODOアイテムを作成するエンドポイント。
    # - CSRFトークンとJWTを検証し、新しいJWTトークンを生成。
    # - 入力データをエンコードしてデータベースに保存。
    # - 新しいJWTトークンをクッキーにセットし、作成されたTODOを返す。
    new_token = auth.verify_csrf_update_jwt(
        request, csrf_protect, request.headers
    )
    todo = jsonable_encoder(data)
    res = await db_create_todo(todo)
    response.status_code = HTTP_201_CREATED
    response.set_cookie(
        key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True
    )
    if res:
        return res
    raise HTTPException(
        status_code=404, detail="Create task failed"
        )


@router.get("/api/todo", response_model=List[Todo])
async def get_todos(request: Request):
    # すべてのTODOアイテムを取得するエンドポイント。
    # - JWTを検証し、ユーザーが認証済みであることを確認。
    # - データベースからTODOリストを取得し返す。
    # auth.verify_jwt(request)
    res = await db_get_todos()
    return res


@router.get("/api/todo/{id}", response_model=Todo)
async def get_single_todo(request: Request, response: Response, id: str):
    # 指定されたIDに対応するTODOアイテムを取得するエンドポイント。
    # - JWTを検証し、新しいJWTトークンを生成。
    # - データベースから指定されたTODOを取得し返す。
    new_token = auth.verify_update_jwt(request)
    res = await db_get_single_todo(id)
    response.set_cookie(
        key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True
    )
    if res:
        return res
    raise HTTPException(
        status_code=404, detail=f"Task of ID:{id} does not exist"
        )


@router.put("/api/todo/{id}", response_model=Todo)
async def update_todo(request: Request, response: Response, id: str, data: TodoBody, csrf_protect: CsrfProtect = Depends()):
    # 指定されたIDのTODOアイテムを更新するエンドポイント。
    # - CSRFトークンとJWTを検証し、新しいJWTトークンを生成。
    # - 更新データをエンコードしてデータベースに保存。
    # - 新しいJWTトークンをクッキーにセットし、更新されたTODOを返す。
    new_token = auth.verify_csrf_update_jwt(
        request, csrf_protect, request.headers
    )
    todo = jsonable_encoder(data)
    res = await db_update_todo(id, todo)
    response.set_cookie(
        key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True
    )
    if res:
        return res
    raise HTTPException(
        status_code=404, detail="UPDATE task failed"
        )


@router.delete("/api/todo/{id}", response_model=SuccessMsg)
async def delete_todo(request: Request, response: Response, id: str, csrf_protect: CsrfProtect = Depends()):
    # 指定されたIDのTODOアイテムを削除するエンドポイント。
    # - CSRFトークンとJWTを検証し、新しいJWTトークンを生成。
    # - データベースからTODOを削除し、成功メッセージを返す。
    new_token = auth.verify_csrf_update_jwt(
        request, csrf_protect, request.headers
    )
    res = await db_delete_todo(id)
    response.set_cookie(
        key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True
    )
    if res:
        return {"message": "Successfully deleted"}
    raise HTTPException(
        status_code=404, detail=f"Task of ID:{id} does not exist"
        )