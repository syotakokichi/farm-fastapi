from fastapi import APIRouter
from fastapi import Response, Request, HTTPException, Depends
from fastapi.encoders import jsonable_encoder
from schemas import Booking, BookingBody, SuccessMsg
from database import db_create_booking, db_get_bookings, db_get_single_booking, db_update_booking, db_delete_booking
from starlette.status import HTTP_201_CREATED
from typing import List
from fastapi_csrf_protect import CsrfProtect
from auth_utils import AuthJwtCsrf

router = APIRouter()
auth = AuthJwtCsrf()

@router.post("/api/booking", response_model=Booking)
async def create_booking(request: Request, response: Response, data: BookingBody, csrf_protect: CsrfProtect = Depends()):
    # 新しいbookingを作成するエンドポイント。
    # - CSRFトークンとJWTを検証し、新しいJWTトークンを生成。
    # - 入力データをエンコードしてデータベースに保存。
    # - 新しいJWTトークンをクッキーにセットし、作成されたbookingを返す。
    new_token = auth.verify_csrf_update_jwt(
        request, csrf_protect, request.headers
    )
    booking = jsonable_encoder(data)
    res = await db_create_booking(booking)
    response.status_code = HTTP_201_CREATED
    response.set_cookie(
        key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True
    )
    if res:
        return res
    raise HTTPException(
        status_code=404, detail="Create booking failed"
        )


@router.get("/api/booking", response_model=List[Booking])
async def get_bookings(request: Request):
    # すべてのbookingを取得するエンドポイント。
    # - JWTを検証し、ユーザーが認証済みであることを確認。
    # - データベースからbookingリストを取得し返す。
    # auth.verify_jwt(request)
    res = await db_get_bookings()
    return res


@router.get("/api/booking/{id}", response_model=Booking)
async def get_single_booking(request: Request, response: Response, id: str):
    # 指定されたIDに対応するbookingを取得するエンドポイント。
    # - JWTを検証し、新しいJWTトークンを生成。
    # - データベースから指定されたbookingを取得し返す。
    new_token = auth.verify_update_jwt(request)
    res = await db_get_single_booking(id)
    response.set_cookie(
        key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True
    )
    if res:
        return res
    raise HTTPException(
        status_code=404, detail=f"Booking of ID:{id} does not exist"
        )


@router.put("/api/booking/{id}", response_model=Booking)
async def update_booking(request: Request, response: Response, id: str, data: BookingBody, csrf_protect: CsrfProtect = Depends()):
    # 指定されたIDのbookingを更新するエンドポイント。
    # - CSRFトークンとJWTを検証し、新しいJWTトークンを生成。
    # - 更新データをエンコードしてデータベースに保存。
    # - 新しいJWTトークンをクッキーにセットし、更新されたTODOを返す。
    new_token = auth.verify_csrf_update_jwt(
        request, csrf_protect, request.headers
    )
    booking = jsonable_encoder(data)
    res = await db_update_booking(id, booking)
    response.set_cookie(
        key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True
    )
    if res:
        return res
    raise HTTPException(
        status_code=404, detail="UPDATE booking failed"
        )


@router.delete("/api/booking/{id}", response_model=SuccessMsg)
async def delete_booking(request: Request, response: Response, id: str, csrf_protect: CsrfProtect = Depends()):
    # 指定されたIDのbookingを削除するエンドポイント。
    # - CSRFトークンとJWTを検証し、新しいJWTトークンを生成。
    # - データベースからbookingを削除し、成功メッセージを返す。
    new_token = auth.verify_csrf_update_jwt(
        request, csrf_protect, request.headers
    )
    res = await db_delete_booking(id)
    response.set_cookie(
        key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True
    )
    if res:
        return {"message": "Successfully deleted"}
    raise HTTPException(
        status_code=404, detail=f"Booking of ID:{id} does not exist"
        )