from decouple import config
from typing import Union
from fastapi import HTTPException
import motor.motor_asyncio
from bson import ObjectId
from auth_utils import AuthJwtCsrf
import asyncio

MONGO_API_KEY = config('MONGO_API_KEY')

# MongoDBクライアントの作成
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_API_KEY)
# asyncio.get_event_loop()を使用するための設定
client.get_io_loop = asyncio.get_event_loop

# データベースとコレクションの指定
database = client.CustomerBooking
collection_booking = database.booking  # "booking" コレクション
collection_customer = database.customer  # "customer" コレクション

auth = AuthJwtCsrf()

# データベースから取得したbookingのドキュメントをシリアライズする関数
def booking_serializer(booking) -> dict:
    # TODOドキュメントを辞書形式に変換する関数。
    # - MongoDBのObjectIdを文字列に変換し、各フィールドの値を返す。
    return {
        "id": str(booking["_id"]),             # MongoDBのObjectIdを文字列に変換
        "customer_id": booking["customer_id"],             # タイトル
        "appointment_date": booking["appointment_date"], # 説明
        "details": booking["details"],
    }


# データベースから取得したcustomerのドキュメントをシリアライズする関数
def customer_serializer(customer) -> dict:
    # ユーザードキュメントを辞書形式に変換する関数。
    # - MongoDBのObjectIdを文字列に変換し、ユーザーのメールアドレスを返す。
    return {
        "customer_id": str(customer["_id"]),
        "name": customer["name"],
        "email": customer["email"]
    }


# 非同期で新しいbookingをデータベースに作成する関数
async def db_create_booking(data: dict) -> Union[dict, bool]:
    # 新しいbookingをデータベースに作成する関数。
    # - 成功した場合は、作成したbookingを辞書形式で返す。
    # - 失敗した場合はFalseを返す。
    booking = await collection_booking.insert_one(data)
    new_booking = await collection_booking.find_one({"_id": booking.inserted_id})

    if new_booking:
        return booking_serializer(new_booking)

    return False


# 非同期で全てのbookingを取得する関数
async def db_get_bookings() -> list:
    # 全てのbookingを取得する関数。
    # - 取得したbookingをリスト形式で返す。
    bookings = []
    for booking in await collection_booking.find().to_list(length=100):
        bookings.append(booking_serializer(booking))
    return bookings


# 非同期で指定されたIDのbookingを取得する関数
async def db_get_single_booking(id: str) -> Union[dict, bool]:
    # 指定されたIDのbookingを取得する関数。
    # - 取得したbookingを辞書形式で返す。
    # - 取得できなかった場合はFalseを返す。
    booking = await collection_booking.find_one({"_id": ObjectId(id)})
    if booking:
        return booking_serializer(booking)
    return False


# 非同期で指定されたIDのbookingを更新する関数
async def db_update_booking(id: str, data: dict) -> Union[dict, bool]:
    # 指定されたIDのbookingを更新する関数。
    # - 更新したbookingを辞書形式で返す。
    # - 更新に失敗した場合はFalseを返す。
    booking = await collection_booking.find_one({"_id": ObjectId(id)})
    if booking:
        updated_booking = await collection_booking.update_one(
            {"_id": ObjectId(id)}, {"$set": data}
        )
        if (updated_booking.modified_count > 0):
            new_booking = await collection_booking.find_one({"_id": ObjectId(id)})
            return booking_serializer(new_booking)
    return False


# 非同期で指定されたIDのbookingを削除する関数
async def db_delete_booking(id: str) -> bool:
    # 指定されたIDのbookingを削除する関数。
    # - 削除が成功した場合はTrueを返す。
    # - 削除できなかった場合はFalseを返す。
    booking = await collection_booking.find_one({"_id": ObjectId(id)})
    if booking:
        deleted_booking = await collection_booking.delete_one({"_id": ObjectId(id)})
        if (deleted_booking.deleted_count > 0):
            return True
    return False


# 非同期で新しいユーザーを登録する関数
async def db_signup(data: dict) -> dict:
    # 新しいユーザーをデータベースに登録する関数。
    # - 既存のメールアドレスがある場合はエラーを返す。
    # - パスワードが不正な場合もエラーを返す。
    # - 成功した場合は、新しいユーザー情報を辞書形式で返す。
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    overlap_customer = await collection_customer.find_one({'email': email})
    if overlap_customer:
        raise HTTPException(status_code=400, detail='Email is already taken')
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail='Password too short')
    customer = await collection_customer.insert_one({ "name": name, "email": email, "password": auth.generate_hashed_pw(password)})
    new_customer = await collection_customer.find_one({"_id": customer.inserted_id})
    return customer_serializer(new_customer)


# 非同期でユーザーのログインを処理する関数
async def db_login(data: dict) -> str:
    # ユーザーのログインを処理する関数。
    # - メールアドレスとパスワードを検証。
    # - 成功した場合はJWTトークンを生成して返す。
    # - 失敗した場合はエラーを返す。
    email = data.get('email')
    password = data.get('password')

    customer = await collection_customer.find_one({'email': email})
    if not customer or not auth.verify_pw(password, customer['password']):
        raise HTTPException(
            status_code=401, detail='Invalid email or password'
        )
    token = auth.encode_jwt(email)
    return token