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
database = client.API_DB
collection_todo = database.todo  # "todo" コレクション
collection_user = database.user  # "user" コレクション

auth = AuthJwtCsrf()

# データベースから取得したtodoのドキュメントをシリアライズする関数
def todo_serializer(todo) -> dict:
    # TODOドキュメントを辞書形式に変換する関数。
    # - MongoDBのObjectIdを文字列に変換し、各フィールドの値を返す。
    return {
        "id": str(todo["_id"]),             # MongoDBのObjectIdを文字列に変換
        "title": todo["title"],             # タイトル
        "description": todo["description"], # 説明
    }


# データベースから取得したユーザーのドキュメントをシリアライズする関数
def user_serializer(user) -> dict:
    # ユーザードキュメントを辞書形式に変換する関数。
    # - MongoDBのObjectIdを文字列に変換し、ユーザーのメールアドレスを返す。
    return {
        "id": str(user["_id"]),
        "email": user["email"]
    }


# 非同期で新しいTODOアイテムをデータベースに作成する関数
async def db_create_todo(data: dict) -> Union[dict, bool]:
    # 新しいTODOアイテムをデータベースに作成する関数。
    # - 成功した場合は、作成したTODOを辞書形式で返す。
    # - 失敗した場合はFalseを返す。
    todo = await collection_todo.insert_one(data)
    new_todo = await collection_todo.find_one({"_id": todo.inserted_id})

    if new_todo:
        return todo_serializer(new_todo)

    return False


# 非同期で全てのTODOアイテムを取得する関数
async def db_get_todos() -> list:
    # 全てのTODOアイテムを取得する関数。
    # - 取得したTODOをリスト形式で返す。
    todos = []
    for todo in await collection_todo.find().to_list(length=100):
        todos.append(todo_serializer(todo))
    return todos


# 非同期で指定されたIDのTODOアイテムを取得する関数
async def db_get_single_todo(id: str) -> Union[dict, bool]:
    # 指定されたIDのTODOアイテムを取得する関数。
    # - 取得したTODOを辞書形式で返す。
    # - 取得できなかった場合はFalseを返す。
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo:
        return todo_serializer(todo)
    return False


# 非同期で指定されたIDのTODOアイテムを更新する関数
async def db_update_todo(id: str, data: dict) -> Union[dict, bool]:
    # 指定されたIDのTODOアイテムを更新する関数。
    # - 更新したTODOを辞書形式で返す。
    # - 更新に失敗した場合はFalseを返す。
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo:
        updated_todo = await collection_todo.update_one(
            {"_id": ObjectId(id)}, {"$set": data}
        )
        if (updated_todo.modified_count > 0):
            new_todo = await collection_todo.find_one({"_id": ObjectId(id)})
            return todo_serializer(new_todo)
    return False


# 非同期で指定されたIDのTODOアイテムを削除する関数
async def db_delete_todo(id: str) -> bool:
    # 指定されたIDのTODOアイテムを削除する関数。
    # - 削除が成功した場合はTrueを返す。
    # - 削除できなかった場合はFalseを返す。
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo:
        deleted_todo = await collection_todo.delete_one({"_id": ObjectId(id)})
        if (deleted_todo.deleted_count > 0):
            return True
    return False


# 非同期で新しいユーザーを登録する関数
async def db_signup(data: dict) -> dict:
    # 新しいユーザーをデータベースに登録する関数。
    # - 既存のメールアドレスがある場合はエラーを返す。
    # - パスワードが不正な場合もエラーを返す。
    # - 成功した場合は、新しいユーザー情報を辞書形式で返す。
    email = data.get('email')
    password = data.get('password')
    overlap_user = await collection_user.find_one({'email': email})
    if overlap_user:
        raise HTTPException(status_code=400, detail='Email is already taken')
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail='Password too short')
    user = await collection_user.insert_one({"email": email, "password": auth.generate_hashed_pw(password)})
    new_user = await collection_user.find_one({"_id": user.inserted_id})
    return user_serializer(new_user)


# 非同期でユーザーのログインを処理する関数
async def db_login(data: dict) -> str:
    # ユーザーのログインを処理する関数。
    # - メールアドレスとパスワードを検証。
    # - 成功した場合はJWTトークンを生成して返す。
    # - 失敗した場合はエラーを返す。
    email = data.get('email')
    password = data.get('password')

    user = await collection_user.find_one({'email': email})
    if not user or not auth.verify_pw(password, user['password']):
        raise HTTPException(
            status_code=401, detail='Invalid email or password'
        )
    token = auth.encode_jwt(email)
    return token