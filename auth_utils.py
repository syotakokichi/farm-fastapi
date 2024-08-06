import jwt
from fastapi import HTTPException
from passlib.context import CryptContext
from datetime import datetime, timedelta
from decouple import config


# 環境変数からJWTの秘密鍵を取得
JWT_KEY = config('JWT_KEY')

class AuthJwtCsrf():
    # パスワードのハッシュ化のためのコンテキスト設定
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    # JWTの秘密鍵を設定
    secret_key = JWT_KEY


    def generate_hashed_pw(self, password) -> str:
        # 平文のパスワードをハッシュ化して返す。
        # パスワードはbcryptアルゴリズムでハッシュ化される。
        return self.pwd_ctx.hash(password)


    def verify_pw(self, plain_pw, hashed_pw) -> bool:
        # 平文のパスワードとハッシュ化されたパスワードを比較し、
        # 一致するかを確認する。認証に成功した場合Trueを返す。
        return self.pwd_ctx.verify(plain_pw, hashed_pw)


    def encode_jwt(self, email) -> str:
        # ユーザーのメールアドレスを主体(sub)として、
        # JWTを生成し、返す。トークンは5分間有効で、
        # HS256アルゴリズムで署名される。
        payload = {
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow(),
            'sub': email
        }
        return jwt.encode(
            payload,
            self.secret_key,
            algorithm='HS256'
        )


    def decode_jwt(self, token) -> str:
        # トークンをデコード(復号)し、主体（sub）を返す。
        # トークンが無効または期限切れの場合、HTTPExceptionを発生させる。
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='The token has expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='JWT is invalid')


    def verify_jwt(self, request) -> str:
        # リクエストからJWTを取得し、そのトークンを検証して
        # 正当なものであれば主体を返す。トークンが存在しない場合、
        # または無効な場合は例外を発生させる。
        token = request.cookies.get('access_token')
        if not token:
            raise HTTPException(
                status_code=401, detail='No JWT exist: may not set yet or daleted'
            )
        _, _, value = token.partition(" ")
        subject = self.decode_jwt(value)
        return subject


    def verify_update_jwt(self, request) -> tuple[str, str]:
        # リクエストからJWTを検証し、正当であれば新しいトークンを生成して返す。
        # 新しいトークンと主体（ユーザーの識別子）をタプルとして返す。
        subject = self.verify_jwt(request)
        new_token = self.encode_jwt(subject)
        return new_token, subject


    def verify_csrf_update_jwt(self, request, csrf_protect, headers) -> str:
        # CSRFトークンとJWTを検証し、正当であれば新しいトークンを生成して返す。
        csrf_token = csrf_protect.get_csrf_from_headers(headers)
        csrf_protect.validate_csrf(csrf_token)
        subject = self.verify_jwt(request)
        new_token = self.encode_jwt(subject)
        return new_token