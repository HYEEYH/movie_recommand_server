

###### 영화 추천 앱 API 만들기 실습 ######

### -------- 설치한 라이브러리 확인 --------------- ###
# lamda_app 가상환경
# 파이썬버전 - 3.10

# 설치 라이브러리 : 
# flask , flask-restful, email-validator, 
# psycopg2-binary, passlib, Flask-JWT-Extended
### ---------------------------------------------- ###


### 라이브러리 임포트 -------------------- #
from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager

from config import Config

from resources.user import UserLoginResource, UserLogoutResource, UserRegisterResource, jwt_blocklist


### ------------------------------------- #


app = Flask(__name__)


# 환경변수 세팅 - JWT 적용
app.config.from_object(Config)

# JWT 매니저 초기화
# flask프레임워크(app)를 가지고 jwt매니저 적용해라 
jwt = JWTManager(app)
print('2.jwt매니저 초기화')

# 로그아웃된 토큰으로 요청하는 경우 -->> 이건 는 비정상적인 접근.
# jwt가 알아서 처리하도록 코드 작성.
@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload) :
    jti = jwt_payload['jti']
    return jti in jwt_blocklist




# app.config['JWT_SECRET_KEY'] = 'super-secret' # HS256
# ValueError: not a valid pbkdf2_sha256 hash 오류날때 
# 위 코드를 api = Api(app)위에 적으면 오류가 없어진다고 함.

api = Api(app)

api.add_resource( UserRegisterResource  , '/user/register') # 회원가입 API
api.add_resource( UserLoginResource  , '/user/login') # 로그인API
api.add_resource( UserLogoutResource  , '/user/logout') # 로그아웃API





if __name__ == '__main__' :
    app.run