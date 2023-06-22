

### 앱 API 구동에 필요한 유틸 함수들 모음


# 라이브러리 -----------------------------------

from passlib.hash import pbkdf2_sha256
        # pbkdf2_sha256 : 암호화 방식. 가장 많이 쓰는방식임.

from config import Config

# ---------------------------------------------



### 1. 원문 비밀번호를 단방향으로 암호화 하는 함수.

def hash_password(original_password) :

    password = pbkdf2_sha256.hash(original_password + Config.SALT )
    return password

    ### 랜덤시드값을 맞추면 나오는 패턴을 똑같이 만들 수 있음
    ### -> 해킹의 위험이 커짐.
    ### 비번 + 아무문자열 붙임(랜덤) -> 암호화 과정을 거치면 해킹의 위험이 줄어듬.
    ### password = pbkdf2_sha256.hash(original_password + '0417hell0') 처럼 만들면 되는데
    ### 공개될 위험이 있으니 맨 뒤 붙일 문자('0417hell0')는 config에 집어넣기



### 2. 유저가 입력한 비번이 맞는지 체크하는 함수.

def check_password(original_password, hashed_password) :
    check = pbkdf2_sha256.verify(original_password + Config.SALT, hashed_password)
    return check 
        # 값이 True 또는 False로 나옴.