

### 유저 관련 API

# 라이브러리 ---------------------- #
from flask_restful import Resource
from flask import request
import mysql.connector
from mysql.connector import Error
from mysql_connection import get_connection

from email_validator import validate_email, EmailNotValidError
    # pip install email-validator 한 후 임포트

from utils import check_password, hash_password
    # pip install psycopg2-binary
    # pip install passlib
    # 라이브러리 두개 설치 한 후 임포트

from flask_jwt_extended import create_access_token, get_jwt, jwt_required
    # pip install Flask-JWT-Extended 한 후 임포트

import datetime

# -------------------------------- #


##### 회원가입 관련 API 개발 ---------------------------------------

class UserRegisterResource(Resource) :
    
    def post(self) : 

        ### (데이터1). 보내주는 데이터 확인 
        # { 
        # "email" : "abc@naver.com",
        # "password" : "1234",
        # "name" : "홍길동",
        # "gender" : "male"
        #  }


        ### 1. 클라이언트가 보낸 데이터를 받는다
        ### 바디부분에 있고 제이슨으로 받아온다.

        data = request.get_json( )  # 유저가 보내온 데이터. (데이터1 내용)
        print('1. 회원가입데이터 :', data)



        ### 2. 이메일 주소형식이 올바른지 확인하기.
        try :
            validate_email( data['email'] )

        except EmailNotValidError as e :
            print('이메일오류', e)
            return { 'result':'fail' , 'error': str(e)} , 400

            


        ### 3.  비밀번호 길이가 유효한지 체크하기

        if len(  data['password']  ) < 4   or   len(  data['password']  ) > 14 :
            return { 'result' : 'fail', 'error' : '비번 길이 에러' }, 400



        ### 4. 비밀번호를 암호화 한다.
            # 유틸 파일 가서 암호화 함수 만들기.

        hashed_password = hash_password( data['password'] )
        print('비번암호화', hashed_password)



        #### 5. DB에 이미 회원정보가 있는지 확인한다.
            # 워크밴치 이동 -> sql문 작성
            # select *
            # from user
            # where email = 'abc@naver.com';
        try : 
            connection = get_connection()
            query = '''select *
                        from user
                        where email = %s;'''
            record = ( data['email'], )

            cursor = connection.cursor(dictionary= True)
            cursor.execute(query, record)

            result_list = cursor.fetchall()
            print('결과리스트', result_list )

            if len(result_list) == 1 :
                return { 'result' : 'fail', 'error' : '이미 회원가입 되었습니다.' }, 400
            
            # if 문에 들어가지 않는다면 -> 회원이 아니므로 회원가입 코드를 작성한다
            # DB에 저장한다
            # 쿼리부터 작성 한다.
                # 워크밴치 쿼리문
                # insert into user
                # (email, password, name, gender)
                # values
                # ('aaa@naver.com', '1234', '홍길동', 'male');
            query = '''insert into user
                        (email, password, name, gender)
                        values
                        (%s, %s, %s, %s);'''
            # %s에 들어갈 내용이 record
            record = ( data['email'],
                       hashed_password,
                        data['name'],
                        data['gender'] )
            
            # DB에 집어넣기 위해 커서 가져옴
            cursor = connection.cursor()
            cursor.execute(query, record)

            # 데이터 집어넣기 - 데이터베이스에 적용해라
            connection.commit()

            ### DB에 데이터를 insert 한 후에 
            ### 그 인서트된 행의 아이디를 가져오는 코드!!!
            ### 꼭 commit 뒤에 해야한다!!
            user_id = cursor.lastrowid

            # 닫기
            cursor.close()
            connection.close()
            

        except Error as e :
            print('DB에 넣기', e)
            return { 'result': 'fail', 'error' : str(e) }, 500


        ### 암호화 인증토큰 적용하기
        # 라이브러리 임포트
        # from flask_jwt_extended import create_access_token
        # create_access_token(user_id, expires_delta=datetime.timedelta(days=10))
        # timedelta(days=10) : 10일 지나면 로그인 꺼짐.
        access_token = create_access_token(user_id)


        return { 'result' : 'success', 'access_token' : access_token }
        # return { 'result' : 'success', 'user_id' : user_id } : 이렇게 하면 안됨!@






##### 로그인 관련 API 개발 ---------------------------------------

class UserLoginResource(Resource) :

    def post(self) :

        ### << 과  정  >>
        ### 1. 클라이언트로부터 데이터를 받아온다.
        ### 2. 이메일주소로 DB에 select한다.
        ### 3. 비밀번호가 일치하는지 확인한다.
        ### 4. 클라이언트에게 데이터를 보내준다.


        ### 1. 클라이언트로부터 데이터를 받아온다.
        data = request.get_json()


        ### 2. 이메일주소로 DB에 select한다.
        try :
            connection = get_connection()
            # select *
            # from user
            # where email = 'abc@naver.com';
            query = '''select *
                        from user
                        where email = %s;'''
            record = ( data['email'], )
            
            cursor = connection.cursor(dictionary=True)
            cursor.execute(query, record)

            result_list = cursor.fetchall()
            
            cursor.close()
            connection.close()

        except Error as e:
            print('DB에있는지확인', e)
            return { 'result': 'fail', 'error':str(e) }, 500


        if len(result_list) == 0 :
            return {'result':'fail', 'error':'회원이 아닙니다'}, 400



        ### 3.  비밀번호가 일치하는지 확인한다.
        ###     암호화된 비밀번호가 일치하는지 확인해야함.
        # 유틸.py에서 암호화비번 체크하는 함수 만듦.
        print('비번result_list', result_list)
        check = check_password( data['password'], result_list[0]['password'] )

        if check == False :
            return {'result':'fail', 'error':'비밀번호가 틀렸습니다'}, 400




        ### 4. 클라이언트에게 데이터를 보내준다.
        # 유저 아이디를 토큰을 이용하여 암호화 해서 보냄

        access_token = create_access_token(result_list[0]['id'])

        return { 'result' : 'success', 'access_token': access_token }
                                     # 로그인할때마다 토큰은 계속 바뀜. 해킹방지







##### 로그아웃 관련 API 개발 ---------------------------------------

### 로그아웃 된 토큰을 저장할 set을 만든다.
jwt_blocklist = set()

class UserLogoutResource(Resource) :

    # def delete(self):
    #     pass
    # 여기까지 만들어놓고 서버 올려서 포스트맨에서 서버 통신 되는지 확인

    @jwt_required() # 이 밑의 함수는 jwt토큰이 있어야 한다 -> 라고 알려주는거
    def delete(self):

        # 헤더에있는 인증토큰 가져와서 jwt_blocktoken에 집어넣어라
        jti = get_jwt()['jti']
        print(jti)
        jwt_blocklist.add(jti)

        return { 'result' : 'success' }
    


