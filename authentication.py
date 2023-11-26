from flask import Flask, request, jsonify, redirect, session
from requests_oauthlib import OAuth2Session
import boto3
import jwt
import datetime

app = Flask(__name__)
app.secret_key = '一个非常安全的秘密'

# JWT 密钥和黑名单
SECRET_KEY = '您的密钥'
TOKEN_BLACKLIST = set()

# Google OAuth 设置
GOOGLE_CLIENT_ID = '您的Google客户端ID'
GOOGLE_CLIENT_SECRET = '您的Google客户端秘钥'
REDIRECT_URI = 'http://localhost:5000/callback'
AUTHORIZATION_BASE_URL = 'https://accounts.google.com/o/oauth2/auth'
TOKEN_URL = 'https://accounts.google.com/o/oauth2/token'
SCOPE = ['openid', 'https://www.googleapis.com/auth/userinfo.email']

# AWS Cognito 设置
COGNITO_CLIENT_ID = '您的Cognito应用客户端ID'
cognito_client = boto3.client('cognito-idp', region_name='us-east-1')


# 假的管理员数据
fake_administrator = {
    'username': 'admin',
    'password': 'admin123'
}

# JWT 编码和解码
def encode_jwt(user_data):
    payload = {
        **user_data,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def decode_jwt(token):
    if token in TOKEN_BLACKLIST:
        raise Exception('Token has been revoked')
    return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

# 用户注册
@app.route('/register', methods=['POST'])
def register():
    body = request.json
    username = body['username']
    password = body['password']
    phone_number = body['phone_number']

    try:
        response = cognito_client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=username,
            Password=password,
            UserAttributes=[{'Name': 'phone_number', 'Value': phone_number}]
        )
        return jsonify({'message': '用户注册成功。验证码已发送'})
    except cognito_client.exceptions.ClientError as e:
        return jsonify({'error': e.response['Error']['Message']}), 400

# 用户使用 Gmail 登录
@app.route('/authenticate/member', methods=['GET'])
def member_login():
    google = OAuth2Session(GOOGLE_CLIENT_ID, scope=SCOPE, redirect_uri=REDIRECT_URI)
    authorization_url, state = google.authorization_url(AUTHORIZATION_BASE_URL, access_type="offline", prompt="select_account")
    session['oauth_state'] = state
    return redirect(authorization_url)

# Google OAuth 回调
@app.route('/callback', methods=['GET'])
def callback():
    google = OAuth2Session(GOOGLE_CLIENT_ID, state=session['oauth_state'])
    google.fetch_token(TOKEN_URL, client_secret=GOOGLE_CLIENT_SECRET, authorization_response=request.url)
    userinfo = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
    token = encode_jwt({'email': userinfo['email']})
    return jsonify({'token': token})

# 管理员登录
@app.route('/authenticate/administrator', methods=['POST'])
def admin_login():
    username = request.json.get('username')
    password = request.json.get('password')
    if username == fake_administrator['username'] and password == fake_administrator['password']:
        token = encode_jwt({'username': username, 'role': 'administrator'})
        return jsonify({'token': token})
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

# 登出
@app.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization', '').split(' ')[1]
    TOKEN_BLACKLIST.add(token)
    return jsonify({'message': 'Logged out successfully'})

# 受保护的路由
@app.route('/protected')
def protected():
    token = request.headers.get('Authorization', '').split(' ')[1]
    try:
        user_data = decode_jwt(token)
        return jsonify(user_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 401

if __name__ == '__main__':
    app.run(debug=True)
