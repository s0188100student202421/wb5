from http.server import BaseHTTPRequestHandler, HTTPServer
import mysql.connector
from mysql.connector import Error
import cgi
import re
import secrets
from http import cookies
import json
import base64
import jwt
import os
import hashlib            
import datetime          

#----------Получение и настройка секретного ключа для JWT-------------------
SECRET_KEY = os.environ.get('JWT_SECRET_KEY') 
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print("Warning: JWT_SECRET_KEY not set in environment. Using generated ephemeral key")
# --------------------------------------------------------------------------

#------------------Функции для JWT---------------------------------
def generate_jwt(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    # Если токен вернулся в виде байтов, декодируем в строку
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def verify_jwt(token):
    try:
        # Обратите внимание: аргумент должен называться algorithms
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# --------------------------------------------------------------------------

#---------------для кодирования/декодирования Base64------------------------
def safe_base64_encode(data):
    return base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8')

def safe_base64_decode(data):
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)  # Добавляем недостающие символы '='
    return base64.urlsafe_b64decode(data).decode("utf-8")
# --------------------------------------------------------------------------

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


class HttpProcessor(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/wb5/login"):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            try:
                with open('login.html', 'r', encoding='utf-8') as file:
                    content = file.read()
                self.wfile.write(content.encode('utf-8'))
            except FileNotFoundError:
                self.wfile.write(b"login.html not found")
        elif self.path == "/wb5/":
            cookie = cookies.SimpleCookie(self.headers.get('Cookie'))
            auth_token = cookie.get("auth_token")
            if not auth_token or not verify_jwt(auth_token.value):
                self.send_response(302)
                self.send_header("Location", "/wb5/login")
                self.end_headers()
                return

            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()

            try:
                with open('server.html', 'r', encoding='utf-8') as file:
                    html_content = file.read()
            except FileNotFoundError:
                self.wfile.write(b"server.html not found")
                return

            form_data = {
                'fio': cookie.get('fio'),
                'phone': cookie.get('phone'),
                'email': cookie.get('email'),
                'date': cookie.get('date'),
                'bio': cookie.get('bio'),
                'languages': cookie.get('languages'),
                'gender': cookie.get('gender'),
                'check': cookie.get('check')
            }

            for field, value in form_data.items():
                if value:

                    if isinstance(value, cookies.Morsel):
                        decoded = safe_base64_decode(value.value)
                    else:
                        decoded = safe_base64_decode(value)
                    html_content = html_content.replace(f"{{{{{field}}}}}", decoded)
                else:
                    html_content = html_content.replace(f"{{{{{field}}}}}", "")

            errors = cookie.get('errors')
            if errors:
                decoded_errors = safe_base64_decode(errors.value)
                fixed_error = decoded_errors.replace("'", '"')
                try:
                    error_dict = json.loads(fixed_error)
                except json.JSONDecodeError:
                    error_dict = {}
                for field, error in error_dict.items():
                    html_content = html_content.replace(
                        f'{{{{{field}}}}}',
                        f'<input type="text" name="{field}" value="{form_data.get(field, "")}" class="error">'
                    )
                    html_content = html_content.replace(f"{{{{error_{field}}}}}", f'<span class="error">{error}</span>')

                for field in ['fio', 'phone', 'email', 'bio', 'languages', 'gender', 'check', 'date']:
                    if field not in error_dict:
                        html_content = html_content.replace(f"{{{{error_{field}}}}}", "")
            else:
                for field in ['fio', 'phone', 'email', 'bio', 'languages', 'gender', 'check', 'date']:
                    html_content = html_content.replace(f"{{{{error_{field}}}}}", " ")

            self.wfile.write(html_content.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/wb5/login":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST'})
            login_input = form.getvalue("login")
            password_input = form.getvalue("password")
            if not login_input or not password_input:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Login and password are required.")
                return

            try:
                connection = mysql.connector.connect(
                    host='u68824_2',
                    database='u68824',
                    user='u68824',
                    password='u68824'
                )
                if connection.is_connected():
                    cursor = connection.cursor()
                    cursor.execute("SELECT user_id, hashed_password FROM users WHERE login = %s", (login_input,))
                    result = cursor.fetchone()
                    if result:
                        user_id, stored_hash = result
                        if stored_hash == hash_password(password_input):
                            token = generate_jwt(user_id)
                            cookie = cookies.SimpleCookie()
                            cookie["auth_token"] = token
                            cookie["auth_token"]["path"] = "/wb5/"
                            cookie["auth_token"]["max-age"] = 3600 
                            cookie["auth_token"]["httponly"] = True
                            # Сохраняем user_id в cookie
                            cookie["user_id"] = str(user_id)
                            cookie["user_id"]["path"] = "/wb5/"
                            cookie["user_id"]["max-age"] = 3600 
                            cookie["user_id"]["httponly"] = True   
                            self.send_response(302)
                            self.send_header("Location", "/wb5/")
                            for morsel in cookie.values():
                                self.send_header("Set-Cookie", morsel.OutputString())
                            self.end_headers()
                            return
                        else:
                            self.send_response(401)
                            self.end_headers()
                            self.wfile.write(b"Invalid login or password.")
                    else:
                        try:
                            hashed_pwd = hash_password(password_input)
                            cursor.execute(
                                "INSERT INTO users (login, hashed_password) VALUES (%s,%s)",
                                (login_input, hashed_pwd)
                            )
                            user_id = cursor.lastrowid
                            connection.commit()
                            token = generate_jwt(user_id)
                            cookie = cookies.SimpleCookie()
                            cookie["auth_token"] = token
                            cookie["auth_token"]["path"] = "/wb5/"
                            cookie["auth_token"]["max-age"] = 3600 
                            cookie["auth_token"]["httponly"] = True
                            # Сохраняем user_id в cookie
                            cookie["user_id"] = str(user_id)
                            cookie["user_id"]["path"] = "/wb5/"
                            cookie["user_id"]["max-age"] = 3600 
                            cookie["user_id"]["httponly"] = True
                            self.send_response(302)
                            self.send_header("Location", "/wb5/")
                            for morsel in cookie.values():
                                self.send_header("Set-Cookie", morsel.OutputString())
                            self.end_headers()
                        except Error as e:
                            self.send_response(500)
                            self.end_headers()
                            self.wfile.write(f"Database error: {e}".encode('utf-8'))
                    cursor.close()
                    connection.close()
            except Error as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Database error: {e}".encode('utf-8'))

        elif self.path == "/wb5/":
            cookie = cookies.SimpleCookie(self.headers.get('Cookie'))
            auth_token = cookie.get("auth_token")
            user_id = cookie.get("user_id")
            if not auth_token or not verify_jwt(auth_token.value):
                self.send_response(302)
                self.send_header("Location", "/wb5/login")
                self.end_headers()
                return
            if not user_id:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"User ID not found in cookies.")
                return
            user_id = int(user_id.value)
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST'})

            fio = form.getvalue('fio')
            phone = form.getvalue('phone')
            email = form.getvalue('email')
            date = form.getvalue('date')
            gender = form.getvalue('gender')
            languages = form.getlist('languages')
            bio = form.getvalue('bio')
            check = form.getvalue('check')

            errors = {}
            valid_fio = re.compile(r"^[A-Za-zА-Яа-яЁё ]+$")
            if not fio or not valid_fio.match(fio) or len(fio) > 150:
                errors["fio"] = "Недопустимые символы в поле 'ФИО'. Разрешены только буквы и пробелы."

            valid_phone = re.compile(r"^(?:\+7|8)[0-9]{10}$")
            if not phone or not valid_phone.match(phone):
                errors["phone"] = "Неверный номер телефона. Используйте формат +7XXXXXXXXXX."

            valid_email = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            if not email or not valid_email.match(email):
                errors["email"] = "Неверный email. Используйте формат example@domain.com."
            if not date:
                errors["date"] = "Пожалуйста укажите дату"
            if not gender:
                errors["gender"] = "Не выбран пол."

            if not languages:
                errors["languages"] = "Не выбран ни один язык программирования."

            if not bio or len(bio) > 500:
                errors["bio"] = "Неверная биография. Максимальная длина 500 символов."

            if not check:
                errors["check"] = "Необходимо согласие с контрактом."

            if errors:
                cookie = cookies.SimpleCookie()
                for field in ['fio', 'phone', 'email', 'date', 'bio', 'gender', 'check','date']:
                    value = locals().get(field, '')
                    if value:
                        cookie[field] = safe_base64_encode(value)
                        cookie[field]['path'] = '/wb5/'
                        cookie[field]['httponly'] = True
                        cookie[field]['max-age'] = 31536000
                if languages:
                    cookie['languages'] = safe_base64_encode(",".join(languages))
                    cookie['languages']['path'] = '/wb5/'
                    cookie['languages']['httponly'] = True
                    cookie['languages']['max-age'] = 31536000

                cookie["errors"] = safe_base64_encode(json.dumps(errors))
                cookie["errors"]['path'] = '/wb5/'
                cookie["errors"]['httponly'] = True
                cookie["errors"]['max-age'] = 3600

                self.send_response(302)
                self.send_header('Location', '/wb5/')
                for morsel in cookie.values():
                    self.send_header('Set-Cookie', morsel.OutputString())
                self.end_headers()
                return

            try:
                connection = mysql.connector.connect(
                    host='u68824_2',
                    database='u68824',
                    user='u68824',
                    password='u68824'
                )
                if connection.is_connected():
                    cursor = connection.cursor()
                    cursor.execute("""
                        INSERT INTO applications(user_id, full_name, gender, phone, email, date, bio, agreement)
                        VALUES (%s,%s, %s, %s, %s, %s, %s, %s)
                    """, (user_id, fio, gender, phone, email, date, bio, bool(check)))

                    
                    for lang in languages:
                        cursor.execute("""
                            INSERT INTO programming_languages (guid)
                            VALUES (%s)
                        """, (lang,))

                    login = "Unknown"
                    cursor.execute("SELECT login FROM users WHERE user_id = %s", (user_id,))
                    login_result = cursor.fetchone()
                    if login_result:
                        login = login_result[0]

                    connection.commit()
                    cursor.close()
                    connection.close()

                    cookie = cookies.SimpleCookie()
                    for field in ['fio', 'phone', 'email', 'date', 'bio', 'gender', 'check']:
                        cookie[field] = ""
                        cookie[field]['path'] = '/wb5/'
                        cookie[field]['max-age'] = 0
                    if languages:
                        cookie['languages'] = ""
                        cookie['languages']['path'] = '/wb5/'
                        cookie['languages']['max-age'] = 0
                    cookie['errors'] = ""
                    cookie['errors']['path'] = '/wb5/'
                    cookie['errors']['max-age'] = 0

                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    for morsel in cookie.values():
                        self.send_header('Set-Cookie', morsel.OutputString())
                    self.end_headers()
                    self.wfile.write(f"Data successfully sent! Login: {login}".encode('utf-8'))
            except Error as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Database error: {e}".encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    port = 8006
    serv = HTTPServer(("0.0.0.0", port), HttpProcessor)
    print(f"Server is running on port {port}...")
    serv.serve_forever()
