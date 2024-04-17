from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
import hashlib
import re
import jwt


app = Flask(__name__)
CORS(app)


def connect_to_db():
    return psycopg2.connect(
        host="postgres-auth",
        database="auth",
        user="admin",
        password="admin"
    )


def check_email_exists(email):
    try:
        with connect_to_db() as conn, conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT email FROM users WHERE email = %s
                """, (email,))
            return cursor.fetchone() is not None
    except psycopg2.Error as e:
        print("Database error:", e)
        return False


def validate_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def register_user(first_name, last_name, email, password):
    try:
        with connect_to_db() as conn, conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users (first_name, last_name, email, password)
                VALUES (%s, %s, %s, %s)
                """, (first_name, last_name, email, password))
            conn.commit()
            return jsonify({'message': 'User registered successfully'}), 200
    except psycopg2.Error as e:
        return jsonify({'error': f'Failed to register user: {e}'}), 500
    finally:
        conn.close()


@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    
    if not all([first_name, last_name, email, password]):
        return jsonify({'error': 'Missing required fields'}), 400

    if check_email_exists(email):
        return jsonify({'error': 'Email already exists'}), 400
    if not validate_email(email):
        return jsonify({'error': 'Invalid email address'}), 400
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    return register_user(first_name, last_name, email, hashed_password)


def check_credentials(email, password):
    try:
        with connect_to_db() as conn, conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT email FROM users WHERE email = %s AND password = %s
                """, (email, hashlib.sha256(password.encode()).hexdigest()))
            return cursor.fetchone() is not None
    except psycopg2.Error as e:
        print("Database error:", e)
        return False
    finally:
        conn.close()


def generate_jwt_token(email):
    return jwt.encode({'email': email}, 'secret', algorithm='HS256')


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    if not validate_email(email):
        return jsonify({'error': 'Invalid email address'}), 400

    if not check_credentials(email, password):
        return jsonify({'error': 'Invalid email or password'}), 401

    token = generate_jwt_token(email)
    return jsonify({'token': token}), 200


if __name__ == "__main__":
    app.run(debug=True, port=3000, host='0.0.0.0')
