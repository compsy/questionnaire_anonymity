#!/usr/bin/env python3

import sqlite3
import configparser
import secrets
import string
import bcrypt
import hashlib
from flask import Flask, request, render_template, make_response

# Set up global 'config' object
config = configparser.ConfigParser()
config.read('server.ini')

# Set up global 'sqldb' object
sqldb = sqlite3.connect(config['main']['DatabaseFile'])
# Create the SQL tables and indexes if they don't exist yet
c = sqldb.cursor()
c.execute('CREATE TABLE IF NOT EXISTS users (username, password, secret_salt)')
c.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_ind0 ON users (username)')
c.execute('CREATE TABLE IF NOT EXISTS questionnaire (secret_key, secret_data)')
c.execute('CREATE UNIQUE INDEX IF NOT EXISTS questionnaire_ind0 ON questionnaire (secret_key)')
sqldb.commit()

app = Flask(__name__)


sid_keys = {}

def new_session_id():
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return ''.join([chars[secrets.randbelow(len(chars))] for i in range(32)])


@app.route('/', methods=['GET'])
def index_get():
    return render_template('index.html')


@app.route('/register', methods=['GET'])
def register_get():
    return render_template('register_form.html')


@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username', None)
    if username is None or not username.isalnum():  # .isalnum() also rejects empty strings
        return render_template('register_form.html', error='Invalid "username" value')
    password = request.form.get('password', None)
    if password is None or not password.isalnum():
        return render_template('register_form.html', error='Invalid "password" value')

    # Some notes:
    # - Should check that username doesn't already exist
    # - Should allow punctuation etc. in password

    password_enc = password.encode('utf-8')
    secret_salt = bcrypt.gensalt()
    secret_bcrypt = bcrypt.hashpw(password_enc, secret_salt)
    secret_key = hashlib.sha256(secret_bcrypt)

    c = sqldb.cursor()
    c.execute('INSERT INTO users (username, password, secret_salt) VALUES (?, ?, ?)',
              (username, password, secret_salt.decode('utf-8')))
    c.execute('INSERT INTO questionnaire (secret_key) VALUES (?)',
              (secret_key.hexdigest(),))
    sqldb.commit()

    sid = new_session_id()
    sid_keys[sid] = secret_key.hexdigest()

    resp = make_response(render_template('register_ok.html'))
    resp.set_cookie('username', username)
    resp.set_cookie('sid', sid)
    return resp


@app.route('/login', methods=['GET'])
def login_get():
    return render_template('login_form.html')


@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username', None)
    if username is None or not username.isalnum():  # .isalnum() also rejects empty strings
        return render_template('login_form.html', error='Invalid "username" value')
    password = request.form.get('password', None)
    if password is None or not password.isalnum():
        return render_template('login_form.html', error='Invalid "password" value')

    c = sqldb.cursor()
    c.execute('SELECT password, secret_salt FROM users WHERE username=?', (username,))
    row = c.fetchone()

    if row is None or password != row[0]:
        return render_template('login_form.html', error='Unknown username or bad password')

    password_enc = password.encode('utf-8')
    secret_salt = row[1].encode('utf-8')
    secret_bcrypt = bcrypt.hashpw(password_enc, secret_salt)
    secret_key = hashlib.sha256(secret_bcrypt)

    sid = new_session_id()
    sid_keys[sid] = secret_key.hexdigest()

    resp = make_response(render_template('login_ok.html', username=username, password=password))
    resp.set_cookie('username', username)
    resp.set_cookie('sid', sid)
    return resp


@app.route('/show', methods=['GET'])
def show_get():
    username = request.cookies.get('username', None)
    sid = request.cookies.get('sid', None)
    secret_key = sid_keys[sid] if sid else None
    return render_template('show.html', username=username, sid=sid, secret_key=secret_key)


@app.route('/edit', methods=['GET'])
def edit_get():
    sid = request.cookies.get('sid', None)
    secret_key = sid_keys[sid] if sid else None

    if secret_key is None:
        return render_template('edit.html', error='Please login')

    c = sqldb.cursor()
    c.execute('SELECT secret_data FROM questionnaire WHERE secret_key=?', (secret_key,))
    row = c.fetchone()

    if row is None:
        return render_template('edit.html', secret_key=secret_key, error='Questionnaire data not found')

    return render_template('edit.html', secret_key=secret_key, secret_data=row[0])


@app.route('/edit', methods=['POST'])
def edit_post():
    sid = request.cookies.get('sid', None)
    secret_key = sid_keys[sid] if sid else None

    if secret_key is None:
        return render_template('edit.html', error='Please login')

    secret_data=request.form['secret_data']
    c = sqldb.cursor()
    c.execute('UPDATE questionnaire SET secret_data=? WHERE secret_key=?',
              (secret_data, secret_key))
    sqldb.commit()

    return render_template('edit.html', secret_key=secret_key, secret_data=secret_data)


@app.route('/logout', methods=['GET'])
def logout():
    sid = request.cookies.get('sid', None)

    try:
        del sid_keys[sid]
    except KeyError:
        pass

    resp = make_response(render_template('logout_ok.html'))
    resp.set_cookie('username', '', 0)
    resp.set_cookie('sid', '', 0)
    return resp


if __name__ == '__main__':
    app.run(host=config['main']['BindAddress'],
            port=config['main']['BindPort'])
