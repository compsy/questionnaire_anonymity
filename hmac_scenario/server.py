#!/usr/bin/env python3

import sqlite3
import configparser
import hmac
from flask import Flask, request, render_template, make_response

# Set up global 'config' object
config = configparser.ConfigParser()
config.read('server.ini')

# Set up global 'sqldb' object
sqldb = sqlite3.connect(config['main']['DatabaseFile'])
# Create the SQL tables and indexes if they don't exist yet
c = sqldb.cursor()
c.execute('CREATE TABLE IF NOT EXISTS users (username, password)');
c.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_ind0 ON users (username)');
c.execute('CREATE TABLE IF NOT EXISTS questionnaire (secret_key, secret_data)');
c.execute('CREATE UNIQUE INDEX IF NOT EXISTS questionnaire_ind0 ON questionnaire (secret_key)');
sqldb.commit()

app = Flask(__name__)


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

    secret_hmac = hmac.new(password.encode('utf-8'), username.encode('utf-8'), 'sha256')

    c = sqldb.cursor()
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)',
              (username, password));
    c.execute('INSERT INTO questionnaire (secret_key) VALUES (?)',
              (secret_hmac.hexdigest(),));
    sqldb.commit();

    resp = make_response(render_template('register_ok.html'))
    resp.set_cookie('username', username)
    resp.set_cookie('secret_hmac', secret_hmac.hexdigest())
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
    c.execute('SELECT password FROM users WHERE username=?', (username,));
    row = c.fetchone()

    if row is None or password != row[0]:
        return render_template('login_form.html', error='Unknown username or bad password')

    secret_hmac = hmac.new(password.encode('utf-8'), username.encode('utf-8'), 'sha256')

    resp = make_response(render_template('login_ok.html', username=username, password=password))
    resp.set_cookie('username', username)
    resp.set_cookie('secret_hmac', secret_hmac.hexdigest())
    return resp


@app.route('/show', methods=['GET'])
def show_get():
    username = request.cookies.get('username', None)
    secret_hmac = request.cookies.get('secret_hmac', None)
    return render_template('show.html', username=username, secret_hmac=secret_hmac)


@app.route('/edit', methods=['GET'])
def edit_get():
    secret_hmac = request.cookies.get('secret_hmac', None)

    c = sqldb.cursor()
    c.execute('SELECT secret_data FROM questionnaire WHERE secret_key=?', (secret_hmac,));
    row = c.fetchone()

    if row is None:
        return render_template('edit.html', secret_hmac=secret_hmac, error='Questionnaire data not found')

    return render_template('edit.html', secret_hmac=secret_hmac, secret_data=row[0])


@app.route('/edit', methods=['POST'])
def edit_post():
    secret_hmac = request.cookies.get('secret_hmac', None)

    secret_data=request.form['secret_data']
    c = sqldb.cursor()
    c.execute('UPDATE questionnaire SET secret_data=? WHERE secret_key=?',
              (secret_data, secret_hmac));
    sqldb.commit();

    return render_template('edit.html', secret_hmac=secret_hmac, secret_data=secret_data)


@app.route('/logout', methods=['GET'])
def logout():
    resp = make_response(render_template('logout_ok.html'))
    resp.set_cookie('username', '', 0)
    resp.set_cookie('secret_hmac', '', 0)
    return resp


if __name__ == '__main__':
    app.run(host=config['main']['BindAddress'],
            port=config['main']['BindPort'])
