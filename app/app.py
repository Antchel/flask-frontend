import hashlib
import math
import uuid
import bcrypt
import requests
from flask import Flask, render_template, url_for, redirect, flash, session, request, make_response
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, \
    set_access_cookies, get_jwt_identity
import sqlite3 as lite
import datetime
from flask_jwt_extended.exceptions import NoAuthorizationError
from forms import SignUpForm, RegisterForm, CreateLinkForm, EditLinkForm, AuthorizationForm, FreeLinkForm

con = lite.connect('link_shortener.db', check_same_thread=False)
cur = con.cursor()

# cur.execute('CREATE TABLE IF NOT EXISTS urls ('
#             'id INTEGER PRIMARY KEY AUTOINCREMENT,'
#             'created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,'
#             'original_url TEXT NOT NULL,'
#             'short_url TEXT,'
#             'human_url TEXT,'
#             'link_type INTEGER,'
#             'username TEXT,'
#             'clicks INTEGER NOT NULL DEFAULT 0)')
#
# cur.execute('CREATE TABLE IF NOT EXISTS users ('
#             'id	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
#             'username	TEXT NOT NULL UNIQUE,'
#             'password	TEXT NOT NULL)')

app = Flask(__name__, template_folder='../templates')
app.config['SECRET_KEY'] = 'sdgjh48i3kjg'
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
# Change this in your code!
app.config["JWT_SECRET_KEY"] = "super-secret"

jwt = JWTManager(app)
salt = bcrypt.gensalt()
expiration_time = 200
backend_port = 5001


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    flash("Your JWT token has been expired.")
    return redirect(f"{request.host_url}/authorize/{session['URL']}")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == "POST":
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}?'
                             f'username={form.username.data}&password={form.password.data}'
                             f'&valid_password={form.valid_password.data}')
        print(resp.json())
        print(request.host_url)
        print(request.host)
        print("register", resp.status_code)
        if resp.status_code > 202:
            flash(f"{resp.json()}")
            return render_template('register.html', form=form)
        flash(f"{resp.json()[0]}")
        return redirect(url_for('log'))
    if request.method == 'GET':
        return render_template('register.html', form=form)
    else:
        return render_template('register.html', form=form)


@app.route('/', methods=['GET', 'POST'])
@app.route('/log', methods=['GET', 'POST'])
def log():
    session['username'] = "guest"
    form = SignUpForm()
    if request.method == 'POST' and form.validate():
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}?'
                             f'username={form.username.data}&password={form.password.data}')
        print(resp.json())
        print(f"{request.host_url.partition(':5')[0]}:{backend_port}")
        print("login", resp.status_code)
        if resp.status_code > 202:
            flash(f"{resp.json()}")
            return render_template('login.html', form=form)
        # access_token = create_access_token(identity=form.username.data,
        #                                    expires_delta=datetime.timedelta(seconds=expiration_time))
        session['username'] = form.username.data
        respon = make_response(redirect(url_for('linkage')))
        set_access_cookies(respon, resp.json()['JWT'])
        return respon
    if request.method == 'GET':
        return render_template('login.html', form=form)
    else:
        return render_template('login.html', form=form)


@app.route('/linkage', methods=['GET', 'POST'])
def linkage():
    if session['username'] == "guest":
        flash('Login please!')
        return redirect(url_for('log'))
    form = CreateLinkForm()
    if request.method == 'POST':
        print("Send request")
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}/linkage?'
                             f'source_link={form.source_link.data}'
                             f'&human_link={form.human_link.data}'
                             f'&link_type={form.link_type.data}'
                             f'&username={session["username"]}')
        if resp.status_code > 202:
            flash(resp.json()['msg'])
            return render_template('linkage.html', form=form,
                                   short_url=None,
                                   human_url=None)

        return render_template('linkage.html', form=form,
                               short_url=resp.json()[0]['short_url'],
                               human_url=resp.json()[0]['attribute'])

    if request.method == 'GET':
        return render_template('linkage.html', form=form,
                               short_url=None,
                               human_url=None)


@app.route('/<url_name>/')
def url_redirect(url_name):
    session['URL'] = url_name
    full_url = request.host_url + url_name
    resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}/{url_name}/?'
                         f'full_url={full_url}')
    print(resp.json())
    print(resp.json()[0]['original_id'])
    if resp.status_code <= 202:
        return redirect(resp.json()[0]['original_id'])


@app.route('/page404', methods=["GET", "POST"])
def err_page():
    if request.method == "GET":
        return render_template('page404.html')


@app.route('/stats', methods=["GET", "POST"])
def stats():
    if request.method == "GET":
        resp = requests.get(f'{request.host_url.partition(":5")[0]}:{backend_port}/stats?'
                            f'username={session["username"]}')
        urls_list = resp.json()[0]["urls_list"]
        return render_template('stats.html', urls=urls_list)


@app.route('/delete/<del_id>')
def delete(del_id):
    resp = requests.delete(f'{request.host_url.partition(":5")[0]}:{backend_port}/stats?'
                           f'username={session["username"]}'
                           f'&del_id={del_id}')
    if resp.status_code > 202:
        flash(resp.json()['msg'])
    return redirect(url_for('stats'))


@app.route('/delete_user/<del_id>')
def delete_user(del_id):
    resp = requests.delete(f'{request.host_url.partition(":5")[0]}:{backend_port}/delete_user?'
                           f'&del_id={del_id}')
    if resp.status_code > 202:
        flash(resp.json()['msg'])
    return redirect(url_for('admin'))


@app.route('/update/<del_id>')
def delete_attr(del_id):
    resp = requests.patch(f'{request.host_url.partition(":5")[0]}:{backend_port}/stats?'
                           f'username={session["username"]}'
                           f'&del_id={del_id}')
    if resp.status_code > 202:
        flash(resp.json()['msg'])
    return redirect(url_for('stats'))


@app.route('/edit/<edit_id>', methods=["GET", "POST"])
def edit(edit_id):
    form = EditLinkForm()
    if request.method == "GET":
        return render_template('edit_form.html', form=form)
    if request.method == "POST" and form.validate():
        human_url = request.host_url + form.human_link.data
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}/stats?'
                              f'username={session["username"]}'
                              f'&edit_id={edit_id}'
                              f'&psydo={human_url}'
                              f'&link_type={form.link_type.data}')
        # if resp.status_code > 202:
        #     flash(resp.json()[0]['msg'])
        return redirect(url_for('stats'))
    return render_template('edit_form.html', form=form)


@app.route('/authorize/<url>/', methods=['GET', 'POST'])
def authorize(url):
    form = AuthorizationForm()
    if request.method == 'POST' and form.validate():
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}/authorize/{url}?'
                             f'username={form.password.data}'
                             f'&password={form.username.data}')
        if resp.status_code <= 202:
            redirect(resp.json()[0]['redirect_url'])
        else:
            return render_template('authorize.html', form=form)
    if request.method == 'GET':
        return render_template('authorize.html', form=form)
    else:
        return render_template('authorize.html', form=form)


@app.route('/about_us', methods=['GET', "POST"])
def about():
    if request.method == "GET":
        return render_template('about.html')


# @app.route('/admin', methods=['GET', "POST"])
# def admin():
#     if session['username'] == 'Admin':
#         urls = cur.execute("SELECT * FROM users")
#         if request.method == "GET":
#             return render_template('admin.html', urls=urls)
#         if request.method == "POST":
#             return render_template('admin.html', urls=urls)
#     else:
#         flash("Login as 'Admin' and try again")
#         return redirect(url_for('log'))


@app.route('/free_link', methods=['GET', "POST"])
def free_link():
    form = FreeLinkForm()
    if request.method == "GET":
        return render_template('free_link.html', form=form)
    if request.method == 'POST' and form.validate():
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}/free_link?'
                             f'source_link={form.source_link.data}')
        short_url = resp.json()[0]['short_url']
        return render_template('free_link.html', form=form, short_url=short_url)
    return render_template('free_link.html', form=form)


if __name__ == "__main__":
    app.run(port=5000)
