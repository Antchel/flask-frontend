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

cur.execute('CREATE TABLE IF NOT EXISTS urls ('
            'id INTEGER PRIMARY KEY AUTOINCREMENT,'
            'created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,'
            'original_url TEXT NOT NULL,'
            'short_url TEXT,'
            'human_url TEXT,'
            'link_type INTEGER,'
            'username TEXT,'
            'clicks INTEGER NOT NULL DEFAULT 0)')

cur.execute('CREATE TABLE IF NOT EXISTS users ('
            'id	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
            'username	TEXT NOT NULL UNIQUE,'
            'password	TEXT NOT NULL)')

app = Flask(__name__, template_folder='../templates')
app.config['SECRET_KEY'] = 'sdgjh48i3kjg'

app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
app.config["JWT_COOKIE_SECURE"] = False
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
        return redirect(url_for('log'))
    if request.method == 'GET':
        return render_template('register.html', form=form)
    else:
        return render_template('register.html', form=form)


@app.route('/', methods=['GET', 'POST'])
@app.route('/log', methods=['GET', 'POST'])
def log():
    form = SignUpForm()
    if request.method == 'POST' and form.validate():
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}?'
                             f'username={form.username.data}&password={form.password.data}')
        print(resp.json())
        a = request.host_url
        print(f"{request.host_url.partition(':5')[0]}:{backend_port}" )
        print("login", resp.status_code)
        if resp.status_code > 202:
            flash(f"{resp.json()}")
            return render_template('login.html', form=form)
        access_token = create_access_token(identity=form.username.data,
                                                   expires_delta=datetime.timedelta(seconds=expiration_time))
        resp = make_response(redirect(url_for('linkage')))
        set_access_cookies(resp, access_token)
        return resp
    if request.method == 'GET':
        return render_template('login.html', form=form)
    else:
        return render_template('login.html', form=form)


@app.route('/linkage', methods=['GET', 'POST'])
def linkage():
    verify_jwt_in_request()
    if not get_jwt_identity():
        flash('Login please!')
        return redirect(url_for('log'))
    short_url = None
    human_url = None
    form = CreateLinkForm()
    url_cnt = con.execute('SELECT COUNT(*) FROM urls').fetchall()
    hash_symbols = math.log2(url_cnt[0][0]) // 4
    if hash_symbols < 8:
        HASH_SIZE = 8
    else:
        HASH_SIZE = int(hash_symbols)
    if request.method == 'POST':
        resp = requests.post(f'http://127.0.0.1:5001/linkage?'
                             f'source_link={form.source_link.data}'
                             f'&human_link={form.human_link.data}'
                             f'&link_type={form.link_type.data}')
        print(resp.status_code)
        if resp.status_code > 202:
            return render_template('linkage.html', form=form,
                                   short_url=short_url,
                                   human_url=human_url)

        print(resp.json())
        return render_template('linkage.html', form=form,
                               short_url=resp.json()['short_url'],
                               human_url=resp.json()['attribute'])

    if request.method == 'GET':
        return render_template('linkage.html', form=form,
                               short_url=short_url,
                               human_url=human_url)


# Finised there



@app.route('/<url_name>/')
def url_redirect(url_name):
    conn = cur
    session['URL'] = url_name
    full_url = request.host_url + url_name
    source_url = cur.execute(f"select original_url from urls where "
                             f"(short_url = '{full_url}')"
                             f"or (human_url = '{full_url}')").fetchone()
    if not source_url:
        flash("Wrong URL")
        return redirect("/page404")
    link_type = cur.execute(f"select link_type from urls where "
                            f"(short_url = '{full_url}')"
                            f"or (human_url = '{full_url}')").fetchone()

    if link_type[0] == 1:
        if source_url[0]:
            original_id = source_url[0]
            clicks = cur.execute(f"SELECT clicks FROM urls WHERE "
                                 f"(short_url = '{full_url}') "
                                 f"or (human_url = '{full_url}')").fetchone()
            tmp_click_cnt = clicks[0]
            tmp_click_cnt = tmp_click_cnt + 1
            conn.execute(f'UPDATE urls SET clicks = "{tmp_click_cnt}" WHERE '
                         f"(short_url = '{full_url}') "
                         f"or (human_url = '{full_url}')")
            con.commit()
            return redirect(original_id)
        else:
            flash('Invalid URL')
            return redirect("/page404")

    if link_type[0] == 2:
        try:
            verify_jwt_in_request()
        except NoAuthorizationError:
            flash("Please, authorize!")
            return redirect(f"{request.host_url}/authorize/{url_name}")
        if source_url[0]:
            original_id = source_url[0]
            clicks = cur.execute(f"SELECT clicks FROM urls WHERE "
                                 f"(short_url = '{full_url}') "
                                 f"or (human_url = '{full_url}')").fetchone()
            tmp_click_cnt = clicks[0]
            tmp_click_cnt = tmp_click_cnt + 1
            conn.execute(f'UPDATE urls SET clicks = "{tmp_click_cnt}" WHERE '
                         f"(short_url = '{full_url}') "
                         f"or (human_url = '{full_url}')")
            con.commit()
            return redirect(original_id)
        else:
            flash('Invalid URL')
            return redirect(url_for('page404'))

    if link_type[0] == 3:
        try:
            verify_jwt_in_request()
        except NoAuthorizationError:
            flash("Please, authorize!")
            return redirect(f"{request.host_url}/authorize/{url_name}")
        current_user = get_jwt_identity()
        author = cur.execute(f"SELECT username FROM urls WHERE"
                             f"((short_url = '{full_url}')"
                             f"or (human_url = '{full_url}')) AND "
                             f"username = '{current_user}'").fetchone()
        if not author:
            flash("You have not enough privileges")
            return redirect(f"{request.host_url}/authorize/{url_name}")
        if source_url[0]:
            original_id = source_url[0]
            clicks = cur.execute(f"SELECT clicks FROM urls WHERE original_url = '{original_id}'"
                                 f" and username = '{current_user}'").fetchone()
            tmp_click_cnt = clicks[0]
            tmp_click_cnt = tmp_click_cnt + 1
            conn.execute(f'UPDATE urls SET clicks = "{tmp_click_cnt}" WHERE original_url = "{original_id}" '
                         f'and username = "{current_user}"')
            con.commit()
            return redirect(original_id)
        else:
            flash('Invalid URL')
            return redirect('/page404')


@app.route('/page404', methods=["GET", "POST"])
def err_page():
    if request.method == "GET":
        return render_template('page404.html')


@app.route('/stats', methods=["GET", "POST"])
def stats():
    if request.method == "GET":
        urls_list = cur.execute(f'SELECT * FROM urls WHERE username = "{session["username"]}"').fetchall()
        return render_template('stats.html', urls=urls_list)
    if request.method == "POST":
        urls_list = cur.execute(f'SELECT * FROM urls WHERE username = "{session["username"]}"').fetchall()
        return render_template('stats.html', urls=urls_list)


@app.route('/delete/<del_id>')
def delete(del_id):
    cur.execute(f'DELETE FROM urls WHERE id = "{del_id}" AND username = "{session["username"]}"').fetchall()
    con.commit()
    return redirect(url_for('stats'))


@app.route('/delete_user/<del_id>')
def delete_user(del_id):
    cur.execute(f'DELETE FROM users WHERE id = "{del_id}"')
    con.commit()
    return redirect(url_for('admin'))


@app.route('/update/<del_id>')
def delete_attr(del_id):
    print(del_id)
    cur.execute(f'UPDATE urls SET human_url = "" WHERE id = "{del_id}" AND username = "{session["username"]}"').fetchall()
    con.commit()
    return redirect(url_for('stats'))


@app.route('/edit/<edit_id>', methods=["GET", "POST"])
def edit(edit_id):
    form = EditLinkForm()
    if request.method == "GET":
        return render_template('edit_form.html', form=form)
    if request.method == "POST" and form.validate():
        human_url = request.host_url + form.human_link.data
        cur.execute(f'UPDATE urls SET human_url = "{human_url}", '
                    f'link_type = "{form.link_type.data}" WHERE id = "{edit_id}" AND username = "{session["username"]}"').fetchall()
        con.commit()
        return redirect(url_for('stats'))
    return render_template('edit_form.html', form=form)


@app.route('/authorize/<url>/', methods=['GET', 'POST'])
def authorize(url):
    form = AuthorizationForm()
    if request.method == 'POST' and form.validate():
        usr_pass = cur.execute(f"SELECT password FROM users WHERE username = '{form.username.data}'").fetchone()
        if not usr_pass:
            flash("Current user doesn't exists")
            return render_template('authorize.html', form=form)
        else:
            if bcrypt.checkpw(form.password.data.encode("utf8"), usr_pass[0].encode("utf8")):
                session['username'] = form.username.data
                access_token = create_access_token(identity=form.username.data,
                                                   expires_delta=datetime.timedelta(seconds=expiration_time))
                redirect_url = request.host_url + url
                resp = make_response(redirect(f"{redirect_url}"))
                set_access_cookies(resp, access_token)
                return resp
            else:
                flash("Wrong password")
                return render_template('authorize.html', form=form)
    if request.method == 'GET':
        return render_template('authorize.html', form=form)
    else:
        return render_template('authorize.html', form=form)


@app.route('/about_us', methods=['GET', "POST"])
def about():
    if request.method == "GET":
        return render_template('about.html')


@app.route('/admin', methods=['GET', "POST"])
def admin():
    if session['username'] =='Admin':
        urls = cur.execute("SELECT * FROM users")
        if request.method == "GET":
            return render_template('admin.html', urls=urls)
        if request.method == "POST":
            return render_template('admin.html', urls=urls)
    else:
        flash("Login as 'Admin' and try again")
        return redirect(url_for('log'))


@app.route('/free_link', methods=['GET', "POST"])
def free_link():
    form = FreeLinkForm()
    if request.method == "GET":
        return render_template('free_link.html', form=form)
    if request.method == 'POST' and form.validate():
        url_cnt = con.execute('SELECT COUNT(*) FROM urls').fetchall()
        hash_symbols = math.log2(url_cnt[0][0])//4
        if hash_symbols < 8:
            HASH_SIZE = 8
        else:
            HASH_SIZE = hash_symbols
        hash_id = hashlib.sha256(uuid.uuid4().hex.encode()+form.source_link.data.encode()).hexdigest()[-HASH_SIZE:]
        short_url = request.host_url + hash_id
        con.execute(f'INSERT INTO urls (original_url, short_url,  link_type, username) VALUES '
                    f'("{form.source_link.data}","{short_url}",'
                    f' "1", "{session["username"]}")')
        con.commit()
        return render_template('free_link.html', form=form, short_url=short_url)
    return render_template('free_link.html', form=form)


if __name__ == "__main__":
    app.run(port=5000)
