import bcrypt
import requests
from flask import Flask, render_template, url_for, redirect, flash, session, request, make_response
from flask_jwt_extended import JWTManager, set_access_cookies
from forms import SignUpForm, RegisterForm, CreateLinkForm, EditLinkForm, AuthorizationForm, FreeLinkForm

app = Flask(__name__, template_folder='../templates')
app.config['SECRET_KEY'] = 'sdgjh48i3kjg'
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

app.config['JWT_TOKEN_LOCATION'] = ['cookies']

app.config["JWT_SECRET_KEY"] = "super-secret"

jwt = JWTManager(app)
salt = bcrypt.gensalt()
expiration_time = 200
backend_port = 5001

cookies = {'access_token_cookie': ""}


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    flash("Your JWT token has been expired.")
    return redirect(f"{request.host_url}/authorize/{session['URL']}")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == "POST" and form.validate():
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}/register?'
                             f'username={form.username.data}&password={form.password.data}'
                             f'&valid_password={form.valid_password.data}')
        if resp.status_code > 202:
            flash(f"{resp.json()['msg']}")
            return render_template('register.html', form=form)
        flash(f"{resp.json()['msg']}")
        return redirect(url_for('log'))
    if request.method == 'GET':
        return render_template('register.html', form=form)
    else:
        return render_template('register.html', form=form)


@app.route('/', methods=['GET', 'POST'])
@app.route('/log', methods=['GET', 'POST'])
def log():
    global cookies
    session['username'] = "guest"
    form = SignUpForm()
    if request.method == 'POST' and form.validate():
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}?'
                             f'username={form.username.data}&password={form.password.data}')
        if resp.status_code > 202:
            flash(f"{resp.json()}")
            return render_template('login.html', form=form)
        session['username'] = form.username.data
        respon = make_response(redirect(url_for('linkage')))
        cookies = {'access_token_cookie': request.cookies.get('access_token')}
        set_access_cookies(respon, resp.json()['JWT'])
        respon.set_cookie('access_token', resp.json()['JWT'])
        return respon
    if request.method == 'GET':
        return render_template('login.html', form=form)
    else:
        return render_template('login.html', form=form)


@app.route('/linkage', methods=['GET', 'POST'])
def linkage():
    global cookies
    if session['username'] == "guest":
        flash('Login please!')
        return redirect(url_for('log'))
    form = CreateLinkForm()
    if request.method == 'POST' and form.validate():
        print(form.source_link.data)
        print(form.link_type.data)
        print(form.human_link.data)
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}/linkage?'
                             f'source_link={form.source_link.data}'
                             f'&human_link={form.human_link.data}'
                             f'&link_type={form.link_type.data}'
                             f'&username={session["username"]}', cookies=cookies)
        if resp.status_code > 202:
            flash(resp.json()['msg'])
            return render_template('linkage.html', form=form,
                                   short_url=None,
                                   human_url=None)
        else:
            return render_template('linkage.html', form=form,
                                   short_url=resp.json()['short_url'],
                                   human_url=resp.json()['attribute'])

    if request.method == 'GET':
        return render_template('linkage.html', form=form,
                               short_url=None,
                               human_url=None)
    else:
        return render_template('linkage.html', form=form,
                               short_url=None,
                               human_url=None)


@app.route('/<url_name>/')
def url_redirect(url_name):
    session['URL'] = url_name
    full_url = request.host_url + url_name
    cookies = {'access_token_cookie': request.cookies.get('access_token')}
    resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}/{url_name}/?'
                         f'full_url={full_url}', cookies=cookies)
    if resp.status_code <= 202:
        return redirect(resp.json()['original_id'])
    if resp.status_code == 403:
        flash("Please, authorize!")
        return redirect(f"{request.host_url}/authorize/{url_name}")
    else:
        return redirect(f"{request.host_url}/authorize/{url_name}")


@app.route('/page404', methods=["GET", "POST"])
def err_page():
    if request.method == "GET":
        return render_template('page404.html')


@app.route('/stats', methods=["GET", "POST"])
def stats():
    if request.method == "GET":
        cookies = {'access_token_cookie': request.cookies.get('access_token')}
        resp = requests.get(f'{request.host_url.partition(":5")[0]}:{backend_port}/stats?'
                            f'username={session["username"]}', cookies=cookies)
        if resp.status_code > 202:
            flash(resp.json()['msg'])
            return redirect(url_for('log'))
        urls_list = resp.json()["urls_list"]
        return render_template('stats.html', urls=urls_list)


@app.route('/delete/<del_id>')
def delete(del_id):
    resp = requests.delete(f'{request.host_url.partition(":5")[0]}:{backend_port}/stats?'
                           f'username={session["username"]}'
                           f'&del_id={del_id}', cookies=cookies)
    if resp.status_code > 202:
        flash(resp.json()['msg'])
    return redirect(url_for('stats'))


@app.route('/delete_user/<del_id>')
def delete_user(del_id):
    resp = requests.delete(f'{request.host_url.partition(":5")[0]}:{backend_port}/delete_user?'
                           f'&del_id={del_id}', cookies=cookies)
    if resp.status_code > 202:
        flash(resp.json()['msg'])
    return redirect(url_for('admin'))


@app.route('/update/<del_id>')
def delete_attr(del_id):
    resp = requests.patch(f'{request.host_url.partition(":5")[0]}:{backend_port}/stats?'
                           f'username={session["username"]}'
                           f'&del_id={del_id}', cookies=cookies)
    if resp.status_code > 202:
        flash(resp.json()['msg'])
    return redirect(url_for('stats'))


@app.route('/edit/<edit_id>', methods=["GET", "POST"])
def edit(edit_id):
    form = EditLinkForm()
    if request.method == "GET":
        return render_template('edit_form.html', form=form)
    if request.method == "POST" and form.validate():
        if form.human_link.data:
            human_url = request.host_url + form.human_link.data
        else:
            human_url = ""
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}/stats?'
                              f'username={session["username"]}'
                              f'&edit_id={edit_id}'
                              f'&psydo={human_url}'
                              f'&link_type={form.link_type.data}', cookies=cookies)
        if resp.status_code > 202:
            flash(resp.json()['msg'])
        return redirect(url_for('stats'))
    return render_template('edit_form.html', form=form)


@app.route('/authorize/<url>/', methods=['GET', 'POST'])
def authorize(url):
    form = AuthorizationForm()
    if request.method == 'POST' and form.validate():
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}/authorize/{url}/?'
                             f'username={form.username.data}'
                             f'&password={form.password.data}')
        if resp.status_code <= 202:
            response = make_response(redirect(resp.json()['redirect_url']))
            response.set_cookie('access_token', resp.json()['access_token'])
            return response
        else:
            flash(resp.json()['msg'])
            return render_template('authorize.html', form=form)
    if request.method == 'GET':
        return render_template('authorize.html', form=form)
    else:
        return render_template('authorize.html', form=form)


@app.route('/about_us', methods=['GET', "POST"])
def about():
    if request.method == "GET":
        return render_template('about.html')


@app.route('/free_link', methods=['GET', "POST"])
def free_link():
    form = FreeLinkForm()
    if request.method == "GET":
        return render_template('free_link.html', form=form)
    if request.method == 'POST' and form.validate():
        resp = requests.post(f'{request.host_url.partition(":5")[0]}:{backend_port}/free_link?'
                             f'source_link={form.source_link.data}')
        if resp.status_code > 202:
            flash("Something goes wrong!")
            return redirect(url_for("err_page"))
        short_url = resp.json()['short_url']
        return render_template('free_link.html', form=form, short_url=short_url)
    return render_template('free_link.html', form=form)


if __name__ == "__main__":
    app.run(port=5000)
