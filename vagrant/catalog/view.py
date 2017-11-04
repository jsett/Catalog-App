from models import Base, User, Catagory, Item
from flask import Flask, jsonify, request, url_for, abort
from flask import g, render_template, redirect, url_for
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from flask.ext.httpauth import HTTPBasicAuth
import json

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests

auth = HTTPBasicAuth()

engine = create_engine('sqlite:///Catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


@auth.verify_password
def verify_password(username_or_token, password):
    print "verify_password"
    # Check if session has the token if not check the username
    if (hasattr(session, 'mytoken')):
        if (session.mytoken != ''):
            print "verify by session token"
            # sesson.mytoken has the token
            user_id = User.verify_auth_token(session.mytoken)
        else:
            # check user the user name
            user_id = User.verify_auth_token(username_or_token)
    else:
        # check the user name
        user_id = User.verify_auth_token(username_or_token)

    if user_id:
        print "token"
        # verify the token
        user = session.query(User).filter_by(id=user_id).one()
    else:
        print "password"
        # verify using password
        user = session.query(User).filter_by(username=username_or_token)
        user = user.first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    session.cur_user = user
    return True


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    auth_code = request.json.get('auth_code')
    # login using google
    if provider == 'google':
        try:
            oauth_flow = flow_from_clientsecrets('client_secrets.json',
                                                 scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            mmesg = 'Failed to upgrade the authorization code.'
            response = make_response(json.dumps(mmesg), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # we now have the acess token
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
               % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        # get the users info
        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']

        # check to see if the user is in our database
        user = session.query(User).filter_by(email=email).first()
        if not user:
            # add the user to the database
            user = User(username=name, picture=picture, email=email)
            session.add(user)
            session.commit()

        # generate a token for the user
        token = user.generate_auth_token(600)

        # add the token to the session
        session.mytoken = token

        return jsonify({'token': token.decode('ascii')})
    else:
        return 'Unrecoginized Provider'


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/users', methods=['POST'])
def new_user():
    # create a new users
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        print "missing arguments"
        abort(400)

    if session.query(User).filter_by(username=username).first() is not None:
        print "existing user"
        user = session.query(User).filter_by(username=username).first()
        return jsonify({'message': 'user already exists'}), 200

    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({'username': user.username}), 201


@app.route('/user_login', methods=["GET", "POST"])
def get_user_login():
    if request.method == 'POST':
        username = request.form['UserName']
        password = request.form['Password']
        # if user name or password is empty then return error on loging screen
        if username is None or password is None:
            lnerror = True
            return render_template('user_login.html', lnerror=lnerror)

        # if the user exist then verify password and set token
        user = session.query(User).filter_by(username=username).first()
        if user is not None:
            # password is wrong return error
            if not user or not user.verify_password(password):
                lnerror = True
                return render_template('user_login.html', lnerror=lnerror)
            else:
                # password is correct set the token and redirect to index
                token = user.generate_auth_token(600)
                session.mytoken = token
                return redirect(url_for('get_index'))

        # the user does not exist so create one then redirect to index
        user = User(username=username)
        user.hash_password(password)
        session.add(user)
        session.commit()
        token = user.generate_auth_token()
        session.mytoken = token
        return redirect(url_for('get_index'))

    lnerror = False
    return render_template('user_login.html', lnerror=lnerror)


@app.route('/user_logout')
@auth.login_required
def get_user_logout():
    # clear the session to logout the user
    session.mytoken = ""
    return redirect(url_for('get_index'))


@app.route('/index')
def get_index():
    data = {}
    data['home'] = True
    data['title'] = "Catalog App"
    data["logged_in"] = False
    if (hasattr(session, 'mytoken')):
        if (session.mytoken != ''):
            data["logged_in"] = True
    # get the categorys and lates 30 items
    c = session.query(Catagory).order_by(-Catagory.id.desc()).all()
    itm = session.query(Item).order_by(-Item.id.desc()).limit(30).all()
    data['cats'] = c
    data['items'] = itm
    return render_template('index.html', data=data)


@app.route('/category/create')
@auth.login_required
def get_create_category():
    # renders the category form
    data = {}
    data['title'] = "Create Category"
    data['home'] = False
    data["logged_in"] = False
    if (hasattr(session, 'mytoken')):
        if (session.mytoken != ''):
            data["logged_in"] = True
    return render_template('category_create.html', data=data)


@app.route('/category/read/<int:id>')
def get_read_category(id):
    # renders the category viewer
    data = {}
    data['title'] = "Read Category"
    data['home'] = False
    data["logged_in"] = False
    if (hasattr(session, 'mytoken')):
        if (session.mytoken != ''):
            data["logged_in"] = True
    try:
        c = session.query(Catagory).filter_by(id=id).one()
        itm = session.query(Item).filter_by(catagory_id=c.id).all()
        data['cat'] = c
        data['items'] = itm
    except:
        return redirect(url_for('get_index'))
    return render_template('category_read.html', data=data)


@app.route('/category/update/<int:id>')
@auth.login_required
def get_edit_category(id):
    # renders the category update form
    data = {}
    data['title'] = "Update Category"
    data['home'] = False
    data["logged_in"] = False
    if (hasattr(session, 'mytoken')):
        if (session.mytoken != ''):
            data["logged_in"] = True
    try:
        c = session.query(Catagory).filter_by(id=id).one()
    except:
        return redirect(url_for('get_index'))
    data['c'] = c
    return render_template('category_update.html', data=data)


@app.route('/item/create')
@auth.login_required
def get_create_item():
    # renders the item form
    data = {}
    data['title'] = "Create Item"
    data['home'] = False
    data["logged_in"] = False
    if (hasattr(session, 'mytoken')):
        if (session.mytoken != ''):
            data["logged_in"] = True
    cats = session.query(Catagory).order_by(-Catagory.id.desc()).all()
    data['cats'] = cats
    return render_template('item_create.html', data=data)


@app.route('/item/read/<int:id>')
def get_read_item(id):
    # renders the item viewer
    data = {}
    data['title'] = "Create Item"
    data['home'] = False
    data["logged_in"] = False
    if (hasattr(session, 'mytoken')):
        if (session.mytoken != ''):
            data["logged_in"] = True
    try:
        c = session.query(Item).filter_by(id=id).one()
        cat = session.query(Catagory).filter_by(id=c.catagory_id).one()
    except:
        return redirect(url_for('get_index'))
    data['c'] = {"id": c.id,
                 "title": c.title,
                 "description": c.description,
                 "catagory": cat.title,
                 "catagory_id": cat.id,
                 "catagory_description": cat.description}
    return render_template('item_read.html', data=data)


@app.route('/item/update/<int:id>')
@auth.login_required
def get_edit_item(id):
    # renders the item update form
    data = {}
    data['title'] = "Create Item"
    data['home'] = False
    data["logged_in"] = False
    if (hasattr(session, 'mytoken')):
        if (session.mytoken != ''):
            data["logged_in"] = True
    try:
        c = session.query(Item).filter_by(id=id).one()
        cats = session.query(Catagory).order_by(-Catagory.id.desc()).all()
    except:
        return redirect(url_for('get_index'))
    data['c'] = {"c": c, "cats": cats}
    return render_template('item_update.html', data=data)


@app.route('/api/v1/category/create', methods=['POST'])
@auth.login_required
def v1_create_category():
    # api endpoint to create a category
    title = request.json.get('title')
    description = request.json.get('description')
    cat = Catagory(title=title,
                   description=description,
                   created_by=session.cur_user.username)
    session.add(cat)
    session.commit()
    cid = cat.id
    return jsonify({'id': cid})


@app.route('/api/v1/category/read/<int:id>', methods=['GET'])
@auth.login_required
def v1_read_category(id):
    # api endpoint to read a category
    c = session.query(Catagory).filter_by(id=id).one()
    return jsonify({"id": c.id,
                    "title": c.title,
                    "description": c.description,
                    "created_by": c.created_by})


@app.route('/api/v1/category/update/<int:id>', methods=['POST'])
@auth.login_required
def v1_update_category(id):
    # api endpoint to update a category
    c = session.query(Catagory).filter_by(id=id).one()
    if (session.cur_user.username != c.created_by):
            return jsonify({"error": "Must Be Created By Same User"})
    c.title = request.json.get('title')
    c.description = request.json.get('description')
    session.commit()
    return jsonify({"id": c.id,
                    "title": c.title,
                    "description": c.description,
                    "created_by": c.created_by})


@app.route('/api/v1/category/delete/<int:id>', methods=['DELETE'])
@auth.login_required
def v1_delete_category(id):
    # api endpoint to delete a category
    c = session.query(Catagory).filter_by(id=id).one()
    if (session.cur_user.username != c.created_by):
            return jsonify({"error": "Must Be Created By Same User"})
    session.delete(c)
    session.commit()
    return jsonify({"res": "ok"})


@app.route('/api/v1/item/create', methods=['POST'])
@auth.login_required
def v1_create_item():
    # api endpoint to create a item
    title = request.json.get('title')
    description = request.json.get('description')
    cat = request.json.get('catagory')
    cat = session.query(Catagory).filter_by(id=cat).one()
    itm = Item(title=title,
               description=description,
               catagory_id=cat.id,
               created_by=session.cur_user.username)
    session.add(itm)
    session.commit()
    cid = itm.id
    return jsonify({'id': cid})


@app.route('/api/v1/item/read/<int:id>', methods=['GET'])
@auth.login_required
def v1_read_item(id):
    # api endpoint to read a item
    c = session.query(Item).filter_by(id=id).one()
    cat = session.query(Catagory).filter_by(id=c.catagory_id).one()
    return jsonify({"id": c.id,
                    "title": c.title,
                    "description": c.description,
                    "catagory": cat.title,
                    "catagory_id": cat.id,
                    "catagory_description": cat.description})


@app.route('/api/v1/item/update/<int:id>', methods=['POST'])
@auth.login_required
def v1_update_item(id):
    # api endpoint to update a item
    c = session.query(Item).filter_by(id=id).one()
    if (session.cur_user.username != c.created_by):
            return jsonify({"error": "Must Be Created By Same User"})
    c.title = request.json.get('title')
    c.description = request.json.get('description')
    cat = request.json.get('catagory')
    cat = session.query(Catagory).filter_by(id=cat).one()
    c.catagory_id = cat.id

    session.commit()
    return jsonify({"id": c.id,
                    "title": c.title,
                    "description": c.description,
                    "catagory": cat.title,
                    "catagory_id": cat.id,
                    "catagory_description": cat.description})


@app.route('/api/v1/item/delete/<int:id>', methods=['DELETE'])
@auth.login_required
def v1_delete_item(id):
    # api endpoint to delete a item
    c = session.query(Item).filter_by(id=id).one()
    if (session.cur_user.username != c.created_by):
            return jsonify({"error": "Must Be Created By Same User"})
    session.delete(c)
    session.commit()
    return jsonify({"res": "ok"})

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
