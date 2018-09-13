from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from sqlalchemy import *


app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"


engine = create_engine('sqlite:///categorywithusers.db')
Base.metadata.bind = engine

Session = sessionmaker(bind=engine)


# Create anti-forgery state token


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

# Google Login Page


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
                -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session = Session()
    try:
        session.add(newUser)
        session.commit()
        user = session.query(User).filter_by(
            email=login_session['email']).one_or_none()
        return user.id
    except:
        session.rollback()
    finally:
        session.close()


def getUserInfo(user_id):
    session = Session()
    try:
        user = session.query(User).filter_by(id=user_id).one_or_none()
        return user
    except:
        session.rollback()
    finally:
        session.close()


def getUserID(email):
    session = Session()
    try:
        user = session.query(User).filter_by(email=email).one_or_none()
        session.commit()
        return user.id
    except:
        return None
    finally:
        session.close()

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategory'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategory'))

# END of Google Login Page


# JSON APIs to view Catalog Information

@app.route('/category/<int:category_id>/items/JSON')
def catalogItemsJSON(category_id):
    session = Session()
    try:
        category = session.query(Category).filter_by(
            id=category_id).one_or_none()
        items = session.query(Item).filter_by(
            category_id=category_id).all()
        return jsonify(Items=[i.serialize for i in items])
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()


@app.route('/category/<int:category_id>/items/<int:item_id>/JSON')
def ItemJSON(category_id, item_id):
    session = Session()
    try:
        item = session.query(Item).filter_by(id=item_id).one_or_none()
        return jsonify(Item=item.serialize)
    except:
        session.rollback()
        raise
    finally:
        session.close()


@app.route('/category/JSON')
def categoryJSON():
    session = Session()
    try:
        category = session.query(Category).all()
        return jsonify(category=[r.serialize for r in category])
    except:
        session.rollback()
        raise
    finally:
        session.close()
# END OF JSON APIs to VIEW Catalog Information


# Show all Category in catalog
@app.route('/')
@app.route('/category/')
def showCategory():
    session = Session()
    try:
        category = session.query(Category)
        items = session.query(Item)
        session.commit()
        if 'username' not in login_session:
            return render_template(
                'publicCategory.html', category=category, items=items)
        else:
            return render_template('category.html',
                                   category=category, items=items)
    except:
        session.rollback()
        raise
    finally:
        session.close()


#  CRUD OPERATIONS FOR CATEGORY
# Create a new category


@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        session = Session()
        try:
            newCategory = Category(
                name=request.form['name'], user_id=login_session['user_id'])
            session.add(newCategory)
            flash('New Category %s Successfully Created' % newCategory.name)
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.close()
        return redirect(url_for('showCategory'))
    else:
        return render_template('newCategory.html')

# # Edit Category


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    session = Session()
    try:
        editedCategory = session.query(
            Category).filter_by(id=category_id).one_or_none()
        if 'username' not in login_session:
            return redirect('/login')
        if editedCategory.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are \
            not authorized to edit this Category');\
            window.location.href = '/';\
            }</script><body onload='myFunction()'>"
        if request.method == 'POST':
            if request.form['name']:
                editedCategory.name = request.form['name']
            session.add(editedCategory)
            session.commit()
            flash('Category Successfully Edited %s' % editedCategory.name)
            return redirect(url_for('showCategory'))
        else:
            return render_template('editCategory.html',
                                   category=editedCategory)
    except:
        session.rollback()
        raise
    finally:
        session.close()


#  Delete a Category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    session = Session()
    try:
        categoryToDelete = session.query(
            Category).filter_by(id=category_id).one_or_none()
        if 'username' not in login_session:
            return redirect('/login')
        if categoryToDelete.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are not \
            authorized to delete this Category');}\
            </script><body onload='myFunction()'>"
        session.delete(categoryToDelete)
        session.commit()
        flash('%s Successfully Deleted' % categoryToDelete.name)
    except:
        session.rollback()
        raise
    finally:
        session.close()
    return redirect(url_for('showCategory', category_id=category_id))


# END OF CATEGORY CRUD OPERATIONS

@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/items')
def categoryItem(category_id):
    session = Session()
    try:
        category = session.query(Category).filter_by(
            id=category_id).one_or_none()
        creator = getUserInfo(category.user_id)
        items = session.query(Item).filter_by(category_id=category.id).all()
        session.commit()
        if 'username' not in login_session or\
                creator.id != login_session['user_id']:
            return render_template(
                'categoryIndividual.html', category=category, items=items,
                creator=creator)
        else:
            return render_template(
                'publicCategoryIndividual.html', category=category,
                items=items, creator=creator)
    except:
        session.rollback()
        raise
    finally:
        session.close()

# ITEM CRUD OPERATIONS

# Displaying individual item


@app.route('/category/<int:category_id>/items/<int:item_id>')
def showItem(category_id, item_id):
    session = Session()
    try:
        category = session.query(Category).filter_by(
            id=category_id).one_or_none()
        creator = getUserInfo(category.user_id)
        items = session.query(Item).filter_by(
            id=item_id, category_id=category.id).one_or_none()
        session.commit()
        if 'username' not in login_session\
                or creator.id != login_session['user_id']:
            return render_template(
                'itemIndividual.html', category=category,
                items=items, creator=creator)
        else:
            return render_template(
                'itemIndividual.html', category=category,
                items=items, creator=creator)
    except:
        session.rollback()
        raise
    finally:
        session.close()


# Create a new  item
@app.route('/category/<int:category_id>/items/new/', methods=['GET', 'POST'])
def newItem(category_id):
    session = Session()
    try:
        if 'username' not in login_session:
            return redirect('/login')
        category = session.query(Category).filter_by(
            id=category_id).one_or_none()
        if login_session['user_id'] != category.user_id:
            return "<script>function myFunction() {alert('You are not \
            authorized to add items to this category.');}</script>\
            <body onload='myFunction()'>"
        if request.method == 'POST':
            newItem = Item(
                name=request.form['name'],
                description=request.form['description'],
                category_id=category_id, user_id=category.user_id)
            session.add(newItem)
            session.commit()
            flash('New Item Successfully Created')
            return redirect(url_for('categoryItem', category_id=category_id))
        else:
            return render_template('addItem.html', category_id=category_id)
    except:
        session.rollback()
        raise
    finally:
        session.close()

# Edit a  item


@app.route(
    '/category/<int:category_id>/items/<int:item_id>/edit',
    methods=['GET', 'POST'])
def editItem(category_id, item_id):
    session = Session()
    try:
        if 'username' not in login_session:
            return redirect('/login')
        editedItem = session.query(Item).filter_by(
            category_id=category_id, id=item_id).one_or_none()
        category = session.query(Category).filter_by(
            id=category_id).one_or_none()
        if login_session['user_id'] != category.user_id:
            return "<script>function myFunction() {alert('You are not \
            authorized to edit items to this Category.\
            ');window.location.href = '/';}\
            </script><body onload='myFunction()'>"
        if request.method == 'POST':
            if request.form['name']:
                editedItem.name = request.form['name']
            if request.form['description']:
                editedItem.description = request.form['description']
            session.add(editedItem)
            session.commit()
            flash(' Item Successfully Edited')
            return redirect(url_for('categoryItem', category_id=category.id))
        else:
            return render_template('editItem.html', category=category)
    except:
        session.rollback()
        raise
    finally:
        session.close()


# Delete a  item
@app.route(
    '/category/<int:category_id>/items/<int:item_id>/delete',
    methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    session = Session()
    try:
        if 'username' not in login_session:
            return redirect('/login')
        category = session.query(Category).filter_by(
            id=category_id).one_or_none()
        itemToDelete = session.query(Item).filter_by(
            category_id=category_id, id=item_id).one_or_none()
        if login_session['user_id'] != category.user_id:
            return "<script>function myFunction() {alert('You are \
            not authorized to delete items \
            to this Category.');}</script>\
             <body onload='myFunction()'>"
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
    except:
        session.rollback()
        raise
    finally:
        session.close()
    return redirect(url_for('categoryItem', category_id=category_id))


# END OF ITEM CRUD OPERATIONS
if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'super_secret_key'
    app.run(host='0.0.0.0', port=5000)
