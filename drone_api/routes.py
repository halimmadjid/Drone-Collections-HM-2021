from drone_api import app, db, oauth  
from flask import render_template, request, redirect, url_for, flash, session, jsonify

#drone_api module imports
from drone_api.forms import UserLoginForm
from drone_api.models import User, check_password_hash, Drone, drone_schema, drones_schema

#Imports for flask login
from flask_login import login_user, logout_user, current_user, login_required

import os 
from drone_api.helpers import get_jwt, token_required, verify_owner
# Home Route  -- AKA Main Landing Page Route (This is where users will fall to our project)
@app.route('/')
def home(): 
    return render_template('home.html')

@app.route('/signup', methods = ['GET', 'POST'])
# signin = route(signin)
def signup(): 
    form = UserLoginForm()

    try: 

        if request.method == 'POST' and form.validate_on_submit(): 
            email = form.email.data
            password = form.password.data
            print(email,password)

            user = User(email, password = password)

            db.session.add(user)
            db.session.commit() #it means to save it to the database
            return redirect(url_for('signin'))
    except:
        raise Exception('Invalid Form Data: Please check your form')
    
    return render_template('signup.html', form=form)

@app.route('/signin', methods = ['GET', 'POST'])
def signin(): 
    form = UserLoginForm()

    try: 
        if request.method == 'POST' and form.validate_on_submit(): 
            email = form.email.data
            password = form.password.data 
            print(email,password)

            logged_user = User.query.filter(User.email == email).first()
            if logged_user and check_password_hash(logged_user.password, password): 
                login_user(logged_user)
                flash('You were successfully logged in: Via Email/Password')

                return redirect(url_for('home'))
            else: 
                flash('Your Email/Password is incorrect', 'auth-failed')
                return redirect(url_for('signin'))
    except: 
        raise Exception('Invalid FOrm Data: Please check your form')
    return render_template('signin.html', form=form)

@app.route('/logout')
@login_required
def logout(): 
    logout_user()
    if session: 
        for key in list(session.keys()): 
            session.pop(key)
    return redirect(url_for('home'))

@app.route('/profile', methods = ['GET'])
@login_required
def profile():
    jwt = get_jwt(current_user)
    return render_template('profile.html', jwt = jwt)

#verify_token = token_verify(token)

#The following is CRUD (Create, read, update and delete) Operations: 

#CREATE DRONE ENDPOINT
@app.route('/drones', methods = ['POST'])
@token_required
def create_drone(current_user_token):
    print(current_user_token)
    name = request.json['name']
    price = request.json['price']
    model = request.json['model']
    user_id = current_user_token.token

    drone = Drone(name,price,model, user_id=user_id)
    
    db.session.add(drone)
    db.session.commit()

    response = drone_schema.dump(drone)
    return jsonify(response)

#RETRIEVE ALL DRONEs ENDPOINT (this is also how you create a REST API)
@app.route('/drones', methods = ['GET']) 
@token_required
def get_drones(current_user_token):
    try: 
        owner, current_user_token = verify_owner(current_user_token)
    except: 
        bad_res = verify_owner(current_user_token)
        return bad_res
    owner, current_user_token = verify_owner(current_user_token)
    drones = Drone.query.filter_by(user_id = owner.user_id).all()
    response = drones_schema.dump(drones)
    return jsonify(response)

# RETRIEVE ONE Drone ENDPOINT (similar syntax from above)
@app.route('/drones/<id>', methods = ['GET'])
@token_required
def get_drone(current_user_token, id):
    try: 
        owner, current_user_token = verify_owner(current_user_token)
    except: 
        bad_res = verify_owner(current_user_token)
        return bad_res
    owner, current_user_token = verify_owner(current_user_token)
    drone = Drone.query.get(id)
    response = drone_schema.dump(drone) #dump method will take all info and shapeshift from sql table records so that JSON can understand. 
    return jsonify(response)

# UPDATE DRONE ENDPOINT
@app.route('/drones/<id>', methods = ['POST','PUT'])
@token_required
def update_drone(current_user_token, id):
    try: 
        owner, current_user_token = verify_owner(current_user_token)
    except: 
        bad_res = verify_owner(current_user_token)
        return bad_res 
    owner, current_user_token = verify_owner(current_user_token)
    drone = Drone.query.get(id) # GET DRONE INSTANCE
    drone.name = request.json['name'] #this updates the dabatase
    drone.price = request.json['price']
    drone.model = request.json['model']

    db.session.commit() #this committs it to the database
    response = drone_schema.dump(drone)
    return jsonify(response)


# DELETE DRONE ENDPOINT
@app.route('/drones/<id>', methods = ['DELETE'])
@token_required
def delete_drone(current_user_token, id):
    try: 
        owner, current_user_token = verify_owner(current_user_token)
    except: 
        bad_res = verify_owner(current_user_token)
        return bad_res
    drone = Drone.query.get(id)
    db.session.delete(drone)
    db.session.commit()
    response = drone_schema.dump(drone)
    return jsonify(response)


# Google OAUTH Routes and config info
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
)

@app.route('/google-auth') #the underscore and dash do not have to match. it will give an error.
def google_auth(): 
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external = True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    response = google.get('userinfo')
    user_info = response.json()
    user= oauth.google.userinfo()
    user = User.query.filter_by(email = user_info['email']).first()

    if user:
        user.first_name = user_info['given_name']
        user.last_name = user_info['family_name']
        user.email = user_info['email']
        user.g_auth_verify = user_info['verified_email']

        db.session.add(user)
        db.session.commit()
        login_user(user)
        session.permanent = True
        return redirect(url_for('home'))

    else:
        g_first_name = user_info['given_name']
        g_last_name = user_info['family_name']
        g_email = user_info['email']
        g_verified = user_info['verified_email']

        user = User(
            first_name = g_first_name,
            last_name = g_last_name,
            email = g_email,
            g_auth_verify = g_verified
        )

        db.session.add(user)
        db.session.commit()
        session.permanent = True
        login_user(user)
        return redirect(url_for('home'))

    print(user_info)
    return redirect(url_for('home'))
