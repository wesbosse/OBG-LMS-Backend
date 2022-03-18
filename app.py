import os
import time
import jwt
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize environment variables 
app = Flask(__name__)
app.config['SECRET_KEY'] = 'OBG-Test'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# Initialize Extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

class User(db.Model):
    __tablename__ = 'users'

    # Create an inline user model
    # TODO: migrate to individual model files
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index = True)
    password_hash = db.Column(db.String(64))

    # Using werkzeug methods for password hashing
    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # Creating auth tokens using our secret key with a 10 minute expiration
    def generate_auth_token(self, expires_in = 600):
        return jwt.encode({'id': self.id, 'exp': time.time() + expires_in }, 
                          app.config['SECRET_KEY'],
                          algorithm='HS256')

    # method for attempting to decode the token, returning the user if successful
    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, 
                              app.config['SECRET_KEY'],
                              algorithm=['HS256'])
        except:
            return 
        
        return User.query.get(data['id'])

@auth.verify_password
def verify_password(username_or_token, password):
    # try token first
    user = User.verify_auth_token(username_or_token)
    
    # try to find the user and then check if the password is valid
    if not user:
        user = User.query.filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False

    # if successful, update global user and return True
    g.user = user
    return True

@app.route('/api/register', methods=['POST'])
def register():
    username = request.json.get('username') 
    password = request.json.get('password')

    # Check for blank requests
    if username is None or password is None:
        abort(400)
    
    # Check for existing users
    if User.query.filter_by(username = username).first() is not None:
        abort(400)
    
    # Create a new user instance and set the password
    user = User(username = username)
    user.hash_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    return (jsonify({'username': user.username}), 201)


@app.route('/api/login')
@auth.login_required
def get_token():
    token = g.user.generate_auth_token(600)
    return jsonify({ 'token': token.decode('ascii'), 'duration': 600 })


if __name__ == "__main__":
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
