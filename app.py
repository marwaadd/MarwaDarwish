import json
import flask
from aiohttp import FlowControlDataQueue
from flask import Flask, render_template, g, redirect, url_for , request , session
import flask_oidc
import flask_pymongo
from flask_restful import Api , Resource , abort ,fields , marshal_with
from flask_pymongo import PyMongo
from flask import jsonify
import flask_restful 
import numpy as np
from flask_oidc import OpenIDConnect
import requests
import logging
import hashlib
from flask_jwt_extended import JWTManager ,jwt_required, get_jwt_identity ,create_access_token

import datetime

app = Flask(__name__)
api = Api(app)
app.config["MONGO_URI"] = "mongodb://localhost:27017/Marwa"
mongodb_client = PyMongo(app)
db = mongodb_client.db
# mongo = PyMongo(app)


app = flask.Flask(__name__)

# class Category(db.Document):
#     name = db.StringField()
#     email = db.StringField()



@app.route("/add_Category")
def add_Category():
    db.Category.insert_one({'Name': "Vegitable", 'Product': [{
    'name': "apple",
 
    'comment': "Awesome blog post"
  }]})
    return flask.jsonify(message="success")




@app.route("/add_Product")
def add_Product():
    db.Product.insert_one({'Name': "apple", 'Descrption': ['good']})
    return flask.jsonify(message="success")

    
@app.route('/getAllCategory')
def getAllCategory():
    products= db.Category
    output=[]
    for i in products.find():
        output.append({'Name':i['Name']})
    return jsonify({'result':output})



@app.route('/getProuductsFromCategory/<name>' , methods=['GET'])
def getProuductsFromCategory(name):
    Category=db.Category
    output=[]

    
    for i in Category.find({"Name": name }):
        output.append({'Product':i['Product']})
    return jsonify({'result':output})


@app.route('/deleteCategory/<name>' , methods=['GET'])
def deleteCategory(name):
    Category=db.Category
 
    Category.delete_one({"Name": name })
    
    return 'ok'

@app.route('/update_category/<name>' , methods=['POST', 'GET'])
def update_category(name):
    Category=db.Category
   
    item = Category.find_one({'Name': name})

   

    Category.update_one({"_id": 'ObjectId(id)'},
                    { "$set": {
                                "Name": request.form.get('Name'),
                                "Product": request.form.get('Product'),
                               
                                }
                    })
    return 'Updated, success'


jwt = JWTManager(app) # initialize JWTManager
app.config['JWT_SECRET_KEY'] = 'Your_Secret_Key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1) # define the life span of the token

@app.route("/api/v1/login", methods=["post"])
def login():
	login_details = request.get_json() # store the json body request
	user_from_db = db.find_one({'username': login_details['username']})  # search for user in database

	if user_from_db:
		encrpted_password = hashlib.sha256(login_details['password'].encode("utf-8")).hexdigest()
		if encrpted_password == user_from_db['password']:
			access_token = create_access_token(identity=user_from_db['username']) # create jwt token
			return jsonify(access_token=access_token), 200

	return jsonify({'msg': 'The username or password is incorrect'}), 401


@app.route("/api/v1/users", methods=["POST"])
def register():
	new_user = request.get_json() # store the json body request
	new_user["password"] = hashlib.sha256(new_user["password"].encode("utf-8")).hexdigest() # encrpt password
	doc = db.find_one({"username": new_user["username"]}) # check if user exist
	if not doc:
		db.insert_one(new_user)
		return jsonify({'msg': 'User created successfully'}), 201
	else:
		return jsonify({'msg': 'Username already exists'}), 409



@app.route("/api/v1/user", methods=["GET"])
@jwt_required
def profile():
	current_user = get_jwt_identity() # Get the identity of the current user
	user_from_db = db.find_one({'username' : current_user})
	if user_from_db:
		del user_from_db['_id'], user_from_db['password'] # delete data we don't want to return
		return jsonify({'profile' : user_from_db }), 200
	else:
		return jsonify({'msg': 'Profile not found'}), 404

if __name__ == "__main__":

    app.run(debug=True)