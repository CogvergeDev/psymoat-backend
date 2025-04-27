from flask import Flask, request, jsonify, make_response
import controller as dynamodb
import csv
from io import StringIO
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from controller import auth_bp, bcrypt 
from flask_cors import CORS
from dotenv import load_dotenv
import os



load_dotenv()




app = Flask(__name__)



CORS(app, origins=["http://localhost:3000" , "https://psymoat.vercel.app", "https://www.psymoat.in" ], supports_credentials=True)

app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600*12  



jwt = JWTManager(app)
app.register_blueprint(auth_bp)


# TEST ROUTE
@app.route('/test')
@jwt_required()
def test():
    user_id = get_jwt_identity()
    print(user_id)
    print("TEST SUCCESS")
    return 'TEST SUCCESS'

# TABLE CREATION ROUTES
@app.route('/create-user-table')
def create_user_table_route():
    dynamodb.create_user_table()
    return 'User Table created'

@app.route('/create-exam-table')
def create_exam_table_route():
    dynamodb.create_exam_table()
    return 'Exam Table created'

@app.route('/create-module-table')
def create_module_table_route():
    dynamodb.create_module_table()
    return 'Module Table created'


# INITIALIZATION ROUTES
@app.route('/initialize-new-module' , methods=['POST'])
def initialize_new_module():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided."}), 400

    try:
        response = dynamodb.initialize_new_module(data.get('exam_id') , data.get('module_name'))

        if not response:
            return jsonify({"error": "No response recieved."}), 400
        
        return jsonify({"message": f"{data.get('module_name')} is initialized."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/initialize-new-exam' , methods=['POST'])
def initialize_new_exam():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided."}), 400
    
    if not data.get('exam_name'):
        return jsonify({"error": "Exam name not provided."}), 400

    try:
        response = dynamodb.initialize_new_exam(data.get('exam_name'))

        if not response:
            return jsonify({"error": "No response recieved."}), 400
        
        return jsonify({"message": f"{data.get('exam_name')} is initialized."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ADDING MODULES TO DB ROUTE
@app.route('/add-to-module/<string:module_id>', methods=['POST'])
def add_to_module(module_id):
    # data = request.get_json()

    if not module_id:
        return jsonify({"error": "module_id is required"}), 400
    
    file = request.files.get('csv_file')
    if not file:
        return jsonify({"error": "CSV file is required"}), 400
    
    try:
        # Read the file content
        file_content = file.read().decode('utf-8')
        # Use StringIO to make it like a file object for csv reader
        csv_file = StringIO(file_content)
        csv_reader = csv.DictReader(csv_file)
        
        questionResponse = dynamodb.get_module_questions(module_id)
        questions = questionResponse['Item']['questions']
        
        
        # print(questions)
        # questions = []
        
        # Convert CSV rows to JSON and append to the pre-existing array
        for i,row in enumerate(csv_reader):
            # Add ids to the row data
            row['module_id'] = module_id
            row['question_id'] = f"{module_id}_{i+1}"
            # Append row to the pre-existing array
            questions.append(row)

        # print(questions)
        
        # return jsonify({"message": "CSV data processed and added successfully", "data": questions}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


    # this is where controller function is used.
    
    response = dynamodb.add_questions_in_module(module_id, questions)    
    print(response)
    if (response['ResponseMetadata']['HTTPStatusCode'] == 200):
        return {
            'msg': 'Added successfully',
        }
    return {  
        'msg': 'Some error occcured',
        'response': response
    }


@app.route('/get-all-module-details', methods=['GET'])
@jwt_required()
def get_all_module_details():
    try:
        reponse = dynamodb.get_all_module_details()
        return reponse
    except Exception as e:
        return {
            'msg': 'Some error occured',
            'error': str(e)
        }


@app.route('/get-all-exam-details', methods=['GET'])
@jwt_required()
def get_all_exam_details():
    try:
        reponse = dynamodb.get_all_exam_details()
        return reponse
    except Exception as e:  
        return {
            'msg': 'Some error occured',
            'error': str(e)
        }

# GETTING QUESTION FROM A MODULE
@app.route('/get-module-questions/<string:module_id>', methods=['GET'])
@jwt_required()
def get_module_questions(module_id):
    print(module_id)
    try:
        response = dynamodb.get_module_questions(module_id)
        
        if not response:
            return { 'msg': 'No questions found' }, 404
        
        if isinstance(response, dict) and 'ResponseMetadata' in response:
            if response['ResponseMetadata'].get('HTTPStatusCode') == 200:
                if 'Item' in response:
                    return { 'Item': response['Item'] }, 200
                return { 'msg': 'Item not found!' }, 404
        
        return { 'msg': 'Some error occurred', 'response': response }, 500
    
    except KeyError:
        return { 'msg': 'Invalid response structure' }, 500
    except Exception as e:
        return { 'msg': f'An unexpected error occurred: {str(e)}' }, 500


# SUBMITTING QNA ROUTE
@app.route('/submit-questions' , methods=['POST'])
@jwt_required()
def submit_questions():
    # Get the data from the request
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided."}), 400
    except Exception as e:
        return jsonify({"error": "Invalid JSON format."}), 400

    email = get_jwt_identity()

    # Check if 'email' is present in the request data
    if 'email' not in data:
        return jsonify({"error": "Email is required in the request data."}), 400

    # Check if email matches the one in the JWT
    if email != data['email']:
        return jsonify({"error": "Unauthorized access."}), 401

    # Get the user from the database
    try:
        user = dynamodb.get_user(data['email'])
        if not user:
            return jsonify({"error": "User not found."}), 404
    except Exception as e:
        return jsonify({"error": "Failed to retrieve user information."}), 500

    # Submit the questions
    try:
        response = dynamodb.submit_questions(data, user)
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": "Failed to submit questions."}), 500

    
    
    
    


# GET USER
@app.route('/get-user', methods=['GET'])
@jwt_required()
def get_user():
    email = get_jwt_identity()
    try:
        response = dynamodb.get_user(email)
        if not response:
            return {'error': 'User not found!'}, 404
        return response
    except Exception as e:  
        return {
            'msg': 'Some error occured',
            'error': str(e)
        }

#AUTH
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        response = dynamodb.register(data['email'], hashed_password, data['fullName'])
        print(response) 
        return jsonify(response), 201
    except Exception as e:
        return jsonify({
            'msg': 'Some error occured',
            'error': str(e)
        }), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        response = dynamodb.login(data['email'], data['password'])
        print(response)
        return response
    except Exception as e:
        return {
            'msg': 'Some error occured',
            'error': str(e)
        }
    





if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)