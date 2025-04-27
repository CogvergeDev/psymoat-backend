# app.py

from datetime import datetime
import os
from flask import Flask, request, jsonify
import controller as dynamodb
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from dotenv import load_dotenv
import razorpay
from razorpay.errors import BadRequestError, ServerError as RazorpayServerError, SignatureVerificationError


load_dotenv()

app = Flask(__name__)


CORS(
    app,
    origins=[
        "http://localhost:3000",
        "https://psymoat.vercel.app",
        "https://www.psymoat.in"
    ],
    supports_credentials=True
)


razorpay_client = razorpay.Client(
    auth=(
        os.getenv("RAZORPAY_KEY_ID"),
        os.getenv("RAZORPAY_KEY_SECRET")
    )
)


app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/refresh'
app.config['JWT_COOKIE_SECURE'] = False       # Set to True in production
app.config['JWT_COOKIE_SAMESITE'] = 'None'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False # Enable & handle CSRF for stronger protection

jwt = JWTManager(app)


# TEST ROUTE
@app.route('/test')
@jwt_required()
def test():
    user_id = get_jwt_identity()
    print(user_id)
    print("TEST SUCCESS")
    return 'TEST SUCCESS', 200


# TABLE CREATION ROUTES
@app.route('/create-user-table')
def create_user_table_route():
    dynamodb.create_user_table()
    return 'User Table created', 200

@app.route('/create-exam-table')
def create_exam_table_route():
    dynamodb.create_exam_table()
    return 'Exam Table created', 200

@app.route('/create-module-table')
def create_module_table_route():
    dynamodb.create_module_table()
    return 'Module Table created', 200

@app.route('/create-test-table')
def create_test_table_route():
    dynamodb.create_test_table()
    return 'Test Table created', 200

@app.route('/create-live-lec-table')
def create_live_lec_table_route():
    dynamodb.create_live_lecture_table()
    return 'Live Lecture Table created', 200

@app.route('/create-video-table')
def create_video_table_route():
    dynamodb.create_video_table()
    return 'Video Table created', 200

@app.route('/create-payments-table')
def create_payments_table_route():
    dynamodb.create_payments_table()
    return 'Payments Table created', 200


# INITIALIZATION ROUTES
@app.route('/initialize-new-module', methods=['POST'])
def initialize_new_module():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided."}), 400

    try:
        response = dynamodb.initialize_new_module(
            data.get('exam_id'),
            data.get('module_name')
        )
        if not response:
            return jsonify({"error": "No response received."}), 400

        return jsonify({"message": f"{data.get('module_name')} is initialized."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/initialize-new-exam', methods=['POST'])
def initialize_new_exam():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided."}), 400

    if not data.get('exam_name'):
        return jsonify({"error": "Exam name not provided."}), 400

    try:
        response = dynamodb.initialize_new_exam(data.get('exam_name'))
        if not response:
            return jsonify({"error": "No response received."}), 400

        return jsonify({"message": f"{data.get('exam_name')} is initialized."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ADDING MODULES TO DB ROUTE
@app.route('/add-to-module/<string:module_id>', methods=['POST'])
def add_to_module(module_id):
    if not module_id:
        return jsonify({"error": "module_id is required"}), 400

    file = request.files.get('csv_file')
    if not file:
        return jsonify({"error": "CSV file is required"}), 400

    try:
        file_content = file.read().decode('utf-8')
        from io import StringIO
        import csv
        csv_file = StringIO(file_content)
        csv_reader = csv.DictReader(csv_file)

        questionResponse = dynamodb.get_module_questions(module_id)
        questions = questionResponse['Item']['questions']

        for i, row in enumerate(csv_reader):
            row['module_id'] = module_id
            row['question_id'] = f"{module_id}_{i+1}"
            questions.append(row)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    response = dynamodb.add_questions_in_module(module_id, questions)
    if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return jsonify({'msg': 'Added successfully'}), 200

    return jsonify({'msg': 'Some error occurred', 'response': response}), 500


@app.route('/get-all-module-details', methods=['GET'])
@jwt_required()
def get_all_module_details():
    try:
        response = dynamodb.get_all_module_details()
        return jsonify(response), response.get('statusCode', 200)
    except Exception as e:
        return jsonify({'msg': 'Some error occurred', 'error': str(e)}), 500

@app.route('/get-all-exam-details', methods=['GET'])
@jwt_required()
def get_all_exam_details():
    try:
        response = dynamodb.get_all_exam_details()
        return jsonify(response), response.get('statusCode', 200)
    except Exception as e:
        return jsonify({'msg': 'Some error occurred', 'error': str(e)}), 500


# GETTING QUESTION FROM A MODULE
@app.route('/get-module-questions/<string:module_id>', methods=['GET'])
@jwt_required()
def get_module_questions(module_id):
    try:
        response = dynamodb.get_module_questions(module_id)
        if not response:
            return jsonify({'msg': 'No questions found'}), 404

        if 'ResponseMetadata' in response and response['ResponseMetadata'].get('HTTPStatusCode') == 200:
            if 'Item' in response:
                return jsonify({'Item': response['Item']}), 200
            return jsonify({'msg': 'Item not found!'}), 404

        return jsonify({'msg': 'Some error occurred', 'response': response}), 500

    except KeyError:
        return jsonify({'msg': 'Invalid response structure'}), 500
    except Exception as e:
        return jsonify({'msg': f'An unexpected error occurred: {str(e)}'}), 500


# SUBMITTING QNA ROUTE
@app.route('/submit-questions', methods=['POST'])
@jwt_required()
def submit_questions():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided."}), 400
    except Exception:
        return jsonify({"error": "Invalid JSON format."}), 400

    email = get_jwt_identity()
    if 'email' not in data:
        return jsonify({"error": "Email is required in the request data."}), 400
    if email != data['email']:
        return jsonify({"error": "Unauthorized access."}), 401

    try:
        user = dynamodb.get_user(data['email'])
        if not user or isinstance(user, tuple):
            return jsonify({"error": "User not found."}), 404
    except Exception:
        return jsonify({"error": "Failed to retrieve user information."}), 500

    try:
        response = dynamodb.submit_questions(data, user)
        return jsonify(response), 200
    except Exception:
        return jsonify({"error": "Failed to submit questions."}), 500


# GET USER
@app.route('/get-user', methods=['GET'])
@jwt_required()
def get_user():
    email = get_jwt_identity()
    try:
        response = dynamodb.get_user(email)
        if isinstance(response, tuple):
            return jsonify(response[0]), response[1]
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'msg': 'Some error occurred', 'error': str(e)}), 500


# AUTH ROUTES
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password') or not data.get('fullName'):
        return jsonify({'msg': 'email, password and fullName are required'}), 400
    return dynamodb.register(
        email=data['email'],
        password=data['password'],
        fullName=data['fullName']
    )

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'msg': 'email and password are required'}), 400
    return dynamodb.login(
        email=data['email'],
        password=data['password']
    )

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    return dynamodb.refresh()

@app.route('/logout', methods=['POST'])
def logout():
    return dynamodb.logout()



@app.route('/razorpay/order/create/', methods=['POST'])
@jwt_required()
def create_razorpay_order():
    # Parse & validate JSON
    try:
        data = request.get_json(force=True)
    except Exception as e:
        return jsonify({
            'error': 'Invalid JSON payload',
            'details': str(e)
        }), 400

    amount = data.get('amount')
    currency = data.get('currency', 'INR')

    if amount is None:
        return jsonify({'error': 'The "amount" field is required.'}), 400

    # Validate amount type & value
    try:
        amt_int = int(amount)
        if amt_int <= 0:
            raise ValueError("Amount must be a positive integer")
    except (ValueError, TypeError) as e:
        return jsonify({
            'error': 'Invalid "amount" value',
            'details': str(e)
        }), 400

    # Create order with Razorpay
    try:
        razorpay_order = razorpay_client.order.create({
            'amount': amt_int * 100,   # paise
            'currency': currency,
            'payment_capture': 1
        })
    except BadRequestError as e:
        # client-side issue (e.g. unsupported currency)
        return jsonify({
            'error': 'Razorpay order creation failed (BadRequest)',
            'details': str(e)
        }), 400
    except RazorpayServerError as e:
        # server-side / gateway issue
        return jsonify({
            'error': 'Razorpay server error',
            'details': str(e)
        }), 502
    except Exception as e:
        # anything else
        return jsonify({
            'error': 'Unexpected error while creating order',
            'details': str(e)
        }), 500

    # Success
    return jsonify({'data': razorpay_order}), 200


@app.route('/razorpay/order/complete/', methods=['POST'])
@jwt_required()
def complete_razorpay_order():
    # Parse & validate JSON
    try:
        data = request.get_json(force=True)
    except Exception as e:
        return jsonify({
            'error': 'Invalid JSON payload',
            'details': str(e)
        }), 400

    payment_id = data.get('payment_id')
    order_id   = data.get('order_id')
    signature  = data.get('signature')
    amount = data.get('amount')
    created_at = datetime.now()
    user_id = data.get('user_id')
    plan_id = data.get('plan_id')


    missing = [k for k in ('payment_id','order_id','signature') if not data.get(k)]
    if missing:
        return jsonify({
            'error': 'Missing required fields',
            'missing': missing
        }), 400

    # Verify signature
    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id':   order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature':  signature
        })
    except SignatureVerificationError as e:
        return jsonify({
            'error': 'Signature verification failed',
            'details': str(e)
        }), 400
    except Exception as e:
        return jsonify({
            'error': 'Unexpected error during signature verification',
            'details': str(e)
        }), 500

    # Fetch payment details (optional)
    try:
        payment = razorpay_client.payment.fetch(payment_id)
    except BadRequestError as e:
        return jsonify({
            'error': 'Failed to fetch payment (BadRequest)',
            'details': str(e)
        }), 400
    except RazorpayServerError as e:
        return jsonify({
            'error': 'Razorpay server error while fetching payment',
            'details': str(e)
        }), 502
    except Exception as e:
        return jsonify({
            'error': 'Unexpected error while fetching payment',
            'details': str(e)
        }), 500

    #Todo:  put payment in db and update user 
    return jsonify({
        'status': 'success',
        'message': 'Payment verified and fetched',
        'payment': payment
    }), 200



if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
