# app.py

from datetime import datetime, timedelta
import os
from flask import Flask, request, jsonify
import controller as dynamodb
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from dotenv import load_dotenv
from botocore.exceptions import BotoCoreError, ClientError
import razorpay
from razorpay.errors import BadRequestError, ServerError as RazorpayServerError, SignatureVerificationError
from uuid import uuid4
import csv
from io import StringIO
from zoneinfo import ZoneInfo

# define IST timezone
IST = ZoneInfo("Asia/Kolkata")


load_dotenv()

app = Flask(__name__)


CORS(
    app,
    origins=[
        "http://localhost:3000",
        "https://psymoat.vercel.app",
        "https://www.psymoat.in",
        "https://psymoat.in",
        "https://psymoat-9w5leylea-cogvergedevs-projects.vercel.app",
        "https://proxy-psymoat.vercel.app",
        "https://www.psymoat.in/api"
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
app.config['JWT_COOKIE_SECURE'] = True       # Set to True in production
app.config['JWT_COOKIE_SAMESITE'] = 'None'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False # Enable & handle CSRF for stronger protection
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)  # Set token expiry to 1 day

jwt = JWTManager(app)


# TEST ROUTE
@app.route('/test')
@jwt_required()
def test():
    user_id = get_jwt_identity()
    print(user_id)
    print("TEST SUCCESS")
    return 'TEST SUCCESS', 200

@app.route('/check-auth')
@jwt_required()
def check_auth():
    try: 
        email = get_jwt_identity()
        if email:  
            return "User is authenticated", 200
        else:
            return "Unauthorized", 401
    except Exception as e:
        return f"Error Occured: {e}", 500



# TABLE CREATION ROUTES
@app.route('/create-user-table')
def create_user_table_route():
    dynamodb.create_user_table()
    return 'User Table created', 200

@app.route('/create-tests-solved-table')
def create_tests_table_route():
    dynamodb.create_test_solved_table()
    return 'TestsSolved Table created', 200

@app.route('/create-mock-test-table')
def create_mock_test_table_route():
    dynamodb.create_mock_test_table()
    return 'MockTest Table created', 200

@app.route('/create-questions-table')
def create_question_table_route():
    dynamodb.create_question_table()
    return 'Question Table created', 200

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

@app.route('/create-lec-table')
def create_lec_table_route():
    dynamodb.create_lecture_table()
    return 'Live Lecture Table created', 200

@app.route('/create-video-table')
def create_video_table_route():
    dynamodb.create_video_table()
    return 'Video Table created', 200


@app.route('/create-payment-history-table')
def create_payment_history_table_route():
    dynamodb.create_payment_history_table()
    return 'PaymentHistory Table created', 200


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
@app.route('/get-module-no-of-questions/<string:module_id>', methods=['GET'])
@jwt_required()
def get_module_no_of_questions(module_id):
    try:
        response = dynamodb.get_module_no_of_questions(module_id)
        if not response:
            return jsonify({'msg': 'No questions found'}), 404

        return response
    except KeyError:
        return jsonify({'msg': 'Invalid response structure'}), 500
    except Exception as e:
        return jsonify({'msg': f'An unexpected error occurred: {str(e)}'}), 500


# NEW APIs 

# Get all questions from a module (ig dev api)
@app.route('/get-all-questions/<string:module_id>')
def get_all_questions(module_id):
    try:
        questions = dynamodb.get_all_questions(module_id)
        if not questions:
            return jsonify({'msg': 'No questions found'}), 404
        return jsonify({'questions': questions}), 200
    except Exception as e:
        return jsonify({'msg': f'An unexpected error occurred: {e}'}), 500


@app.route('/add-to-module/<string:module_id>', methods=['POST'])
def add_to_module(module_id):
    if not module_id:
        return jsonify({"error": "module_id is required"}), 400

    file = request.files.get('csv_file')
    if not file:
        return jsonify({"error": "CSV file is required"}), 400

    # load CSV
    text = file.read().decode('utf-8')
    reader = csv.DictReader(StringIO(text))
    rows = list(reader)

    free_counter = 1
    paid_counter = 1
    processed = []

    for row in rows:
        # parse the incoming "isPaid" column
        print(row.get('IsPaid', '').strip())
        is_paid = row.get('IsPaid', '').strip() == "T"
        row['is_paid'] = is_paid

        # pick the right counter and suffix
        if is_paid:
            idx = paid_counter
            paid_counter += 1
            suffix = 'p'
        else:
            idx = free_counter
            free_counter += 1
            suffix = 'f'

        # build question_id
        row['question_id'] = f"{module_id}_{suffix}_{idx}"
        processed.append(row)

    try:
        # Pass the counts of new questions being added
        paid_count = paid_counter - 1  # Subtract 1 because counter starts at 1
        free_count = free_counter - 1
        result = dynamodb.add_questions_to_module(module_id, processed, paid_count, free_count)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "msg": "Questions added successfully",
        "totalQuestions": result.get('numberOfQuestions'),
        "paidQuestions": result.get('numberOfPaidQuestions'),
        "freeQuestions": result.get('numberOfFreeQuestions'),
        "allQuestionIds": result.get('questions', [])
    }), 200


@app.route('/get-questions/<string:module_id>/<string:question_type>/<int:idx>')
@jwt_required()
def route_get_questions_by_type(module_id, question_type, idx):
    try:
        is_paid = question_type.lower() == 'paid'
        questions = dynamodb.get_questions_by_type(module_id, idx, is_paid)
        if not questions:
            return jsonify({'msg': 'No questions found'}), 404

        return jsonify({'questions': questions}), 200

    except Exception as e:
        return jsonify({'msg': f'An unexpected error occurred: {e}'}), 500

@app.route('/get-wrong-questions/<string:module_id>/<int:idx>', methods=['GET'])
@jwt_required()
def get_user_wrong_questions(module_id, idx):
    try:
        user_id = get_jwt_identity()
        questions = dynamodb.get_wrong_questions(user_id, module_id, idx)
        if not questions:
            return jsonify({'msg': 'No wrong questions found'}), 404
            
        return jsonify({'questions': questions}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

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



@app.route('/razorpay/order/create', methods=['POST'])
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

@app.route('/razorpay/order/complete', methods=['POST'])
@jwt_required()
def complete_razorpay_order():
    try:
        data = request.get_json(force=True)
    except Exception as e:
        return jsonify({
            'error': 'Invalid JSON payload',
            'details': str(e)
        }), 400

    # required fields
    payment_id = data.get('payment_id')
    order_id   = data.get('order_id')
    signature  = data.get('signature')
    amount     = data.get('amount')
    plan_id    = data.get('plan_id')
    created_at = datetime.now(IST).isoformat()
    user_email = get_jwt_identity()

    missing = [k for k in ('payment_id','order_id','signature') if not data.get(k)]
    if missing:
        return jsonify({
            'error': 'Missing required fields',
            'missing': missing
        }), 400

    # verify signature
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

    # fetch the real payment object
    try:
        payment = razorpay_client.payment.fetch(payment_id)
    except Exception as e:
        return jsonify({
            'error': 'Could not fetch payment details',
            'details': str(e)
        }), 502

    # if not captured, record failure only
    if payment.get('status') != 'captured':
        dynamodb.save_failed_payment_history({
            'payment_id':      payment_id,
            'order_id':        order_id,
            'amount':          amount,
            'status':          payment.get('status'),
            'error_code':      payment.get('error_code'),
            'error_desc':      payment.get('error_description'),
            'user_email':      user_email,
            'plan_id':         plan_id,
            'created_at':      created_at
        })
        return jsonify({
            'status':  'failure',
            'message': f"Payment not captured (status={payment.get('status')})",
            'payment': payment
        }), 402

    # ——— at this point status == 'captured' ———
    try:
        result = dynamodb.save_successful_payment({
            'payment_id': payment_id,
            'order_id':   order_id,
            'amount':     amount,
            'signature':  signature,
            'created_at': created_at,
            'user_email': user_email,
            'plan_id':    plan_id
        })
        return jsonify({
            'status':  'success',
            'message': 'Payment verified and saved',
            'payment': payment,
            'db':      result
        }), 200

    except Exception as e:
        return jsonify({
            'error':   'Failed to save payment & update user',
            'details': str(e)
        }), 500




@app.route('/delete-payment-fields', methods=['DELETE'])
@jwt_required()
def delete_payment_fields():
    # 1) grab email from the validated JWT
    email = get_jwt_identity()

    try:
        # 2) delete those attributes
        result = dynamodb.delete_user_payment_fields(email)
        return jsonify(result), 200

    except RuntimeError as err:
        # could also catch / log more specifics
        return jsonify({
            'status': 'error',
            'message': str(err)
        }), 500
    

@app.route('/payment-history/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user_payments(user_id):
    try:
        payments = dynamodb.get_user_payment_history(user_id)
        return jsonify({'payments': payments}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch payment history: {str(e)}'}), 500

@app.route('/payment/<string:payment_id>', methods=['GET'])
@jwt_required()
def get_payment(payment_id):
    try:
        payment = dynamodb.get_payment_details(payment_id)
        if not payment:
            return jsonify({'error': 'Payment not found'}), 404
        return jsonify({'payment': payment}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch payment: {str(e)}'}), 500

@app.route('/exam-module-stats', methods=['POST'])
@jwt_required()
def get_exam_module_statistics():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        if not data or not data.get('exam_id'):
            return jsonify({
                'error': 'Missing required fields: exam_id and user_id required'
            }), 400

        stats = dynamodb.get_exam_module_stats(data['exam_id'], user_id)
        return jsonify(stats), 200

    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500



@app.route('/add-new-lecture', methods=['POST'])
def add_new_lecture():
    try:
        data = request.get_json(force=True)

        required_fields = [
            'yt_link', 'category', 'title', 'instructor_details',
            'key_topics', 'description', 'zoom_link',
            'date_time_of_zoom_lec', 'exam_id', 'module_id'
        ]

        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({
                'status': 'error',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        lecture_id = dynamodb.create_lecture(
            yt_link=data['yt_link'],
            category=data['category'],
            title=data['title'],
            instructor_details=data['instructor_details'],
            key_topics=data['key_topics'],
            description=data['description'],
            zoom_link=data['zoom_link'],
            date_time_of_zoom_lec=data['date_time_of_zoom_lec'],
            exam_id=data['exam_id'],
            module_id=data['module_id']
        )

        return jsonify({
            'status': 'success',
            'lecture_id': lecture_id
        }), 201

    except RuntimeError as e:
        return jsonify({
            'status': 'error',
            'message': f'Database operation failed: {str(e)}'
        }), 500

    except (BotoCoreError, ClientError) as e:
        return jsonify({
            'status': 'error',
            'message': f'AWS client error: {str(e)}'
        }), 502

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Internal server error: {str(e)}'
        }), 500
    
@app.route('/get-lecture/<string:lecture_id>', methods=['GET'])
def get_lecture(lecture_id):
    try:
        lecture = dynamodb.get_lecture_by_id(lecture_id)

        return jsonify({
            'status': 'success',
            'lecture': lecture
        }), 200

    except RuntimeError as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 404

    except (BotoCoreError, ClientError) as e:
        return jsonify({
            'status': 'error',
            'message': f'AWS client error: {str(e)}'
        }), 502

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Internal server error: {str(e)}'
        }), 500

@app.route('/get-random-lectures/<string:module_id>', methods=['GET'])
def get_random_module_lectures(module_id):
    try:
        lectures = dynamodb.get_random_lectures_from_module(module_id)

        return jsonify({
            'status': 'success',
            'lectures': lectures
        }), 200

    except RuntimeError as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 404

    except (BotoCoreError, ClientError) as e:
        return jsonify({
            'status': 'error',
            'message': f'AWS client error: {str(e)}'
        }), 502

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Internal server error: {str(e)}'
        }), 500


@app.route('/get-all-upcoming-lectures/<string:exam_id>', methods=['GET'])
def get_upcoming_lectures_for_exam(exam_id):
    try:
        lectures = dynamodb.get_upcoming_lectures_for_exam(exam_id)

        return jsonify({
            'status': 'success',
            'upcoming_lectures': lectures
        }), 200

    except RuntimeError as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

    except (BotoCoreError, ClientError) as e:
        return jsonify({
            'status': 'error',
            'message': f'AWS client error: {str(e)}'
        }), 502

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Internal server error: {str(e)}'
        }), 500

@app.route('/get-all-past-lectures/<string:exam_id>', methods=['GET'])
def get_past_lectures_for_exam(exam_id):
    try:
        lectures = dynamodb.get_past_lectures_for_exam(exam_id)

        return jsonify({
            'status': 'success',
            'past_lectures': lectures
        }), 200

    except RuntimeError as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

    except (BotoCoreError, ClientError) as e:
        return jsonify({
            'status': 'error',
            'message': f'AWS client error: {str(e)}'
        }), 502

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Internal server error: {str(e)}'
        }), 500

@app.route('/get-lecture-dashboard-details', methods=['POST'])
def get_lecture_dashboard_details_route():
    try:
        data = request.get_json(force=True)
        exam_id = data.get('exam_id')

        if not exam_id:
            return jsonify({
                'status': 'error',
                'message': 'Missing required parameter: exam_id'
            }), 400

        dashboard = dynamodb.get_lecture_dashboard_details(exam_id)

        return jsonify({
            'status': 'success',
            'dashboard': dashboard
        }), 200

    except RuntimeError as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

    except (BotoCoreError, ClientError) as e:
        return jsonify({
            'status': 'error',
            'message': f'AWS client error: {str(e)}'
        }), 502

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Internal server error: {str(e)}'
        }), 500


@app.route("/create-new-mock-test", methods=["POST"])
def create_mock_test_route():
    # 1) Validate presence of all required fields
    required = [
        "title",
        "duration",
        "no_of_questions",
        "difficulty",
        "is_featured_test",
        "description",
        "exam_id",
        "is_modulewise_test"
    ]
    missing = [f for f in required if f not in request.form]
    if missing:
        return jsonify({"error": f"Missing required field(s): {', '.join(missing)}"}), 400

    # 2) Grab the CSV
    csv_file = request.files.get("csv_file")
    if not csv_file:
        return jsonify({"error": "CSV file (csv_file) is required"}), 400

    # 3) Helper to coerce booleans
    def parse_bool(val):
        if isinstance(val, bool):
            return val
        return val.strip().lower() in ("true", "1", "yes")

    # 4) Collect & convert the form data
    data = {
        "title":            request.form["title"],
        "duration":         request.form["duration"],
        "no_of_questions":  request.form["no_of_questions"],
        "difficulty":       request.form["difficulty"],
        "is_featured_test": parse_bool(request.form["is_featured_test"]),
        "description":      request.form["description"],
        "exam_id":          request.form["exam_id"],
        "is_modulewise_test": parse_bool(request.form["is_modulewise_test"]),
        "module_id":        request.form.get("module_id")
    }

    # 5) Delegate to controller
    try:
        new_test = dynamodb.create_mock_test(data, csv_file)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # 6) Return the freshly created record
    return jsonify(new_test), 201


@app.route("/get-mock-test/<string:test_id>", methods=["GET"])
def fetch_mock_test_route(test_id):
    if not test_id:
        return jsonify({"error": "test_id is required in the URL"}), 400

    try:
        mock_test = dynamodb.get_mock_test(test_id)
    except KeyError as e:
        # not found
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        # any other error
        return jsonify({"error": str(e)}), 500

    return jsonify(mock_test), 200


@app.route('/submit-mock-test', methods=['POST'])
@jwt_required()
def submit_mock_test():
    try:
        user_email = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({"msg": "No data provided"}), 400

        result, status_code = dynamodb.submit_mock_test_controller(user_email, data)
        return jsonify(result), status_code

    except Exception as e:
        return jsonify({"msg": "Server error", "error": str(e)}), 500


@app.route('/get-test-dashboard/<string:exam_id>', methods=['GET'])
def get_test_dashboard(exam_id):
    try:
        result, status_code = dynamodb.get_test_dashboard_controller(exam_id)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"msg": "Server error", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
