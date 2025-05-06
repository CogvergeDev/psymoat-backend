# controller.py

import os
import secrets
import string
from boto3 import resource
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError
from flask import jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
    get_jwt_identity
)
from datetime import datetime

bcrypt = Bcrypt()

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
REGION_NAME = 'us-east-1'

dynamodb_resource = resource(
    'dynamodb',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=REGION_NAME
)

UserTable = dynamodb_resource.Table('User')
ExamTable = dynamodb_resource.Table('Exam')
ModuleTable = dynamodb_resource.Table('Module')
QNAHistoryTable = dynamodb_resource.Table('QNAHistory')
QuestionTable = dynamodb_resource.Table('Questions')
PaymentHistoryTable = dynamodb_resource.Table('PaymentHistory')

def generate_id(size=6):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(size))


def get_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# TABLE CREATION
def create_user_table():
    return dynamodb_resource.create_table(
        TableName='User',
        KeySchema=[{'AttributeName': 'email', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'email', 'AttributeType': 'S'}],
        ProvisionedThroughput={'ReadCapacityUnits': 10, 'WriteCapacityUnits': 10}
    )

def create_exam_table():
    return dynamodb_resource.create_table(
        TableName='Exam',
        KeySchema=[{'AttributeName': 'exam_id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'exam_id', 'AttributeType': 'S'}],
        ProvisionedThroughput={'ReadCapacityUnits': 10, 'WriteCapacityUnits': 10}
    )

def create_module_table():
    return dynamodb_resource.create_table(
        TableName='Module',
        KeySchema=[{'AttributeName': 'module_id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'module_id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )

def create_qna_history_table():
    return dynamodb_resource.create_table(
        TableName='QNAHistory',
        KeySchema=[{'AttributeName': 'qna_id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'qna_id', 'AttributeType': 'S'}],
        ProvisionedThroughput={'ReadCapacityUnits': 10, 'WriteCapacityUnits': 10}
    )

def create_test_table():
    return dynamodb_resource.create_table(
        TableName='Test',
        KeySchema=[{'AttributeName': 'test_id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'test_id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )

def create_video_table():
    return dynamodb_resource.create_table(
        TableName='Video',
        KeySchema=[{'AttributeName': 'video_id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'video_id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )

def create_live_lecture_table():
    return dynamodb_resource.create_table(
        TableName='LiveLecture',
        KeySchema=[{'AttributeName': 'live_lec_id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'live_lec_id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )

def create_question_table():
    return dynamodb_resource.create_table(
        TableName='Questions',
        KeySchema=[{'AttributeName': 'question_id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'question_id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )

def create_payment_history_table():
    return dynamodb_resource.create_table(
        TableName='PaymentHistoryTable',
        KeySchema=[{'AttributeName': 'payment_id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'payment_id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )

# NEW APIs

def get_questions(module_id: str, idx: int) -> list:
    """
    Fetch exactly 20 questions for module_id at page idx.
    Returns an empty list if fewer than 20 exist.
    """
    # Calculate which question_ids to pull
    start = (idx - 1) * 20 + 1
    end   = idx * 20
    keys  = [{'question_id': f"{module_id}_{i}"} for i in range(start, end + 1)]

    items = []
    try:
        to_fetch = {QuestionTable.table_name: {'Keys': keys}}
        # loop to retry unprocessed
        while to_fetch:
            resp = dynamodb_resource.meta.client.batch_get_item(RequestItems=to_fetch)
            items.extend(resp.get('Responses', {}).get(QuestionTable.table_name, []))
            to_fetch = resp.get('UnprocessedKeys', {})

    except (ClientError, BotoCoreError) as e:
        # let the route catch this
        raise RuntimeError(f"DynamoDB error on batch_get_item: {e}")

    # only return a “full page” of 20
    if len(items) != 20:
        return []

    # sort by the numeric suffix
    items.sort(key=lambda it: int(it['question_id'].rsplit('_', 1)[1]))
    return items

def get_all_questions(module_id: str) -> list:
    """
    Scan QuestionTable for all items whose question_id begins with '{module_id}_'.
    Returns a sorted list of question‐items; if none found, returns [].
    """
    prefix = f"{module_id}_"
    try:
        # first page
        resp = QuestionTable.scan(
            FilterExpression=Attr('question_id').begins_with(prefix)
        )
        items = resp.get('Items', [])

        # handle pagination
        while 'LastEvaluatedKey' in resp:
            resp = QuestionTable.scan(
                FilterExpression=Attr('question_id').begins_with(prefix),
                ExclusiveStartKey=resp['LastEvaluatedKey']
            )
            items.extend(resp.get('Items', []))

        # sort by numeric suffix (so module_1, module_2, …)
        items.sort(key=lambda it: int(it['question_id'].rsplit('_', 1)[1]))
        return items

    except (ClientError, BotoCoreError) as e:
        # re‐raise or log however you prefer
        raise

def add_questions_to_module(module_id: str, rows: list, paid_count: int, free_count: int) -> dict:
    """
    Takes a list of question rows and adds them to the module.
    Updates total, paid, and free question counts.
    """
    if not module_id or not rows:
        raise ValueError("Module ID and questions are required")

    try:
        # Check if module exists
        resp = ModuleTable.get_item(
            Key={'module_id': module_id}
        )
        if 'Item' not in resp:
            raise ValueError(f"Module {module_id} not found")

        existing_questions = resp['Item'].get('questions', [])
        existing_count = resp['Item'].get('numberOfQuestions', 0)
        existing_paid = resp['Item'].get('numberOfPaidQuestions', 0)
        existing_free = resp['Item'].get('numberOfFreeQuestions', 0)

        # Process and validate each question
        new_ids = []
        for row in rows:
            # Validate required fields
            required_fields = ['Question', 'Option 1', 'Option 2', 'Option 3', 'Option 4', 'Correct Answer']
            missing = [f for f in required_fields if not row.get(f)]
            if missing:
                raise ValueError(f"Missing required fields: {', '.join(missing)}")

            qid = row['question_id']
            if qid in existing_questions:
                continue  # Skip duplicates

            # Create question item with proper attribute handling
            item = {
                'module_id': module_id,
                'question_id': qid,
                'question': row['Question'].strip(),
                'options': [
                    row['Option 1'].strip(),
                    row['Option 2'].strip(),
                    row['Option 3'].strip(),
                    row['Option 4'].strip()
                ],
                'correct_answer': row['Correct Answer'].strip(),
                'explanation': row.get('Explanation', '').strip(),
                'difficulty': row.get('Difficulty', 'Medium').strip(),
                'is_paid': row['is_paid']
            }

            # Write to QuestionTable
            try:
                QuestionTable.put_item(Item=item)
                new_ids.append(qid)
            except (ClientError, BotoCoreError) as e:
                raise RuntimeError(f"Failed to write question {qid}: {e}")

        if not new_ids:
            return {
                'numberOfQuestions': existing_count,
                'numberOfPaidQuestions': existing_paid,
                'numberOfFreeQuestions': existing_free,
                'questions': existing_questions
            }

        # Update ModuleTable with all counts
        update_expr = """
            SET questions = list_append(if_not_exists(questions, :empty), :new_ids), 
                numberOfQuestions = :new_count,
                numberOfPaidQuestions = :paid_count,
                numberOfFreeQuestions = :free_count
        """
        expr_values = {
            ':empty': [],
            ':new_ids': new_ids,
            ':new_count': existing_count + len(new_ids),
            ':paid_count': existing_paid + paid_count,
            ':free_count': existing_free + free_count
        }

        update_resp = ModuleTable.update_item(
            Key={'module_id': module_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
            ReturnValues='UPDATED_NEW'
        )

        return update_resp.get('Attributes', {})

    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"DynamoDB error: {e}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error: {e}")

def count_questions_by_difficulty(module_id: str, difficulty: str) -> int:
    """
    Count how many questions in QuestionTable for the given module_id
    have difficulty == difficulty (e.g. 'Easy', 'Medium', 'Hard').
    """
    prefix = f"{module_id}_"
    try:
        # first page
        resp = QuestionTable.scan(
            FilterExpression=Attr('question_id').begins_with(prefix) &
                             Attr('difficulty').eq(difficulty),
            Select='COUNT'
        )
        total = resp.get('Count', 0)

        # handle pagination
        while 'LastEvaluatedKey' in resp:
            resp = QuestionTable.scan(
                FilterExpression=Attr('question_id').begins_with(prefix) &
                                 Attr('difficulty').eq(difficulty),
                Select='COUNT',
                ExclusiveStartKey=resp['LastEvaluatedKey']
            )
            total += resp.get('Count', 0)

        return total

    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(
            f"Error counting {difficulty} questions for module {module_id}: {e}"
        )

def submit_questions(data, user):
    exam_id   = data["exam_id"]
    module_id = data["module_id"]

    # ─── 1. mark exam as taken ─────────────────────────────────────────────────────
    if exam_id not in user.setdefault("examsTaken", []):
        user["examsTaken"].append(exam_id)

    # ─── 2. update completed_idx ──────────────────────────────────────────────────
    user.setdefault("completed_idx", {})
    user["completed_idx"].setdefault(exam_id, {})
    user["completed_idx"][exam_id].setdefault(module_id, [])

    module_data   = user["completed_idx"][exam_id][module_id]
    completed_idx = data["completed_idx"]

    try:
        if completed_idx not in module_data:
            module_data.append(completed_idx)
    except Exception as e:
        print(f"ERROR IN UPDATING COMPLETED IDX: {e}")

    # ─── 3. updating data_graph_leetcode_accuracy ────────────────────────────────
    user.setdefault("data_graph_leetcode_accuracy", {})
    user["data_graph_leetcode_accuracy"].setdefault(exam_id, {
        "easy":   {"number_solved": 0, "total_questions": count_questions_by_difficulty(module_id, 'Easy'), "correct_answered": 0},
        "medium": {"number_solved": 0, "total_questions": count_questions_by_difficulty(module_id, 'Medium'), "correct_answered": 0},
        "hard":   {"number_solved": 0, "total_questions": count_questions_by_difficulty(module_id, 'Hard'), "correct_answered": 0},
    })
    graph = user["data_graph_leetcode_accuracy"][exam_id]

    for level in ("easy", "medium", "hard"):
        correct   = data.get(f"{level}_correct", 0)
        incorrect = data.get(f"{level}_incorrect", 0)
        solved    = correct + incorrect

        graph[level]["number_solved"]    += solved
        graph[level]["correct_answered"] += correct

    # ─── 4. updating data_graph_modulewise ────────────────────────────────────────
    # totalQuestionRef = get_module_no_of_questions(module_id)
    # totalQuestions = totalQuestionRef['Item']['numberOfQuestions']
    user.setdefault("data_graph_modulewise", {})
    user["data_graph_modulewise"].setdefault(exam_id, {})
    user["data_graph_modulewise"][exam_id].setdefault(module_id, {
        "correct_answers": 0,
        "total_questions": get_module_no_of_questions_for_init(module_id),
    })

    total_correct = sum(data.get(f"{lvl}_correct", 0) for lvl in ("easy", "medium", "hard"))

    user["data_graph_modulewise"][exam_id][module_id]["correct_answers"] += total_correct

    # ─── 5. updating solved_wrong ────────────────────────────────────────────────
    user.setdefault("solved_wrong", {})
    user["solved_wrong"].setdefault(exam_id, {})
    user["solved_wrong"][exam_id].setdefault(module_id, [])

    wrong_list = user["solved_wrong"][exam_id][module_id]

    # 5a) remove any QIDs the user just got correct
    for qid in data.get("correct_answers_qid", []):
        if qid in wrong_list:
            wrong_list.remove(qid)

    # 5b) add any newly wrong QIDs (no duplicates)
    for qid in data.get("wrong_answers_qid", []):
        if qid not in wrong_list:
            wrong_list.append(qid)

    # ─── 6. save QnA history & persist user ───────────────────────────────────────
    try:
        for qna_entry in data.get("detailed_user_qna", []):
            qna_entry["email"]     = data["email"]
            qna_entry["qna_id"]    = generate_id(6)
            qna_entry["exam_id"]   = exam_id
            qna_entry["module_id"] = module_id
            qna_entry["timestamp"] = get_time()
            QNAHistoryTable.put_item(Item=qna_entry)

        response = UserTable.update_item(
            Key={"email": data["email"]},
            UpdateExpression=(
                "SET examsTaken = :e, "
                "completed_idx = :c, "
                "data_graph_leetcode_accuracy = :l, "
                "data_graph_modulewise = :m, "
                "solved_wrong = :w"
            ),
            ExpressionAttributeValues={
                ":e": user["examsTaken"],
                ":c": user["completed_idx"],
                ":l": user["data_graph_leetcode_accuracy"],
                ":m": user["data_graph_modulewise"],
                ":w": user["solved_wrong"],
            },
            ReturnValues="UPDATED_NEW"
        )
    except Exception as e:
        return {"status": "error", "message": f"Error saving QnA or updating user: {e}"}

    return response

# DATA OPERATIONS
def get_module_no_of_questions(module_id):
    res =  ModuleTable.get_item(
        Key={'module_id': module_id},
        AttributesToGet=['numberOfQuestions']
    )
    print(res['Item']['numberOfQuestions'])
    return res

def get_module_no_of_questions_for_init(module_id):
    res =  ModuleTable.get_item(
        Key={'module_id': module_id},
        AttributesToGet=['numberOfQuestions']
    )
    print(res['Item']['numberOfQuestions'])
    return res['Item']['numberOfQuestions']

def get_modules_by_exam_id(exam_id):
    try:
        response = ModuleTable.scan(
            ProjectionExpression="module_id, module_name",
            FilterExpression="exam_id = :exam_id",
            ExpressionAttributeValues={":exam_id": exam_id}
        )
        return {
            'statusCode': 200,
            'msg': 'Modules retrieved successfully!',
            'modules': response.get('Items', [])
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'msg': 'Error occurred while retrieving modules',
            'error': str(e)
        }

def get_all_exam_details():
    try:
        response = ExamTable.scan(ProjectionExpression="exam_id, exam_name, modules")
        items = response.get('Items', [])
        exams_dict = {}
        for item in items:
            exam_id = item.get('exam_id')
            exams_dict[exam_id] = {
                'exam_name': item.get('exam_name'),
                'modules': get_modules_by_exam_id(exam_id)
            }
        return {
            'statusCode': 200,
            'msg': 'Exams retrieved successfully!',
            'exams': exams_dict
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'msg': 'Error occurred while retrieving exams',
            'error': str(e)
        }

def add_questions_in_module(module_id, data, free_count, paid_count):

    return ModuleTable.update_item(
        Key={'module_id': module_id},
        UpdateExpression=(
            "SET questions = :qs, "
            "    numberOfQuestions = :tot, "
            "    numberOfPaidQuestions = :paid, "
            "    numberOfFreeQuestions = :free"
        ),
        ExpressionAttributeValues={
            ':qs':   data,
            ':tot':  len(data),
            ':paid': paid_count,
            ':free': free_count,
        },
        ReturnValues="UPDATED_NEW"
    )

def initialize_new_module(exam_id, module_name):
    try:
        module_id = generate_id(6)
        response = ModuleTable.put_item(
            Item={
                'module_id': module_id,
                'module_name': module_name,
                'exam_id': exam_id,
                'questions': [],
                'numberOfQuestions': 0,
                'subtopics': []
            }
        )
        if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
            update_response = ExamTable.update_item(
                Key={'exam_id': exam_id},
                UpdateExpression=(
                    "SET modules = list_append(if_not_exists(modules, :empty_list), :new_module_id)"
                ),
                ExpressionAttributeValues={
                    ':new_module_id': [module_id],
                    ':empty_list': []
                },
                ReturnValues="UPDATED_NEW"
            )
            return {
                "status": "success",
                "module_id": module_id,
                "update_response": update_response
            }
        else:
            return {"status": "error", "message": "Failed to insert new module"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def initialize_new_exam(exam_name):
    try:
        exam_id = generate_id(6)
        response = ExamTable.put_item(
            Item={'exam_id': exam_id, 'exam_name': exam_name, 'modules': []}
        )
        if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
            return {
                "status": "success",
                "exam_id": exam_id,
                "exam_name": exam_name,
                "message": "Exam created successfully."
            }
        else:
            return {
                "status": "error",
                "message": "Failed to initialize exam due to an unexpected error."
            }
    except Exception as e:
        return {"status": "error", "message": f"Failed to initialize exam: {str(e)}"}

def set_new_history(data):
    return QNAHistoryTable.put_item(
        Item={
            "qna_id": generate_id(6),
            "user_id": data['user_id'],
            "question_id": data['question_id'],
            "exam_id": data['exam_id'],
            "module_id": data['module_id'],
            "selected_answer": data['selected_answer'],
            "correct_answer": data['correct_answer'],
            "is_correct": data['is_correct'],
            "timestamp": data['timestamp']
        }
    )

def get_user(email):
    try:
        resp = UserTable.get_item(Key={'email': email})
        if 'Item' not in resp:
            return {'error': 'User not found!'}, 404
        user = resp['Item']
        user.pop('password', None)
        return user
    except Exception as e:
        return {'error': 'An unexpected error occurred', 'details': str(e)}

# AUTHENTICATION
def register(email, password, fullName):
    try:
        existing = UserTable.get_item(Key={'email': email})
        if 'Item' in existing:
            return jsonify({'msg': 'User already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        item = {
            'user_id': generate_id(),
            'email': email,
            'password': hashed_password,
            'fullName': fullName,
            'joinedOn': get_time(),
            'lastLogin': '',
            'examsTaken': [],
        }
        UserTable.put_item(Item=item)
        return jsonify({'msg': 'Registration successful'}), 201
    except (ClientError, BotoCoreError) as e:
        return jsonify({'msg': 'DB error', 'error': str(e)}), 500
    except Exception as e:
        return jsonify({'msg': 'Unexpected error', 'error': str(e)}), 500

def login(email, password):
    try:
        resp = UserTable.get_item(Key={'email': email})
        if 'Item' not in resp:
            return jsonify({'msg': 'User not found'}), 404

        user = resp['Item']
        if not bcrypt.check_password_hash(user['password'], password):
            return jsonify({'msg': 'Invalid credentials'}), 401

        access_token = create_access_token(identity=email)
        refresh_token = create_refresh_token(identity=email)

        response = jsonify({'msg': 'Login successful'})
        set_access_cookies(response, access_token)
        # set_refresh_cookies(response, refresh_token)
        return response, 200
    except (ClientError, BotoCoreError) as e:
        return jsonify({'msg': 'DB error', 'error': str(e)}), 500
    except Exception as e:
        return jsonify({'msg': 'Unexpected error', 'error': str(e)}), 500

def refresh():
    identity = get_jwt_identity()
    new_access = create_access_token(identity=identity)
    response = jsonify({'msg': 'Token refreshed'})
    set_access_cookies(response, new_access)
    return response, 200

def logout():
    response = jsonify({'msg': 'Logout successful'})
    unset_jwt_cookies(response)
    return response, 200

def get_questions_by_type(module_id: str, idx: int, is_paid: bool) -> list:
    """
    Fetch exactly 20 questions for module_id at page idx with specific paid status.
    Returns an empty list if fewer than 20 exist.
    """
    # Calculate which question_ids to pull
    start = (idx - 1) * 20 + 1
    end = idx * 20
    suffix = 'p' if is_paid else 'f'
    keys = [{'question_id': f"{module_id}_{suffix}_{i}"} for i in range(start, end + 1)]

    # print(keys)
    items = []
    try:
        to_fetch = {QuestionTable.table_name: {'Keys': keys}}
        # loop to retry unprocessed
        while to_fetch:
            resp = dynamodb_resource.meta.client.batch_get_item(RequestItems=to_fetch)
            items.extend(resp.get('Responses', {}).get(QuestionTable.table_name, []))
            to_fetch = resp.get('UnprocessedKeys', {})

    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"DynamoDB error on batch_get_item: {e}")

    # only return a "full page" of 20
    if len(items) != 20:
        return []

    # sort by the numeric suffix
    items.sort(key=lambda it: int(it['question_id'].rsplit('_', 1)[1]))
    return items

def save_payment_history(payment_data: dict) -> dict:
    """
    Save payment details to PaymentHistoryTable
    """
    try:
        response = PaymentHistoryTable.put_item(
            Item={
                'payment_id': payment_data['payment_id'],
                'order_id': payment_data['order_id'],
                'amount': payment_data['amount'],
                'created_at': payment_data['created_at'],
                'signature': payment_data['signature'],
                'user_id': payment_data['user_id'],
                'plan_id': payment_data['plan_id']
            }
        )
        return {
            'status': 'success',
            'message': 'Payment history saved successfully',
            'response': response
        }
    except Exception as e:
        raise RuntimeError(f"Failed to save payment history: {e}")

def get_user_payment_history(user_id: str) -> list:
    """
    Get all payment history for a specific user
    """
    try:
        response = PaymentHistoryTable.query(
            IndexName='user_id-index',
            KeyConditionExpression='user_id = :uid',
            ExpressionAttributeValues={
                ':uid': user_id
            }
        )
        return response.get('Items', [])
    except Exception as e:
        raise RuntimeError(f"Failed to fetch payment history: {e}")

def get_payment_details(payment_id: str) -> dict:
    """
    Get details of a specific payment
    """
    try:
        response = PaymentHistoryTable.get_item(
            Key={'payment_id': payment_id}
        )
        return response.get('Item', {})
    except Exception as e:
        raise RuntimeError(f"Failed to fetch payment details: {e}")

def get_exam_module_stats(exam_id: str, user_id: str) -> dict:
    """
    Get statistics for all modules in an exam including wrong questions count
    """
    try:
        # Get exam details to get module IDs
        exam_resp = ExamTable.get_item(
            Key={'exam_id': exam_id},
            AttributesToGet=['modules']
        )
        if 'Item' not in exam_resp:
            raise ValueError(f"Exam {exam_id} not found")
        
        module_ids = exam_resp['Item'].get('modules', [])
        
        # Get user data for wrong questions
        user_resp = UserTable.get_item(
            Key={'email': user_id},
            ProjectionExpression='solved_wrong'
        )
        if 'Item' not in user_resp:
            raise ValueError(f"User {user_id} not found")
            
        wrong_questions = user_resp['Item'].get('solved_wrong', {}).get(exam_id, {})
        
        # Get module details
        modules_stats = []
        for module_id in module_ids:
            module_resp = ModuleTable.get_item(
                Key={'module_id': module_id},
                AttributesToGet=['module_name', 'numberOfQuestions', 'numberOfPaidQuestions', 'numberOfFreeQuestions']
            )
            
            if 'Item' in module_resp:
                module_data = module_resp['Item']
                module_data['numberOfWrongQuestions'] = len(wrong_questions.get(module_id, []))
                modules_stats.append(module_data)
        
        return {
            'exam_id': exam_id,
            'modules': modules_stats
        }
        
    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"DynamoDB error: {e}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error: {e}")

def get_wrong_questions(user_id: str, module_id: str, idx: int) -> list:
    """
    Get wrong questions for a user with pagination
    """
    try:
        # Get user's wrong questions
        user_resp = UserTable.get_item(
            Key={'email': user_id},
            ProjectionExpression='solved_wrong'
        )
        if 'Item' not in user_resp:
            raise ValueError(f"User {user_id} not found")

        # Get wrong questions array for this module
        wrong_questions = []
        solved_wrong = user_resp['Item'].get('solved_wrong', {})
        for exam_data in solved_wrong.values():
            if module_id in exam_data:
                wrong_questions.extend(exam_data[module_id])

        # Calculate pagination
        start_idx = (idx - 1) * 20
        end_idx = min(start_idx + 20, len(wrong_questions))
        page_questions = wrong_questions[start_idx:end_idx]

        if not page_questions:
            return []

        # Fetch actual question details
        questions = []
        for qid in page_questions:
            try:
                q_resp = QuestionTable.get_item(Key={'question_id': qid})
                if 'Item' in q_resp:
                    questions.append(q_resp['Item'])
            except Exception as e:
                print(f"Error fetching question {qid}: {e}")
                continue

        return questions

    except Exception as e:
        raise RuntimeError(f"Failed to fetch wrong questions: {e}")
