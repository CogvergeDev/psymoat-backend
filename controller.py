# controller.py

import os
import secrets
import string
from boto3 import resource
from boto3.dynamodb.conditions import Attr, Key
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
import logging
from dateutil.relativedelta import relativedelta
from zoneinfo import ZoneInfo
import random
import csv
from io import StringIO
import math
from decimal import Decimal





# define IST timezone
IST = ZoneInfo("Asia/Kolkata")


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
PaymentHistoryTable = dynamodb_resource.Table('PaymentHistoryTable')
LectureTable = dynamodb_resource.Table('Lecture')
MockTestTable = dynamodb_resource.Table('MockTest')
TestsSolvedUserDataTable = dynamodb_resource.Table('TestsSolvedUserData')

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

def create_mock_test_table():
    return dynamodb_resource.create_table(
        TableName='MockTest',
        KeySchema=[{'AttributeName': 'test_id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'test_id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )


def create_test_solved_table():
    return dynamodb_resource.create_table(
        TableName='TestsSolvedUserData',
        KeySchema=[{'AttributeName': 'email', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'email', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
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

def create_lecture_table():
    return dynamodb_resource.create_table(
        TableName='Lecture',
        KeySchema=[
            {'AttributeName': 'lecture_id', 'KeyType': 'HASH'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'lecture_id', 'AttributeType': 'S'},
            {'AttributeName': 'exam_id', 'AttributeType': 'S'},
            {'AttributeName': 'date_time_of_zoom_lec', 'AttributeType': 'S'}
        ],
        BillingMode='PAY_PER_REQUEST',
        GlobalSecondaryIndexes=[
            {
                'IndexName': 'ExamUpcomingLecturesIndex',
                'KeySchema': [
                    {'AttributeName': 'exam_id', 'KeyType': 'HASH'},
                    {'AttributeName': 'date_time_of_zoom_lec', 'KeyType': 'RANGE'}
                ],
                'Projection': {
                    'ProjectionType': 'ALL'
                }
            }
        ]
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
            required_fields = ['Question', 'Option 1', 'Option 2', 'Option 3', 'Option 4', 'Answer']
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
                'correct_answer': row['Answer'].strip(),
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



def count_exam_questions_by_difficulty(exam_id: str, difficulty: str) -> int:
    """
    Fetches the list of module IDs for the given exam_id from ExamTable,
    then for each module, counts questions of the given difficulty
    (using your count_questions_by_difficulty function), and returns the sum.
    """
    try:
        # 1) load exam record
        resp = ExamTable.get_item(Key={'exam_id': exam_id})
        exam = resp.get('Item')
        if not exam or 'modules' not in exam:
            # no modules found → zero questions
            raise Exception(f"ERROR modules not found")

        total = 0
        # 2) for each module, count and accumulate
        for module_id in exam['modules']:
            total += count_questions_by_difficulty(module_id, difficulty)

        return total

    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(
            f"Error counting {difficulty} questions for exam {exam_id}: {e}"
        )


def get_likelyhood_clearing_value(
    easy, hard, incorrect,
    B1=0.1, B2=0.25,
    E=3.0,
    scale=38, ceiling=90
):
    # ── 0) normalize types ───────────────────────────────────────────────
    easy      = float(easy)
    hard      = float(hard)
    incorrect = float(incorrect)

    # ── 1) entry diagnostics ─────────────────────────────────────────────

    # ── 2) total attempts ────────────────────────────────────────────────
    total_attempts = easy + hard + incorrect
    if total_attempts == 0:
        return 0

    # ── 3) raw score ────────────────────────────────────────────────────
    raw_score = B1 * easy + B2 * hard

    # ── 4) error penalty ────────────────────────────────────────────────
    error_rate    = incorrect / total_attempts
    error_penalty = -E * error_rate * math.sqrt(total_attempts)

    # ── 5) floor at zero ────────────────────────────────────────────────
    adjusted_score = max(raw_score + error_penalty, 0)

    # ── 6) exponential mapping ──────────────────────────────────────────
    score = ceiling * (1 - math.exp(-adjusted_score / scale))

    return score


def submit_questions(data, user):
    exam_id   = data["exam_id"]
    module_id = data["module_id"]

    # ─── 1. mark exam as taken ────────────────────────────────────────────────
    if exam_id not in user.setdefault("examsTaken", []):
        user["examsTaken"].append(exam_id)

    # ─── 2. update completed_idx ─────────────────────────────────────────────
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

    # ─── 3. updating data_graph_leetcode_accuracy ────────────────────────────
    user.setdefault("data_graph_leetcode_accuracy", {})
    user["data_graph_leetcode_accuracy"].setdefault(exam_id, {
        "easy":   {"number_solved": 0, "total_questions": count_exam_questions_by_difficulty(exam_id, 'Easy'),   "correct_answered": 0},
        "medium": {"number_solved": 0, "total_questions": count_exam_questions_by_difficulty(exam_id,  'Medium'), "correct_answered": 0},
        "hard":   {"number_solved": 0, "total_questions": count_exam_questions_by_difficulty(exam_id,  'Hard'),   "correct_answered": 0},
    })
    graph = user["data_graph_leetcode_accuracy"][exam_id]
    total_incorrect_for_likelyhood = 0
    for level in ("easy", "medium", "hard"):
        correct   = data.get(f"{level}_correct", 0)
        incorrect = data.get(f"{level}_incorrect", 0)
        solved    = correct + incorrect
        graph[level]["number_solved"]    += solved
        graph[level]["correct_answered"] += correct
        total_incorrect_for_likelyhood   += (graph[level]["number_solved"] - graph[level]["correct_answered"])

    # compute and normalize your score
    raw_lcv = get_likelyhood_clearing_value(
        graph['easy']["correct_answered"],
        graph['hard']["correct_answered"],
        total_incorrect_for_likelyhood
    )
    # convert to Decimal so DynamoDB will accept it
    likelyhood_clearing_value = Decimal(str(raw_lcv))
    user["likelyhood_clearing_value"] = likelyhood_clearing_value

    # ─── 4. updating data_graph_modulewise ───────────────────────────────────
    user.setdefault("data_graph_modulewise", {})
    user["data_graph_modulewise"].setdefault(exam_id, {})
    user["data_graph_modulewise"][exam_id].setdefault(module_id, {
        "correct_answers": 0,
        "total_questions": get_module_no_of_questions_for_init(module_id),
    })
    total_correct = sum(data.get(f"{lvl}_correct", 0) for lvl in ("easy", "medium", "hard"))
    user["data_graph_modulewise"][exam_id][module_id]["correct_answers"] += total_correct

    # ─── 5. updating solved_wrong ────────────────────────────────────────────
    user.setdefault("solved_wrong", {})
    user["solved_wrong"].setdefault(exam_id, {})
    user["solved_wrong"][exam_id].setdefault(module_id, [])
    wrong_list = user["solved_wrong"][exam_id][module_id]
    for qid in data.get("correct_answers_qid", []):
        if qid in wrong_list:
            wrong_list.remove(qid)
    for qid in data.get("wrong_answers_qid", []):
        if qid not in wrong_list:
            wrong_list.append(qid)

    # ─── 6. save QnA history & persist user ───────────────────────────────────
    try:
        for qna_entry in data.get("detailed_user_qna", []):
            qna_entry.update({
                "email":     data["email"],
                "qna_id":    generate_id(6),
                "exam_id":   exam_id,
                "module_id": module_id,
                "timestamp": get_time()
            })
            QNAHistoryTable.put_item(Item=qna_entry)

        response = UserTable.update_item(
            Key={"email": data["email"]},
            UpdateExpression=(
                "SET examsTaken = :e, "
                "completed_idx = :c, "
                "data_graph_leetcode_accuracy = :l, "
                "data_graph_modulewise = :m, "
                "solved_wrong = :w, "
                "likelyhood_clearing_value = :lc"
            ),
            ExpressionAttributeValues={
                ":e": user["examsTaken"],
                ":c": user["completed_idx"],
                ":l": user["data_graph_leetcode_accuracy"],
                ":m": user["data_graph_modulewise"],
                ":w": user["solved_wrong"],
                ":lc": likelyhood_clearing_value,
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
            'is_paid' : "false",
            'plan_id': "free",
            'plan_valid_till': ""

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

def save_failed_payment_history(failure_data: dict) -> None:
    """
    Record a failed (or non-captured) payment into PaymentHistoryTable only.
    """
    PaymentHistoryTable.put_item(Item={
        'payment_id':    failure_data['payment_id'],
        'order_id':      failure_data['order_id'],
        'amount':        failure_data['amount'],
        'status':        failure_data['status'],
        'error_code':    failure_data.get('error_code'),
        'error_desc':    failure_data.get('error_desc'),
        'user_email':    failure_data['user_email'],
        'plan_id':       failure_data.get('plan_id'),
        'created_at':    failure_data['created_at']
    })


def save_successful_payment(payment_data: dict) -> dict:
    """
    1) Save payment to PaymentHistoryTable
    2) Update the user in UserTable:
       - mark is_paid = True
       - set plan_id
       - set plan_valid_till = now + 1 month
    """
    # 1) record the payment
    PaymentHistoryTable.put_item(Item={
        'payment_id':   payment_data['payment_id'],
        'order_id':     payment_data['order_id'],
        'amount':       payment_data['amount'],
        'created_at':   payment_data['created_at'],
        'signature':    payment_data['signature'],
        'user_email':   payment_data['user_email'],
        'plan_id':      payment_data['plan_id'],
        'status':       'captured',
    })

    # 2) compute expiry exactly one month from now
    expiry_dt  = datetime.now(IST) + relativedelta(months=1)
    expiry_iso = expiry_dt.isoformat()

    # 3) update or create the user record
    user_response = UserTable.update_item(
        Key={'email': payment_data['user_email']},
        UpdateExpression="""
            SET
              is_paid            = :paid,
              plan_id            = :plan,
              plan_valid_till    = :valid
        """,
        ExpressionAttributeValues={
            ':paid':  True,
            ':plan':  payment_data['plan_id'],
            ':valid': expiry_iso
        },
        ReturnValues="UPDATED_NEW"
    )

    return {
        'status':  'success',
        'message': 'Payment history saved and user subscription updated',
        'user_update': user_response.get('Attributes', {})
    }


def delete_user_payment_fields(email: str) -> dict:
    """
    Remove is_paid, plan_id, and plan_valid_till
    from the UserTable item keyed by `email`.
    """
    try:
        resp = UserTable.update_item(
            Key={ 'email': email },
            UpdateExpression="REMOVE is_paid, plan_id, plan_valid_till",
            ReturnValues="UPDATED_OLD"  
            # returns the old values of any removed attributes
        )
        removed = resp.get('Attributes', {}) or {}
        return {
            'status': 'success',
            'message': f'Removed payment fields for {email}',
            'removed_fields': removed
        }
    except ClientError as e:
        logging.error("DynamoDB error on delete: %s", e.response['Error']['Message'])
        raise RuntimeError(
            f"Failed to delete payment fields for {email}: "
            f"{e.response['Error']['Message']}"
        )
    


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
                module_data['module_id'] = module_id
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



def create_lecture(yt_link, category, title,
                   instructor_details, key_topics,
                   description, zoom_link, date_time_of_zoom_lec,
                   module_id, exam_id):
    """
    Inserts a new lecture record into DynamoDB and updates the corresponding module's lectures list.
    Returns the generated lecture_id.
    """

    lecture_id = generate_id()

    # ✅ Normalize date_time_of_zoom_lec to ISO8601 format
    if isinstance(date_time_of_zoom_lec, datetime):
        date_str = date_time_of_zoom_lec.replace(microsecond=0).isoformat()
    elif isinstance(date_time_of_zoom_lec, str):
        try:
            # Try parsing string to datetime
            parsed_date = datetime.fromisoformat(date_time_of_zoom_lec)
            date_str = parsed_date.replace(microsecond=0).isoformat()
        except ValueError:
            raise ValueError("date_time_of_zoom_lec must be a valid ISO8601 string or datetime object.")
    else:
        raise TypeError("date_time_of_zoom_lec must be a datetime object or ISO8601 string.")

    item = {
        'lecture_id': lecture_id,
        'yt_link': yt_link,
        'category': category,
        'title': title,
        'instructor_details': instructor_details,
        'key_topics': key_topics,
        'description': description,
        'zoom_link': zoom_link,
        'date_time_of_zoom_lec': date_str,
        'module_id': module_id,
        'exam_id': exam_id,
        'created_at': datetime.utcnow().replace(microsecond=0).isoformat()
    }

    try:
        # ✅ Insert lecture into LectureTable
        try:
            LectureTable.put_item(Item=item)
        except Exception as e:
            raise RuntimeError(f"Failed to write new lecture to DynamoDB: {e}") 

        # ✅ Append lecture_id to module's lectures array
        try:
            ModuleTable.update_item(
                Key={'module_id': module_id},
                UpdateExpression="SET lectures = list_append(if_not_exists(lectures, :empty_list), :lecture_id_list)",
                ExpressionAttributeValues={
                    ':lecture_id_list': [lecture_id],
                    ':empty_list': []
                }
            )
        except Exception as e:
            raise RuntimeError(f"Failed to write lecture_id to ModuleTable: {e}") 

    except (BotoCoreError, ClientError) as e:
        raise RuntimeError(f"Failed to write to DynamoDB: {e}")

    return lecture_id

def get_lecture_by_id(lecture_id):
    """
    Fetches a single lecture from DynamoDB by lecture_id.
    Raises RuntimeError if not found or if DynamoDB fails.
    """
    try:
        response = LectureTable.get_item(Key={'lecture_id': lecture_id})
        item = response.get('Item')
        if not item:
            raise RuntimeError(f"Lecture with id '{lecture_id}' not found.")
        return item

    except (BotoCoreError, ClientError) as e:
        raise RuntimeError(f"Failed to fetch from DynamoDB: {e}")





def get_random_lectures_from_module(module_id, count=5):
    """
    Fetches module by module_id, randomly picks `count` lecture_ids,
    and returns selected lecture summaries.
    """
    try:
        # Step 1: Get module
        response = ModuleTable.get_item(Key={'module_id': module_id})
        module_item = response.get('Item')
        if not module_item or 'lectures' not in module_item or not module_item['lectures']:
            raise RuntimeError(f"Module with id '{module_id}' not found or has no lectures.")

        lecture_ids = module_item['lectures']
        if len(lecture_ids) < count:
            count = len(lecture_ids)

        # Step 2: Randomly select unique lecture_ids
        selected_ids = random.sample(lecture_ids, count)

        # Step 3: Fetch lecture details
        lectures = []
        for lecture_id in selected_ids:
            response = LectureTable.get_item(Key={'lecture_id': lecture_id})
            lecture = response.get('Item')
            if lecture:
                lectures.append({
                    'lecture_id': lecture.get('lecture_id'),
                    'title': lecture.get('title'),
                    'category': lecture.get('category'),
                    'instructor_details': lecture.get('instructor_details'),
                    'duration': lecture.get('duration', None),  # duration may not exist
                    'yt_link': lecture.get('yt_link')
                })

        return lectures

    except (BotoCoreError, ClientError) as e:
        raise RuntimeError(f"DynamoDB operation failed: {e}")
    



def get_upcoming_lectures_for_exam(exam_id):
    """
    Query GSI to return upcoming lectures (today or future) for a given exam_id.
    """
    try:
        now_iso = datetime.utcnow().isoformat()

        response = LectureTable.query(
            IndexName='ExamUpcomingLecturesIndex',   # Your GSI name
            KeyConditionExpression=Key('exam_id').eq(exam_id) & Key('date_time_of_zoom_lec').gte(now_iso),
        )

        items = response.get('Items', [])

        lectures = []
        for lecture in items:
            lectures.append({
                'lecture_id': lecture.get('lecture_id'),
                'title': lecture.get('title'),
                'category': lecture.get('category'),
                'instructor_details': lecture.get('instructor_details'),
                'date_time_of_zoom_lec': lecture.get('date_time_of_zoom_lec'),
                'yt_link': lecture.get('yt_link')
            })

        return lectures

    except (BotoCoreError, ClientError) as e:
        raise RuntimeError(f"DynamoDB query failed: {e}")


def get_past_lectures_for_exam(exam_id):
    """
    Query GSI to return past lectures (before today) for a given exam_id.
    """
    try:
        now_iso = datetime.utcnow().isoformat()

        response = LectureTable.query(
            IndexName='ExamUpcomingLecturesIndex',   # Same GSI
            KeyConditionExpression=Key('exam_id').eq(exam_id) & Key('date_time_of_zoom_lec').lt(now_iso),
        )

        items = response.get('Items', [])

        lectures = []
        for lecture in items:
            lectures.append({
                'lecture_id': lecture.get('lecture_id'),
                'title': lecture.get('title'),
                'category': lecture.get('category'),
                'instructor_details': lecture.get('instructor_details'),
                'date_time_of_zoom_lec': lecture.get('date_time_of_zoom_lec'),
                'yt_link': lecture.get('yt_link')
            })

        return lectures

    except (BotoCoreError, ClientError) as e:
        raise RuntimeError(f"DynamoDB query failed: {e}")


def get_lecture_dashboard_details(exam_id):
    """
    Returns 2 upcoming and 2 past lectures for given exam_id.
    """
    try:
        now_iso = datetime.utcnow().isoformat()

        # Upcoming lectures (future dates)
        upcoming_response = LectureTable.query(
            IndexName='ExamUpcomingLecturesIndex',
            KeyConditionExpression=Key('exam_id').eq(exam_id) & Key('date_time_of_zoom_lec').gte(now_iso),
            Limit=2,
            ScanIndexForward=True  # upcoming first
        )
        upcoming_items = upcoming_response.get('Items', [])
        upcoming = [{
            'lecture_id': lec.get('lecture_id'),
            'title': lec.get('title'),
            'category': lec.get('category'),
            'instructor_details': lec.get('instructor_details'),
            'date_time_of_zoom_lec': lec.get('date_time_of_zoom_lec'),
            'yt_link': lec.get('yt_link')
        } for lec in upcoming_items]

        # Past lectures (older dates)
        past_response = LectureTable.query(
            IndexName='ExamUpcomingLecturesIndex',
            KeyConditionExpression=Key('exam_id').eq(exam_id) & Key('date_time_of_zoom_lec').lt(now_iso),
            Limit=2,
            ScanIndexForward=False  # latest past first
        )
        past_items = past_response.get('Items', [])
        past = [{
            'lecture_id': lec.get('lecture_id'),
            'title': lec.get('title'),
            'category': lec.get('category'),
            'instructor_details': lec.get('instructor_details'),
            'date_time_of_zoom_lec': lec.get('date_time_of_zoom_lec'),
            'yt_link': lec.get('yt_link')
        } for lec in past_items]

        return {
            'upcoming_lectures': upcoming,
            'past_lectures': past
        }

    except (BotoCoreError, ClientError) as e:
        raise RuntimeError(f"DynamoDB query failed: {e}")

def create_mock_test(data, csv_file):
    """
    data: dict with all fields except test_id, total_marks, questions
    csv_file: FileStorage for uploaded CSV with columns:
      Question, Option 1, Option 2, Option 3, Option 4,
      Correct Answer, difficulty, explanation, marks
    """
    # 1) Generate test_id 
    test_id = generate_id()

    # 2) Read & decode CSV
    try:
        raw = csv_file.read()
        text = raw.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to read or decode CSV file: {e}")

    # 3) Initialize CSV reader
    try:
        reader = csv.DictReader(StringIO(text))
    except Exception as e:
        raise ValueError(f"Error initializing CSV reader: {e}")

    questions = []
    total_marks = 0
    row_num = 0

    # 4) Process each row
    for row in reader:
        row_num += 1
        try:
            # a) Question text
            question_text = row.get("Question", "").strip()
            if not question_text:
                raise ValueError("missing 'Question' column")

            # b) Options 1–4
            opts = []
            for col in ["Option 1", "Option 2", "Option 3", "Option 4"]:
                val = row.get(col, "").strip()
                if val:
                    opts.append(val)
            if not opts:
                raise ValueError("no options found in columns Option 1–4")

            # c) Correct Answer
            correct = row.get("Answer", "").strip()
            if not correct:
                raise ValueError("missing 'Answer' column")

            # d) Marks
            marks_str = row.get("marks", row.get("Marks", "")).strip()
            marks = int(marks_str) if marks_str else 1
            total_marks += marks

            # e) Difficulty & Explanation (optional)
            difficulty  = row.get("difficulty", row.get("Difficulty", "")).strip()
            explanation = row.get("explanation", row.get("explaination", row.get("Explanation", ""))).strip()

            # f) Append to list
            questions.append({
                "test_question_id": f"{test_id}_question_{row_num}",
                "question":       question_text,
                "options":        opts,
                "correct_answer": correct,
                "difficulty":     difficulty,
                "explanation":    explanation,
                "marks":          marks
            })

        except Exception as e:
            raise ValueError(f"Error processing CSV row {row_num}: {e}")

    # 5) Optional sanity‐check: no_of_questions matches
    expected = int(data.get("no_of_questions", len(questions)))
    if expected != len(questions):
        raise ValueError(f"no_of_questions mismatch: expected {expected}, got {len(questions)} rows")

    # 6) Build the item
    item = {
        "test_id":            test_id,
        "title":              data["title"],
        "duration":           int(data["duration"]),
        "no_of_questions":    len(questions),
        "difficulty":         data["difficulty"],
        "is_featured_test":   data["is_featured_test"],
        "description":        data["description"],
        "exam_id":            data["exam_id"],
        "is_modulewise_test": data["is_modulewise_test"],
        "module_id":          data.get("module_id"),
        "total_marks":        total_marks,
        "questions":          questions
    }

    # 7) Persist to DynamoDB
    try:
        MockTestTable.put_item(Item=item)
    except Exception as e:
        raise RuntimeError(f"Failed to write to MockTests table: {e}")

    return item


def get_mock_test(test_id):
    """
    Fetches a mock test by its test_id from DynamoDB.
    Raises:
      KeyError   – if no test with that ID exists
      RuntimeError – on any underlying DynamoDB error
    """
    try:
        resp = MockTestTable.get_item(Key={"test_id": test_id})
    except Exception as e:
        raise RuntimeError(f"Error fetching test from DB: {e}")

    item = resp.get("Item")
    if not item:
        raise KeyError(f"No mock test found with test_id='{test_id}'")

    return item




def submit_mock_test_controller(user_email, data):
    try:
        request_email = data.get('email')
        if user_email != request_email:
            return {"msg": "Unauthorized. Email mismatch."}, 401

        # Check if user exists in TestsSolvedUserDataTable
        response = TestsSolvedUserDataTable.get_item(Key={'email': user_email})
        item = response.get('Item')

        if item:
            # User exists -> append to tests_submitted
            try:
                TestsSolvedUserDataTable.update_item(
                    Key={'email': user_email},
                    UpdateExpression="SET tests_submitted = list_append(if_not_exists(tests_submitted, :empty_list), :new_test)",
                    ExpressionAttributeValues={
                        ':new_test': [data],
                        ':empty_list': []
                    }
                )
            except ClientError as e:
                return {"msg": "Failed to update TestsSolvedUserDataTable", "error": str(e)}, 500
        else:
            # User does not exist -> create new item
            try:
                TestsSolvedUserDataTable.put_item(Item={
                    'email': user_email,
                    'tests_submitted': [data]
                })
            except ClientError as e:
                return {"msg": "Failed to create item in TestsSolvedUserDataTable", "error": str(e)}, 500

        # Update UserTable
        user_update_item = {
            'test_id': data.get('test_id'),
            'marks_scored': data.get('marks_scored'),
            'total_marks': data.get('total_marks'),
            'exam_id': data.get('exam_id'),
            'timestamp': data.get('timestamp')
        }

        try:
            UserTable.update_item(
                Key={'email': user_email},
                UpdateExpression="SET tests_submitted = list_append(if_not_exists(tests_submitted, :empty_list), :new_entry)",
                ExpressionAttributeValues={
                    ':new_entry': [user_update_item],
                    ':empty_list': []
                }
            )
        except ClientError as e:
            return {"msg": "Failed to update UserTable", "error": str(e)}, 500

        return {"msg": "Mock test submitted successfully."}, 200

    except Exception as e:
        return {"msg": "An unexpected error occurred", "error": str(e)}, 500
    


    # controller.py (add this)
def get_test_dashboard_controller(exam_id):
    try:
        # Scan with filter on exam_id
        response = MockTestTable.scan(
            FilterExpression='exam_id = :exam_id_val',
            ExpressionAttributeValues={':exam_id_val': exam_id}
        )

        items = response.get('Items', [])

        # Only return selected fields
        tests = []
        for item in items:
            test_data = {
                'title': item.get('title'),
                'difficulty': item.get('difficulty'),
                'duration': item.get('duration'),
                'no_of_questions': item.get('no_of_questions'),
                'exam_id': item.get('exam_id'),
                'test_id': item.get('test_id'),
                "is_featured_test": item.get('is_featured_test'),
                "is_modulewise_test": item.get('is_modulewise_test')
            }
            tests.append(test_data)

        return {"tests": tests}, 200

    except ClientError as e:
        return {"msg": "Failed to query MockTestTable", "error": str(e)}, 500
    except Exception as e:
        return {"msg": "An unexpected error occurred", "error": str(e)}, 500

def grant_paid_access(email: str, plan_id: str, plan_valid_till: str) -> dict:
    """
    Updates the user in UserTable to set is_paid=True, plan_id=plan_id, and plan_valid_till.
    """
    try:
        resp = UserTable.get_item(Key={'email': email})
        if 'Item' not in resp:
            return {'status': 'error', 'message': f'User {email} not found.'}
        UserTable.update_item(
            Key={'email': email},
            UpdateExpression="SET is_paid = :paid, plan_id = :plan_id, plan_valid_till = :plan_valid_till",
            ExpressionAttributeValues={
                ':paid': True,
                ':plan_id': plan_id,
                ':plan_valid_till': plan_valid_till
            }
        )
        return {'status': 'success', 'message': f'Paid access granted to {email} with plan_id {plan_id}.'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
