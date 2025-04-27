# controller.py

import os
import secrets
import string
from boto3 import resource
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




# DATA OPERATIONS
def get_module_questions(module_id):
    return ModuleTable.get_item(
        Key={'module_id': module_id},
        AttributesToGet=['questions']
    )


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


def add_questions_in_module(module_id, data):
    return ModuleTable.update_item(
        Key={'module_id': module_id},
        AttributeUpdates={
            'questions': {'Value': data, 'Action': 'PUT'},
            'numberOfQuestions': {'Value': len(data), 'Action': 'PUT'}
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


def submit_questions(data, user):
    exam_id = data["exam_id"]
    module_id = data["module_id"]

    if exam_id not in user['examsTaken']:
        user['examsTaken'].append(exam_id)

    user.setdefault("performanceData", {})
    user["performanceData"].setdefault(exam_id, {})
    user["performanceData"][exam_id].setdefault(module_id, {
        "questionsAnswered": 0,
        "correctAns": 0,
        "incorrectAns": 0,
        "easyQuestionsCorrect": 0,
        "easyQuestionsIncorrect": 0,
        "mediumQuestionsIncorrect": 0,
        "hardQuestionsCorrect": 0,
        "mediumQuestionsCorrect": 0,
        "hardQuestionsIncorrect": 0,
        "topics": {}
    })

    module_data = user["performanceData"][exam_id][module_id]
    try:
        module_data["questionsAnswered"] += data["questions_answered"]
        module_data["correctAns"] += data["answered_correct"]
        module_data["incorrectAns"] += data["answered_incorrect"]
        module_data["easyQuestionsCorrect"] += data["easy_questions_correct"]
        module_data["easyQuestionsIncorrect"] += data["easy_questions_incorrect"]
        module_data["mediumQuestionsIncorrect"] += data["medium_questions_incorrect"]
        module_data["mediumQuestionsCorrect"] += data["medium_questions_correct"]
        module_data["hardQuestionsIncorrect"] += data["hard_questions_incorrect"]
        module_data["hardQuestionsCorrect"] += data["hard_questions_correct"]
    except Exception as e:
        print(f"ERROR IN UPDATING QUESTION COUNTS: {str(e)}")

    for subtopic, stats in data.get("topicwise", {}).items():
        topics = module_data["topics"]
        topics.setdefault(subtopic, {
            "correctAns": 0,
            "incorrectAns": 0,
            "easyQuestionsCorrect": 0,
            "easyQuestionsIncorrect": 0,
            "mediumQuestionsCorrect": 0,
            "mediumQuestionsIncorrect": 0,
            "hardQuestionsCorrect": 0,
            "hardQuestionsIncorrect": 0
        })
        topics[subtopic]["correctAns"] += stats["answered_correct"]
        topics[subtopic]["incorrectAns"] += stats["answered_incorrect"]
        topics[subtopic]["easyQuestionsCorrect"] += stats["easy_questions_correct"]
        topics[subtopic]["easyQuestionsIncorrect"] += stats["easy_questions_incorrect"]
        topics[subtopic]["mediumQuestionsCorrect"] += stats["medium_questions_correct"]
        topics[subtopic]["mediumQuestionsIncorrect"] += stats["medium_questions_incorrect"]
        topics[subtopic]["hardQuestionsCorrect"] += stats["hard_questions_correct"]
        topics[subtopic]["hardQuestionsIncorrect"] += stats["hard_questions_incorrect"]

    try:
        for qna_entry in data.get("detailed_user_qna", []):
            qna_entry["email"] = data['email']
            qna_entry["qna_id"] = generate_id(6)
            qna_entry['exam_id'] = exam_id
            qna_entry['module_id'] = module_id
            qna_entry['timestamp'] = get_time()
            QNAHistoryTable.put_item(Item=qna_entry)
        response = UserTable.update_item(
            Key={"email": data['email']},
            UpdateExpression="SET performanceData = :p, examsTaken = :e",
            ExpressionAttributeValues={
                ":p": user['performanceData'],
                ":e": user['examsTaken']
            },
            ReturnValues="UPDATED_NEW"
        )
    except Exception as e:
        return {"status": "error", "message": f"Error while saving QNA history or updating user: {str(e)}"}

    return response


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
            'completedModules': [],
            'performanceData': {}
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
