from boto3 import resource
from botocore.exceptions import BotoCoreError, ClientError
import secrets
import string
from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from flask_bcrypt import Bcrypt
import os
from datetime import datetime, timedelta, timezone



bcrypt = Bcrypt()



auth_bp = Blueprint('auth', __name__)




AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
REGION_NAME = 'us-east-1'
# AWS_SESSION_TOKEN = os.getenv(AWS_SESSION_TOKEN)
 
resource = resource(
   'dynamodb',
   aws_access_key_id     = AWS_ACCESS_KEY_ID,
   aws_secret_access_key = AWS_SECRET_ACCESS_KEY,
#    aws_session_token     = AWS_SESSION_TOKEN, 
   region_name           = REGION_NAME
)

def generate_id(size):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(size))

def get_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")



# CREATING USER TABLE
def create_user_table():   
   table = resource.create_table(
       TableName = 'User', # Name of the table
       KeySchema = [

           { "AttributeName": "email", "KeyType": "HASH" }

       ],
       AttributeDefinitions = [

           { "AttributeName": "email", "AttributeType": "S" }
       ],
       ProvisionedThroughput={
           'ReadCapacityUnits'  : 10,
           'WriteCapacityUnits': 10
       }
   )
   return table
UserTable = resource.Table('User')

#CREATING EXAM TABLE
def create_exam_table():   
   table = resource.create_table(
       TableName = 'Exam', # Name of the table
       KeySchema = [
           {
               'AttributeName': 'exam_id',
               'KeyType'      : 'HASH' #RANGE = sort key, HASH = partition key
           }
       ],
       AttributeDefinitions = [
           {
               'AttributeName': 'exam_id', # Name of the attribute
               'AttributeType': 'S'   # N = Number (B= Binary, S = String)
           }
       ],
       ProvisionedThroughput={
           'ReadCapacityUnits'  : 10,
           'WriteCapacityUnits': 10
       }
   )
   return table
ExamTable = resource.Table('Exam')

def create_module_table():   
   table = resource.create_table(
       TableName = 'Module', # Name of the table
       KeySchema = [
           {
               'AttributeName': 'module_id',
               'KeyType'      : 'HASH'  # HASH = partition key
           }
       ],
       AttributeDefinitions = [
           {
               'AttributeName': 'module_id',  # Name of the attribute
               'AttributeType': 'S'           # S = String
           }
       ],
       BillingMode='PAY_PER_REQUEST'  # Set to on-demand billing mode
   )

   return table
ModuleTable = resource.Table('Module')

def create_qna_history_table():   
   table = resource.create_table(
       TableName = 'QNAHistory', # Name of the table
       KeySchema = [
           {
               'AttributeName': 'qna_id',
               'KeyType'      : 'HASH' #RANGE = sort key, HASH = partition key
           }
       ],
       AttributeDefinitions = [
           {
               'AttributeName': 'qna_id', # Name of the attribute
               'AttributeType': 'S'   # N = Number (B= Binary, S = String)
           }
       ],
       ProvisionedThroughput={
           'ReadCapacityUnits'  : 10,
           'WriteCapacityUnits': 10
       }
   )
   return table
QNAHistoryTable = resource.Table('QNAHistory')


def get_module_questions(module_id):
    response = ModuleTable.get_item(
        Key = {
            'module_id': module_id
        },
        AttributesToGet = [
            'questions' 
        ]
    )
    return response


    
def get_modules_by_exam_id(exam_id):
    try:
        # Perform a scan to get all modules for the given exam_id from the ModuleTable
        response = ModuleTable.scan(
            ProjectionExpression="module_id, module_name",  # Only retrieve module_id and module_name
            FilterExpression="exam_id = :exam_id",  # Filter for the given exam_id
            ExpressionAttributeValues={
                ":exam_id": exam_id  # Bind the exam_id value
            }
        )
        
        # Extract the items from the response
        items = response.get('Items', [])
        
        # Return the module_id and module_name for all modules related to the exam_id
        return {
            'statusCode': 200,
            'msg': 'Modules retrieved successfully!',
            'modules': items  # List of modules with module_id and module_name
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'msg': 'Error occurred while retrieving modules',
            'error': str(e)
        }

def get_all_exam_details():
    try:
        # Perform a scan to get all items
        response = ExamTable.scan(
            ProjectionExpression="exam_id, exam_name, modules"  # Only retrieve exam_id and exam_name
        )
        
        # Extract the items from the response
        items = response.get('Items', [])
        
        # Create a dictionary where the exam_id is the key
        exams_dict = {}
        for item in items:
            exam_id = item.get('exam_id')
            exam_name = item.get('exam_name')
            # modules = item.get('modules', [])

            # Populate the dictionary with the exam_id as the key
            exams_dict[exam_id] = {
                'exam_name': exam_name,
                'modules': get_modules_by_exam_id(exam_id)
            }
        
        # Return the exams in the desired format
        return {
            'statusCode': 200,
            'msg': 'Exams retrieved successfully!',
            'exams': exams_dict  # Exams now mapped by exam_id
        }
    
    except Exception as e:
        return {
            'statusCode': 500,
            'msg': 'Error occurred while retrieving exams',
            'error': str(e)
        }

def add_questions_in_module(id, data:dict):
 
    # print(data)
    response = ModuleTable.update_item(
       Key = {
           'module_id': id
       },
       AttributeUpdates={
           'questions': {
               'Value'  : data,
               'Action' : 'PUT' 
           },
           'numberOfQuestions': {
                'Value'  : len(data),
                'Action' : 'PUT' 
              }
       },
 
       ReturnValues = "UPDATED_NEW"  # returns the new updated values
    )
    return response

def initialize_new_module(exam_id, module_name):
    try:
        # Step 1: Insert the new module into the ModuleTable
        module_id = generate_id(6)  # Generate the module ID
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

        # Check if the response is OK
        if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
            # Step 2: Update the exam table's 'modules' array
            update_response = ExamTable.update_item(
                Key={'exam_id': exam_id},
                UpdateExpression="SET modules = list_append(if_not_exists(modules, :empty_list), :new_module_id)",
                ExpressionAttributeValues={
                    ':new_module_id': [module_id],  # Directly pass the string as a list
                    ':empty_list': []  # Initialize 'modules' as an empty list if it doesn't exist
                },
                ReturnValues="UPDATED_NEW"  # Return the updated value of the 'modules' array
            )



            # Return the response for updating the exam table
            return {"status": "success", "module_id": module_id, "update_response": update_response}

        else:
            return {"status": "error", "message": "Failed to insert new module"}

    except Exception as e:
        return {"status": "error", "message": str(e)}
    
def initialize_new_exam(exam_name):
    """Initializes a new exam with a unique ID and stores it in the database."""
    try:
        # Step 1: Generate a unique exam ID (using UUID for uniqueness)
        exam_id = generate_id(6)  # Generate a short unique exam ID
        
        # Step 2: Insert the new exam into the ExamTable
        response = ExamTable.put_item(
            Item={
                'exam_id': exam_id,
                'exam_name': exam_name,
                'modules': []  # Start with an empty list of modules
            }
        )
        
        if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
            # Return success response if the HTTPStatusCode is 200
            return {
                "status": "success",
                "exam_id": exam_id,
                "exam_name": exam_name,
                "message": "Exam created successfully."
            }
        else:
            # If status code isn't 200, treat it as an error
            return {
                "status": "error",
                "message": "Failed to initialize exam due to an unexpected error."
            }
    
    except Exception as e:
        # Log the error for debugging purposes
        
        # Return error response
        return {
            "status": "error",
            "message": f"Failed to initialize exam: {str(e)}"
        }

def set_new_history(data:dict):
    response = ExamTable.put_item(
       Item = {
            "qna_id": generate_id(6),
            "user_id": data['user_id'],
            "question_id" : data['question_id'],
            "exam_id" : data['exam_id'],
            "module_id" : data['module_id'],
            "selected_answer" : data['selected_answer'],
            "correct_answer" : data['correct_answer'],
            "is_correct": data['is_correct'],
            "timestamp" : data['timestamp']
        }
    )
    return response

def submit_questions(data, user):

    exam_id = data["exam_id"]
    module_id = data["module_id"]

    if exam_id not in user['examsTaken']:
        user['examsTaken'].append(exam_id)

    if not isinstance(user.get("performanceData"), dict):
        user["performanceData"] = {}  

    # Ensure exam_id key is initialized as a dictionary
    if exam_id not in user["performanceData"] or not isinstance(user["performanceData"][exam_id], dict):
        user["performanceData"][exam_id] = {}

    # Ensure module_id key is initialized as a dictionary
    if module_id not in user["performanceData"][exam_id] or not isinstance(user["performanceData"][exam_id][module_id], dict):
        user["performanceData"][exam_id][module_id] = {
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
        }

        


    try:
    # Update module data
        module_data = user["performanceData"][exam_id][module_id]
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
        print(f"ERROR IN ADDING AND UPDATING NUMBER OF QUESTIONS CORRECT AND INCORRECT.: {str(e)}")



    # Update topic-wise data
    for subtopic, stats in data["topicwise"].items():
        if subtopic not in module_data["topics"]:
            module_data["topics"][subtopic] = {
                "correctAns": 0, 
                "incorrectAns": 0,
                "easyQuestionsCorrect": 0,
                "easyQuestionsIncorrect": 0,
                "mediumQuestionsIncorrect": 0,
                "mediumQuestionsCorrect": 0,
                "hardQuestionsCorrect": 0,
                "hardQuestionsIncorrect": 0
            }

        module_data["topics"][subtopic]["correctAns"] += stats["answered_correct"]
        module_data["topics"][subtopic]["incorrectAns"] += stats["answered_incorrect"]
        module_data["topics"][subtopic]["easyQuestionsCorrect"] += stats["easy_questions_correct"]
        module_data["topics"][subtopic]["easyQuestionsIncorrect"] += stats["easy_questions_incorrect"]
        module_data["topics"][subtopic]["mediumQuestionsCorrect"] += stats["medium_questions_correct"]
        module_data["topics"][subtopic]["mediumQuestionsIncorrect"] += stats["medium_questions_incorrect"]
        module_data["topics"][subtopic]["hardQuestionsCorrect"] += stats["hard_questions_correct"]
        module_data["topics"][subtopic]["hardQuestionsIncorrect"] += stats["hard_questions_incorrect"]



    # Adding entries to QNAHistoryTable for each element in detailed_user_qna
    try:
        for qna_entry in data["detailed_user_qna"]:
            qna_entry["email"] = data['email']  
            qna_entry["qna_id"] = generate_id(6)  
            qna_entry['exam_id'] = exam_id
            qna_entry['module_id'] = module_id
            qna_entry['timestamp'] = get_time()
            # Insert each entry into the QNAHistoryTable (assuming QNAHistoryTable is a DynamoDB Table)
            try: 
                QNAHistoryTable.put_item(Item=qna_entry)
            except Exception as e:
                return {"status": "error", "message": f" Error while adding to QNAHistory Table \n\n{str(e)}"}

        try: 
            response = UserTable.update_item(
            Key={"email": data['email']},
            UpdateExpression="SET performanceData = :p, examsTaken = :e",
            ExpressionAttributeValues={
                ":p": user['performanceData'],
                ":e": user['examsTaken']
            },
            ReturnValues="UPDATED_NEW"  # Returns the updated attributes
        )
        except Exception as e:
                return {"status": "error", "message": f" Error while updating performanceData in  UserTable \n\n{str(e)}"}
    
    except Exception as e:
        return {"status": "error", "message": f"{str(e)}"}
    
    return response


# GET USER
def get_user(email):
    try:
        response = UserTable.get_item(Key={'email': email})
        if 'Item' not in response:
            return {'error': 'User not found!'}, 404
        user = response['Item']
        del user['password']
        return user
    except Exception as e:
        return {'error': 'An unexpected error occurred', 'details': str(e)}


# AUTHENTICATION
def verify_jwt():
    try:
        verify_jwt_in_request()  
        user_email = get_jwt_identity()  
        return user_email
    except Exception as e:
        return jsonify({'message': 'Unauthorized', 'error': str(e)}), 401

def register(email, hashed_password, fullName):
    try:
        # Check if the user already exists
        response = UserTable.get_item(Key={'email': email})
        if 'Item' in response:
            return {'message': 'Username already exists!'}, 400  

        # Insert user into the database
        response_new = UserTable.put_item(
            Item={
                'user_id': generate_id(6),
                'email': email,
                'password': hashed_password,
                'fullName': fullName,
                'joinedOn': get_time(),
                'lastLogin': '',
                'examsTaken': [],
                'completedModules': [],
                'performanceData': []
            }
        )

        return {'message': 'User registered successfully!'}, 201 

    except ClientError as e:
        return {'error': 'DynamoDB Client Error', 'details': e.response['Error']}, 500 
    except BotoCoreError as e:
        return {'error': 'DynamoDB Connection Error', 'details': str(e)}, 500 
    except Exception as e:
        return {'error': 'An unexpected error occurred', 'details': str(e)}, 500 

def login(email, password):
    try:
        response = UserTable.get_item(Key={'email': email})

        if 'Item' not in response:
            return jsonify({'message': 'User not found!'}), 404

        user = response['Item']
        if bcrypt.check_password_hash(user['password'], password):
            access_token = create_access_token(identity=user['email'])
            return jsonify({'message': 'Login Success!', 'response': response , 'access_token': access_token}), 200

        return jsonify({'message': 'Invalid password!'}), 401

    except ClientError as e:
        return jsonify({'error': 'DynamoDB Client Error', 'details': e.response['Error']}), 500
    except BotoCoreError as e:
        return jsonify({'error': 'DynamoDB Connection Error', 'details': str(e)}), 500
    except Exception as e:
        return jsonify({'error': 'An unexpected error occurred', 'details': str(e)}), 500

