
# # SUBMITTING QNA ROUTE
# @app.route('/submit-questions', methods=['POST'])
# @jwt_required()
# def submit_questions():
#     try:
#         data = request.get_json()
#         if not data:
#             return jsonify({"error": "No data provided."}), 400
#     except Exception:
#         return jsonify({"error": "Invalid JSON format."}), 400

#     email = get_jwt_identity()
#     if 'email' not in data:
#         return jsonify({"error": "Email is required in the request data."}), 400
#     if email != data['email']:
#         return jsonify({"error": "Unauthorized access."}), 401

#     try:
#         user = dynamodb.get_user(data['email'])
#         if not user or isinstance(user, tuple):
#             return jsonify({"error": "User not found."}), 404
#     except Exception:
#         return jsonify({"error": "Failed to retrieve user information."}), 500

#     try:
#         response = dynamodb.submit_questions(data, user)
#         return jsonify(response), 200
#     except Exception:
#         return jsonify({"error": "Failed to submit questions."}), 500




# ADDING MODULES TO DB ROUTE
# @app.route('/add-to-module/<string:module_id>', methods=['POST'])
# def add_to_module(module_id):
#     if not module_id:
#         return jsonify({"error": "module_id is required"}), 400

#     file = request.files.get('csv_file')
#     if not file:
#         return jsonify({"error": "CSV file is required"}), 400

#     try:
#         file_content = file.read().decode('utf-8')
#         from io import StringIO
#         import csv
#         csv_file = StringIO(file_content)
#         csv_reader = csv.DictReader(csv_file)

#         questionResponse = dynamodb.get_module_questions(module_id)
#         questions = questionResponse['Item']['questions']

#         for i, row in enumerate(csv_reader):
#             row['module_id'] = module_id
#             row['question_id'] = f"{module_id}_{i+1}"
#             questions.append(row)

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

#     response = dynamodb.add_questions_in_module(module_id, questions)
#     if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
#         return jsonify({'msg': 'Added successfully'}), 200

#     return jsonify({'msg': 'Some error occurred', 'response': response}), 500




# Get questions from module and idx
# @app.route('/get-questions/<string:module_id>/<int:idx>')
# @jwt_required()
# def route_get_questions(module_id, idx):
#     try:
#         questions = dynamodb.get_questions(module_id, idx)
#         if not questions:
#             return jsonify({'msg': 'No questions found'}), 404

#         # questions is a list of dicts
#         return jsonify({'questions': questions}), 200

#     except Exception as e:
#         return jsonify({'msg': f'An unexpected error occurred: {e}'}), 500

