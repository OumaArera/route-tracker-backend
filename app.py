from flask import Flask, request, jsonify, make_response
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_restful import Api
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, get_jwt, unset_jwt_cookies
from models import db
from datetime import datetime, timezone, timedelta
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import func, and_, Date, or_, extract
import smtplib
from email.mime.text import MIMEText
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
import json
import os
import re
from sqlalchemy.orm import joinedload
from werkzeug.utils import secure_filename
from flask import send_from_directory







from models import User,  RoutePlan, Location, Reply,  Facility, AssignedMerchandiser, KeyPerformaceIndicator, Response, MerchandiserPerformance, Message

load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

app.config['SMTP_SERVER_ADDRESS'] = os.getenv("SMTP_SERVER_ADDRESS")
app.config['SMTP_USERNAME'] = os.getenv("SMTP_USERNAME")
app.config['SMTP_PASSWORD'] = os.getenv("SMTP_PASSWORD")
app.config['SMTP_PORT'] = os.getenv("SMTP_PORT")
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'Images')
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'Images')


db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

bcrypt = Bcrypt(app)

api = Api(app)

CORS(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


blacklist = set()

@app.route('/')
def index():
    return '<h1>Merchandiser Route App</h1>'

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route("/users/edit-user/<int:id>", methods=["PUT"])
@jwt_required()
def change_user_details(id):

    data = request.get_json()

    if not data:
        return jsonify({'message': 'Invalid request: Empty data', "successful": False, "status_code": 400}), 400

    # Extract first and last name from request data
    first_name = data.get('first_name')
    last_name = data.get('last_name')

    # Validate that both first and last names are provided
    if not first_name or not last_name:
        return jsonify({'message': 'Invalid request: first_name and last_name are required', "successful": False, "status_code": 400}), 400

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message': 'User not found', "successful": False, "status_code": 404}), 404

    # Update user details
    user.first_name = first_name
    user.last_name = last_name

    try:
        # Commit changes to the database
        db.session.commit()
        return jsonify({'message': 'User details updated successfully',"successful": True,"status_code": 200}), 200
    
    except Exception as e:
        # Rollback in case of an error
        db.session.rollback()
        return jsonify({'message': 'An error occurred while updating user details',"successful": False,"status_code": 500}), 500
    

@app.route("/users/delete-user", methods=["DELETE"])
@jwt_required()
def delete_user():
    data = request.get_json()
    staff_no = data.get("staff_no")
    user_to_delete = User.query.filter_by(staff_no=staff_no).first()

    if not user_to_delete:
        return jsonify({'message': 'User not found', "successful": False, "status_code": 404}), 404

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        return jsonify({'message': f'User {staff_no} has been deleted successfully', "successful": True, "status_code": 204}), 204

    except Exception as err:
        db.session.rollback()
        return jsonify({'message': f'Failed to delete user: {err}', "successful": False, "status_code": 500}), 500
    

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in blacklist

@app.route("/users/logout", methods=["POST"])
@jwt_required()
def logout_user():

    jti = get_jwt()["jti"]
    blacklist.add(jti)

    response = make_response(jsonify({"message": "Logout successful.", "successful": True, "status_code": 201}))

    unset_jwt_cookies(response)

    return response, 201


@app.route('/users/signup', methods=['POST'])
def signup():
    data = request.get_json()

    # Confirm if there's data
    if not data:
        return jsonify({"message": "Invalid request: You provided an empty data", "successful": False, "status_code": 400}), 400

    # Extract required fields
    first_name = data.get('first_name').title() if data.get('first_name') else None
    middle_name = data.get('middle_name').title() if data.get('middle_name') else None
    last_name = data.get('last_name').title() if data.get('last_name') else None
    national_id_no = data.get('national_id_no')
    username = data.get('username').lower() if data.get('username') else None
    email = data.get('email').lower() if data.get('email') else None
    password = data.get('password')
    staff_no = data.get('staff_no')
    role = data.get("role").lower() if data.get("role") else None

    try:
        national_id_no = int(data.get('national_id_no'))
        staff_no = int(data.get('staff_no'))
    except (ValueError, TypeError):
        return jsonify({'message': 'National ID and Staff number must be integers', "successful": False, "status_code": 400}), 400

    if User.query.filter(User.staff_no == staff_no).first():
        return jsonify({'message': 'Staff number already assigned',"successful": False,"status_code": 400}), 400

    if User.query.filter(User.national_id_no == national_id_no).first():
        return jsonify({'message': 'Another user exists with the provided National ID Number',"successful": False,"status_code": 400}), 400

    # Check for required fields
    if not all([first_name, role, last_name, national_id_no, username, email, password]):
        return jsonify({'message': 'Missing required fields',"successful": False,"status_code": 400}), 400

    # Check if username or email already exist
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'message': 'Username or email already exists',"successful": False,"status_code": 409 }), 409

    # Extra checks for input data
    if not isinstance(first_name, str) or len(first_name) > 200:
        return jsonify({'message': 'First name must be a string and not more than 200 characters', "successful": False, "status_code": 400}), 400

    if middle_name and (not isinstance(middle_name, str) or len(middle_name) > 200):
        return jsonify({'message': 'Middle name must be a string and not more than 200 characters', "successful": False, "status_code": 400}), 400

    if not isinstance(last_name, str) or len(last_name) > 200:
        return jsonify({'message': 'Last name must be a string and not more than 200 characters',"successful": False,"status_code": 400}), 400

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'message': 'Invalid email address',"successful": False,"status_code": 400}), 400

    if not isinstance(password, str) or len(password) < 6:
        return jsonify({ 'message': 'Password must be a string and at least 6 characters long', "successful": False, "status_code": 400}), 400
    
    if role not in ["manager", "merchandiser", "admin"]:
        return jsonify({ 'message': 'Role must be either manager, merchandiser or admin',"successful": False, "status_code": 400}), 400

    # Hash the password before saving it
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    # Create new user object
    new_user = User( first_name=first_name, middle_name=middle_name, last_name=last_name, national_id_no=national_id_no, username=username, email=email, password=hashed_password, staff_no = staff_no, role=role)

    access_token = create_access_token(identity=new_user.id)

    try:
        db.session.add(new_user)
        db.session.commit()
        send_new_user_credentials(data)
        return jsonify({"successful": True, "status_code": 201, "access_token": access_token, 'message': 'User created successfully'}), 201

    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to create user. Error: {err}", "successful": False,"status_code": 500 }), 500


@app.route("/users/rest-user", methods=["PUT"])
@jwt_required()
def reset_user_password():

    data = request.get_json()

    if not data:
        return jsonify({"message": "Invalid request: Empty reques","successful": False,"status_code": 400}), 400
    
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Missing required fields", "successful": False, "status_code": 400}), 400
    
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "User not found","successful": False,"status_code": 404}), 404
    

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    user.password = hashed_password

    try:
        db.session.commit()
        send_user_new_password(data, user.first_name)
        return jsonify({"message": "Password reset successfully", "successful": True, "status_code": 200}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({ "message": f"An error occurred: {str(e)}", "successful": False, "status_code": 500}), 500


def send_user_new_password(data, first_name):

    email = data.get("email")
    password = data.get("password")

    subject = f'Password Reset'

    body = f"\nGreetings {first_name}, I trust this mail finds you well.\n\n"

    body += f"Your request for password reset is successful.\n\n"
    body += f"You login credentials are as below\n\n"

    body += f"Email: {email}\n\n"
    body += f"Password: {password}\n\n"
    body += f"Use this url to login https://m-route-frontend.vercel.app \n\n"
    body += "Once you log in,  change your password.\n\n"

    body += f"Kind regards,\n\n"
    body += f"Merch Mate Group\n\n"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = f"merchmate@trial-351ndgwynjrlzqx8.mlsender.net"
    msg['To'] = email

    smtp_server = app.config['SMTP_SERVER_ADDRESS']
    smtp_port = app.config['SMTP_PORT']
    username = app.config['SMTP_USERNAME']
    password = app.config['SMTP_PASSWORD']

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(username, password)
        server.sendmail(username, email, msg.as_string())


def send_new_user_credentials(data):
    first_name = data.get('first_name').title()
    last_name = data.get('last_name').title()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get("role")

    subject = f'Account Creation'

    body = f"\nGreetings {first_name} {last_name}, I trust this mail finds you well.\n\n"

    body += f"You have been created in Merch Mate platform as {role}.\n\n"
    body += f"You login credentials are as below\n\n"

    body += f"Email: {email}\n\n"
    body += f"Password: {password}\n\n"
    body += f"Use this url to login https://m-route-frontend.vercel.app/ \n\n"
    body += "Once you log in,  change your password.\n\n"

    body += f"Kind regards,\n\n"
    body += f"Merch Mate Group\n\n"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = f"merchmate@trial-351ndgwynjrlzqx8.mlsender.net"
    msg['To'] = email

    smtp_server = app.config['SMTP_SERVER_ADDRESS']
    smtp_port = app.config['SMTP_PORT']
    username = app.config['SMTP_USERNAME']
    password = app.config['SMTP_PASSWORD']

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(username, password)
        server.sendmail(username, email, msg.as_string())


@app.route('/users', methods=['GET'])
@jwt_required()
def users():
    users = User.query.all()

    if not users:
        return jsonify({ "message":"No users found", "successful": False, "status_code": 404 }), 404
    
    user_list = []
    for user in users:
        user_info = {'id': user.id, 'first_name': user.first_name, 'last_name': user.last_name, 'username': user.username, 'email': user.email, 'role': user.role, 'status': user.status,  "staff_no": user.staff_no, "avatar": user.avatar,}
        user_list.append(user_info)


    return jsonify({ "successful": True, "status_code": 200, 'message': user_list}), 200


@app.route('/users/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found", "successful": False, "status_code": 404}), 404

    user_info = {'id': user.id, 'first_name': user.first_name, 'last_name': user.last_name, 'username': user.username, 'email': user.email, 'role': user.role, 'status': user.status, "staff_no": user.staff_no, "avatar": user.avatar}


    return jsonify({ "successful": True, "status_code": 200, 'message': user_info}), 200

@app.route("/users/manager-route-plans/<int:manager_id>", methods=["GET"])
@jwt_required()
def get_manager_route_plans(manager_id):
    # Filter route plans based on manager_id
    route_plans = RoutePlan.query.filter_by(manager_id=manager_id).all()

    if not route_plans:
        return jsonify({'message': 'No route plans found for this manager', "successful": False, "status_code": 404}), 404
    
    route_plans_list = []

    for route in route_plans:
        # Fetch associated user details using staff_no
        merchandiser = User.query.filter_by(staff_no=route.staff_no).first()
        if merchandiser:
            # Append route plan details along with merchandiser details to the list
            route_plans_list.append({
                'merchandiser_id': route.merchandiser_id,
                'manager_id': route.manager_id,
                'date_range': route.date_range,
                'instructions': route.instructions,
                'status': route.status,
                "id": route.id,
                'merchandiser_details': {'id': merchandiser.id,'first_name': merchandiser.first_name,'last_name': merchandiser.last_name,'email': merchandiser.email,'avatar': merchandiser.avatar}
            })

    return jsonify({'message': route_plans_list,"successful": True,"status_code": 200}), 200


@app.route("/users/route-plans/<int:merchandiser_id>", methods=["GET"])
@jwt_required()
def get_merchandiser_route_plans(merchandiser_id):

    route_plans = RoutePlan.query.filter_by(merchandiser_id=merchandiser_id).all()

    if not route_plans:
        return jsonify({'message': 'You have not been assigned any routes', "successful": False, "status_code": 404}), 404
    
    route_plans_list = []

    for route in route_plans:
        route_plans_list.append({'merchandiser_id': route.merchandiser_id, 'manager_id': route.manager_id, 'date_range': route.date_range, 'instructions': route.instructions, 'status': route.status, "id": route.id})
    return jsonify({'message': route_plans_list,"successful": True,"status_code": 200}), 200


@app.route("/users/manager-routes/<int:id>", methods=["GET"])
@jwt_required()
def get_manager_routes(id):
    current_date = datetime.now()
    start_of_month = current_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if start_of_month.month == 12:
        start_of_next_month = start_of_month.replace(year=start_of_month.year + 1, month=1)
    else:
        start_of_next_month = start_of_month.replace(month=start_of_month.month + 1)

    routes = RoutePlan.query.filter_by(manager_id=id).all()

    routes_list = []
    for route in routes:
        start_date = datetime.strptime(route.date_range['start_date'], '%Y-%m-%d')

        if start_of_month <= start_date < start_of_next_month:
            merchandiser = User.query.filter_by(id=route.merchandiser_id).first()
            if merchandiser:
                merchandiser_name = f"{merchandiser.first_name} {merchandiser.last_name}"
                staff_no = merchandiser.staff_no
            else:
                merchandiser_name = None
                staff_no = None

            routes_list.append({
                "id": route.id,
                "instructions": route.instructions,
                "manager_id": route.manager_id,
                "date_range": route.date_range,
                "merchandiser_name": merchandiser_name,
                "staff_no": staff_no,
                "status": route.status
            })

    if not routes_list:
        return jsonify({'message': 'You have no route plans found for this month', "successful": False, "status_code": 404}), 404

    return jsonify({"successful": True, "status_code": 200, "message": routes_list}), 200


@app.route("/users/delete-route-plans/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_route_plans(id):
    route = RoutePlan.query.filter_by(id=id).first()

    if not route:
        return jsonify({'message': 'No route plans found',"successful": False,"status_code": 404}), 404
    
    try:
        db.session.delete(route)
        db.session.commit()
        return jsonify({'message': 'Route deleted successfully', "successful": True, "status_code": 204}), 204

    except Exception as err:
        db.session.rollback()
        return jsonify({'message': f'There was an error deleting the route {err}',"successful": False, "status_code": 500}), 500
    

@app.route("/users/modify-route/<int:id>", methods=["PUT"])
@jwt_required()
def modify_route(id):
    route = RoutePlan.query.filter_by(id=id).first()

    if not route:
        return jsonify({'message': 'Route plan does not exist', "successful": False, "status_code": 404}), 404

    data = request.get_json()
    
    # Ensure required fields are in the request data
    if 'start' not in data or 'end' not in data or 'instruction_id' not in data:
        return jsonify({'message': 'Missing required fields: start, end, instruction_id', "successful": False, "status_code": 400}), 400

    start = data['start']
    end = data['end']
    instruction_id = data['instruction_id']

    try:
        # Parse the existing instructions JSON
        existing_instructions = json.loads(route.instructions)

        # Find the specific instruction by instruction_id and update start and end times
        instruction_found = False
        for instruction in existing_instructions:
            if instruction['id'] == instruction_id:
                instruction['start'] = start
                instruction['end'] = end
                instruction_found = True
                break

        if not instruction_found:
            return jsonify({'message': 'Instruction ID not found', "successful": False, "status_code": 404}), 404

        # Update the route plan's instructions with the modified instructions
        route.instructions = json.dumps(existing_instructions)

        # Commit the changes to the database
        db.session.commit()
        return jsonify({'message': 'Route plan updated successfully', "successful": True, "status_code": 200}), 200

    except Exception as err:
        db.session.rollback()
        return jsonify({'message': f'Error processing instructions: {err}', "successful": False, "status_code": 400}), 400

@app.route("/users/merchandisers/routes/<int:id>", methods=["GET"])
@jwt_required()
def get_merchandiser_routes(id):
    routes = RoutePlan.query.filter_by(merchandiser_id=id).all()

    if not routes:
        return jsonify({'message': 'No route plans found', "successful": False, "status_code": 404}), 404

    # Current month date range
    current_date = datetime.now(timezone.utc)
    first_day_of_month = current_date.replace(day=1)
    next_month = first_day_of_month + timedelta(days=32)
    last_day_of_month = next_month.replace(day=1) - timedelta(days=1)

    filtered_routes = []
    
    for route in routes:
        start_date_dt = datetime.fromisoformat(route.date_range['start_date']).replace(tzinfo=timezone.utc)
        end_date_dt = datetime.fromisoformat(route.date_range['end_date']).replace(tzinfo=timezone.utc)
        
        # Check if route's date range overlaps with the current month
        if not (first_day_of_month <= end_date_dt and start_date_dt <= last_day_of_month):
            continue
        
        manager = User.query.get(route.manager_id)
        manager_name = f"{manager.first_name} {manager.last_name}" if manager else "Unknown"

        instructions = json.loads(route.instructions)
        for instruction in instructions:
            facility_id = instruction.get('facility')
            facility = Facility.query.get(facility_id)
            if facility:
                instruction['facility_name'] = facility.name
            else:
                instruction['facility_name'] = "Unknown"

        filtered_routes.append({
            'id': route.id,
            'merchandiser_id': route.merchandiser_id,
            'manager_id': route.manager_id,
            'manager_name': manager_name,
            'date_range': route.date_range,
            'instructions': instructions,
            'status': route.status
        })

    return jsonify({"successful": True, "status_code": 200, 'message': filtered_routes}), 200

@app.route('/users/route-plans', methods=['GET', 'POST'])
@jwt_required()
def route_plan_details():
    if request.method == 'GET':
        route_plans = RoutePlan.query.all()
        if not route_plans:
            return jsonify({'message': 'No route plans found', "successful": False, "status_code": 404}), 404

        route_plan_list = []
        for route_plan in route_plans:
            route_plan_info = {
                'id': route_plan.id,
                'merchandiser_id': route_plan.merchandiser_id,
                'manager_id': route_plan.manager_id,
                'date_range': route_plan.date_range,
                'instructions': route_plan.instructions,
                'status': route_plan.status
            }
            route_plan_list.append(route_plan_info)


        return jsonify({"successful": True, "status_code": 200, 'message': route_plan_list}), 200

    elif request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid request", "successful": False, "status_code": 400}), 400

        manager_id = data.get('manager_id')
        date_range = data.get('date_range')
        instructions = data.get('instructions')
        status = data.get('status')
        staff_no = data.get("staff_no")

        instructions_json = json.dumps(instructions)

        # Check for required fields
        if not all([staff_no, manager_id, date_range, status]):
            return jsonify({'message': 'Missing required fields', "successful": False, "status_code": 400}), 400

        try:
            staff_no = int(staff_no)
            manager_id = int(manager_id)
        except ValueError:
            return jsonify({'message': 'Staff number and Manager ID must be integers', "successful": False, "status_code": 400}), 400

        if not isinstance(date_range, dict):
            return jsonify({'message': 'Date range must be a dictionary', "successful": False, "status_code": 400}), 400

        start_date = date_range.get('start_date')
        end_date = date_range.get('end_date')

        if not all([start_date, end_date]):
            return jsonify({'message': 'Missing start_date or end_date in date_range', "successful": False, "status_code": 400}), 400

        if status not in ['complete', 'pending']:
            return jsonify({'message': 'Status must be either "complete" or "pending"', "successful": False, "status_code": 400}), 400

        user = User.query.filter_by(staff_no=staff_no, role='merchandiser').first()
        if not user:
            return jsonify({'message': 'Invalid staff number or user is not a merchandiser', "successful": False, "status_code": 400}), 400

        # Check if the date_range falls within the current month
        current_date = datetime.now(timezone.utc).date()
        first_day_of_month = current_date.replace(day=1)
        last_day_of_month = (first_day_of_month + timedelta(days=32)).replace(day=1) - timedelta(days=1)

        start_date_dt = datetime.fromisoformat(start_date).date()
        end_date_dt = datetime.fromisoformat(end_date).date()
        
        if not (first_day_of_month <= start_date_dt <= last_day_of_month) or not (first_day_of_month <= end_date_dt <= last_day_of_month):
            return jsonify({'message': 'Assignments can only be made for the current month', "successful": False, "status_code": 400}), 400

        existing_plans = RoutePlan.query.filter_by(merchandiser_id=user.id).all()
        for plan in existing_plans:
            plan_start_date = datetime.fromisoformat(plan.date_range['start_date']).date()
            plan_end_date = datetime.fromisoformat(plan.date_range['end_date']).date()
            if (plan_start_date.month == current_date.month and plan_end_date.month == current_date.month):
                plan_instructions = json.loads(plan.instructions)
                for new_instruction in instructions:
                    new_instruction_start = datetime.fromisoformat(new_instruction['start']).replace(tzinfo=timezone.utc)
                    new_instruction_end = datetime.fromisoformat(new_instruction['end']).replace(tzinfo=timezone.utc)
                    for existing_instruction in plan_instructions:
                        existing_instruction_start = datetime.fromisoformat(existing_instruction['start']).replace(tzinfo=timezone.utc)
                        existing_instruction_end = datetime.fromisoformat(existing_instruction['end']).replace(tzinfo=timezone.utc)
                        if (new_instruction_start.date() == existing_instruction_start.date() and
                            (new_instruction_start <= existing_instruction_end and new_instruction_end >= existing_instruction_start)):
                            return jsonify({'message': f'{user.first_name} {user.last_name} already has another assignment on {new_instruction_start.date()}', "successful": False, "status_code": 400}), 400

        new_route_plan = RoutePlan(
            merchandiser_id=user.id,
            manager_id=manager_id,
            date_range=date_range,
            instructions=instructions_json,
            status=status
        )

        try:
            db.session.add(new_route_plan)
            db.session.commit()
            user_id = get_jwt_identity()
            return jsonify({'message': 'Route plan created successfully', "successful": True, "status_code": 201}), 201

        except Exception as err:
            db.session.rollback()
            return jsonify({'message': f"Internal server error. Error: {err}", "successful": False, "status_code": 500}), 500


@app.route("/users/change-route-status/<int:id>", methods=["PUT"])
@jwt_required()
def change_route_status(id):
    data = request.get_json()

    if not data:
        return jsonify({'message': 'Invalid request: Empty data', "successful": False, "status_code": 400}), 400

    instruction_id = data.get("instruction_id")
    status = data.get("status").lower() if data.get("status") else None

    if not instruction_id or not status:
        return jsonify({'message': 'Missing required fields', "successful": False, "status_code": 400}), 400

    if status not in ["pending", "complete"]:
        return jsonify({ 'message': 'Status must either be "complete" or "pending"', "successful": False, "status_code": 400}), 400

    route_plan = RoutePlan.query.filter_by(id=id).first()

    if not route_plan:
        return jsonify({'message': 'Route plan not found', "successful": False, "status_code": 404}), 404

    try:
        instructions = json.loads(route_plan.instructions)
    except json.JSONDecodeError:
        return jsonify({'message': 'Error decoding instructions JSON',"successful": False, "status_code": 500}), 500

    instruction_found = False

    for instruction in instructions:
        if instruction.get("id") == instruction_id:
            instruction["status"] = status
            instruction_found = True
            break

    if not instruction_found:
        return jsonify({'message': 'Instruction not found', "successful": False, "status_code": 404}), 404

    route_plan.instructions = json.dumps(instructions)

    try:
        db.session.commit()
        return jsonify({ 'message': 'Route plan status updated successfully', "successful": True, "status_code": 201}), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error saving changes to the database', "successful": False, "status_code": 500}), 500

    
@app.route('/users/route-plans/<int:route_plan_id>', methods=['PUT'])
@jwt_required()
def update_route_plan(route_plan_id):

    data = request.get_json()

    route_plan = db.session.get(RoutePlan, route_plan_id)

    if not route_plan:
        return jsonify({'message': 'Route plan not found',"successful": False,"status_code": 404}), 404
    
    # Check if data adheres to model specifications
    if 'merchandiser_id' in data:
        if not isinstance(data['merchandiser_id'], int) or not isinstance(data["manager_id"], int):
            return jsonify({'message': 'Merchandiser and manager IDs must be an integer', "successful": False, "status_code": 400}), 400

    if 'date_range' in data:
        # Attempt to parse the date range string
        try:
            start_date = datetime.strptime(data['date_range']['start_date'], '%d/%m/%Y %I:%M %p')
            end_date = datetime.strptime(data['date_range']['end_date'], '%d/%m/%Y %I:%M %p')
            # Assign the parsed dates to the route plan
            route_plan.start_date = start_date
            route_plan.end_date = end_date
        except ValueError:
            return jsonify({'message': 'Invalid date format. Please provide dates in the format: "dd/mm/yyyy hh:mm am/pm"', "successful": False, "status_code": 400}), 400

    if 'instructions' in data:
        if not isinstance(data['instructions'], str):
            return jsonify({'message': 'Instructions must be a string', "successful": False, "status_code": 400}), 400

    if 'status' in data:
        if data['status'] not in ['complete', 'pending']:
            return jsonify({ 'message': 'Status must be either "complete" or "pending"', "successful": False, "status_code": 400}), 400
    # Update route plan attributes
    route_plan.merchandiser_id = data.get('merchandiser_id', route_plan.merchandiser_id)
    route_plan.manager_id = data.get('manager_id', route_plan.manager_id)
    route_plan.instructions = data.get('instructions', route_plan.instructions)
    route_plan.status = data.get('status', route_plan.status)
    route_plan.date_range= data.get('date_range', route_plan.date_range)

    try:
        db.session.commit()

        return jsonify({'message': 'Route plan updated successfully', "successful": True, "status_code": 201}), 201

    except Exception as err:
        db.session.rollback()
        return jsonify({'message': f"Internal server error. Error: {err}", "successful": False, "status_code": 500 }), 500


@app.route('/users/locations', methods=['GET', 'POST'])
@jwt_required()
def location_details():
    if request.method == 'GET':
        # locations = Location.query.all()

        # Group locations by merchandiser_id and select the latest timestamp for each group
        latest_locations_subquery = db.session.query(Location.merchandiser_id,
                                                      func.max(Location.timestamp).label('latest_timestamp'))\
                                               .group_by(Location.merchandiser_id)\
                                               .subquery()

        # Join the subquery with the Location table to get the latest location details for each merchandiser
        latest_locations_query = db.session.query(Location)\
                                           .join(latest_locations_subquery,
                                                 and_(Location.merchandiser_id == latest_locations_subquery.c.merchandiser_id,
                                                      Location.timestamp == latest_locations_subquery.c.latest_timestamp))\
                                           .all()

        if not latest_locations_query:
            return jsonify({ 'message': 'No locations found', "successful": False,"status_code": 404}), 404

        location_list = []
        for location in latest_locations_query:
            location_info = {'id': location.id,'merchandiser_id': location.merchandiser_id,'timestamp': location.timestamp.strftime('%Y-%m-%d %H:%M:%S'),'latitude': location.latitude,'longitude': location.longitude}
            location_list.append(location_info)

        return jsonify({"successful": True, "status_code": 200, 'message': location_list}), 200
    
    elif request.method == 'POST':

        data = request.get_json()

        # Extract required fields from the JSON data
        merchandiser_id = data.get('merchandiser_id')
        latitude = data.get('latitude')
        longitude = data.get('longitude')

        # Check for required fields
        if not all([merchandiser_id, latitude, longitude]):
            return jsonify({'message': 'Missing required fields', "successful": False, "status_code": 400}), 400
        
        # Check data types and range
        try:
            merchandiser_id = int(merchandiser_id)
            latitude = float(latitude)
            longitude = float(longitude)

        except ValueError:
            return jsonify({'message': 'Merchandiser ID must be an integer, and latitude and longitude must be in decimals',"successful": False, "status_code": 400}), 400

        # Check latitude and longitude range
        if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
            return jsonify({'message': 'Invalid latitude or longitude values',"successful": False,"status_code": 400}), 400

        # Create a new location object
        new_location = Location(merchandiser_id=merchandiser_id, timestamp=datetime.now(timezone.utc),  latitude=latitude, longitude=longitude)

        try:
            db.session.add(new_location)
            db.session.commit()


            return jsonify({'message': 'Location created successfully',"successful": True,"status_code": 201}), 201
        
        except Exception as err:
            db.session.rollback()
            return jsonify({ 'message': f"Internal server error. Error: {err}", "successful": False, "status_code": 500}), 500
   

@app.route("/users/login", methods=["POST"])
def login_user():
    data = request.get_json()

    if not data:
        return jsonify({"message": "Invalid request", "successful": False, "status_code": 400}), 400
    
    email = data.get("email").lower() if data.get('email') else None
    password = data.get("password")
    
    if not email or not password:
        return jsonify({"message": "Email and password required", "successful": False, "status_code": 400}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if user:

        if user.status == "blocked":
            
            return jsonify({"message": "Access denied, please contact system administrator", "successful": False, "status_code": 409}), 409
        
        if bcrypt.check_password_hash(user.password, password):

            if datetime.now(timezone.utc) - user.last_password_change.replace(tzinfo=timezone.utc) > timedelta(days=14):
                
                return jsonify({"message": "Your password has expired", "successful": False,"status_code": 403}), 403
            
            user_data = {"user_id": user.id, "role": user.role, "username": user.username, "email": user.email, "last_name": user.last_name, "avatar": user.avatar, "last_login": datetime.now(timezone.utc).isoformat()}
            
            access_token = create_access_token(identity=user_data)
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()

            return jsonify({"successful": True, "status_code": 201, "access_token": access_token, "message": user_data}), 201
        
        else:
            return jsonify({"message": "Invalid credentials", "successful": False, "status_code": 401}), 401
    else:
        return jsonify({"message": "You do not have an account, please signup.", "successful": False, "status_code": 404}), 404
    

@app.route("/users/change-password", methods=["PUT"])
def change_password():
    
    data = request.get_json()

    if not data:
        return jsonify({"message": "Invalid request", "successful": False, "status_code": 400}), 400
    
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    email = data.get("email") 

    if not old_password or not new_password or not email:
        return jsonify({"message": "Missing required fields", "successful": False, "status_code": 400}), 400
    
    if old_password == new_password:
        return jsonify({"message": "Old password and new password cannot be the same", "successful": False, "status_code": 400}), 400

    if not isinstance(new_password, str) or len(new_password) < 6:
      
        return jsonify({ 'message': 'Password must be a string and at least 6 characters long', "successful": False, "status_code": 400}), 400

    user = User.query.filter_by(email=email).first()
    

    if user:

        user_id = user.id

        if bcrypt.check_password_hash(user.password, old_password):

            hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            user.password = hashed_new_password
            user.last_password_change = datetime.now(timezone.utc)

            try:
                db.session.commit()
                user_id = user_id
                return jsonify({"message": "Password changed successfully", "successful": True, "status_code": 201}), 201
            except Exception as err:
                db.session.rollback()
                return jsonify({"message": f"Failed to change signature. Error{err}", "successful": False, "status_code": 500}), 500
          
        else:
            return jsonify({"message": "Invalid old password", "successful": False, "status_code": 401}), 401
    else:
        return jsonify({ "message": "User not found", "successful": False,"status_code": 404}), 404


@app.route("/users/<int:user_id>/edit-status", methods=["PUT"])
@jwt_required()
def edit_status(user_id):
    data = request.get_json()

    if not data:
        return jsonify({ "message": "Invalid request", "successful": False, "status_code": 400}), 400

    new_status = data.get("status")

    if not new_status:
        return jsonify({"message": "Missing required fields","successful": False, "status_code": 400}), 400

    if new_status not in ["active", "blocked"]:
        return jsonify({"message": "Invalid status value","successful": False, "status_code": 400}), 400

    user = User.query.get(user_id)

    if user:
        user.status = new_status

        try:
            db.session.commit()
            return jsonify({"message": "Status updated successfully", "successful": True, "status_code": 200}), 200
        except Exception as err:
            db.session.rollback()
            return jsonify({"message": f"Failed to update status. Error: {err}", "successful": False, "status_code": 500}), 500
    else:
        return jsonify({"message": "User not found", "successful": False, "status_code": 404}), 404


@app.route("/users/<int:user_id>/edit-role", methods=["PUT"])
@jwt_required()
def edit_role(user_id):
    data = request.get_json()

    if not data:
        return jsonify({"message": "Invalid request", "successful": False, "status_code": 400}), 400

    new_role = data.get("role")

    if not new_role:
        return jsonify({"message": "Missing required fields", "successful": False, "status_code": 400}), 400

    if new_role not in ["admin", "merchandiser", "manager"]:
        return jsonify({"message": "Invalid role value", "successful": False, "status_code": 400}), 400

    user = User.query.get(user_id)

    if user:
        user.role = new_role

        try:
            db.session.commit()
            return jsonify({"message": "Role updated successfully", "successful": True, "status_code": 200}), 200
        except Exception as err:
            db.session.rollback()
            return jsonify({"message": f"Failed to update role. Error: {err}", "successful": False, "status_code": 500}), 500
    else:
        return jsonify({"message": "User not found", "successful": False, "status_code": 404}), 404

    
@app.route("/users/<int:user_id>/update", methods=["PUT"])
def update_user(user_id):
    data = request.get_json()

    if not data:
        return jsonify({ "message": "Invalid request", "successful": False, "status_code": 400}), 400

    # Extract fields from the request
    new_password = data.get("new_password")

    if not new_password:
        return jsonify({ "message": "New password is required", "successful": False, "status_code": 400}), 400

    # Check if the user exists
    user = User.query.get(user_id)
    if not user:
        return jsonify({ "message": "User not found", "successful": False, "status_code": 404}), 404

    # Update the password
    hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_new_password

    try:
        db.session.commit()
        return jsonify({"message": "Password updated successfully", "successful": True, "status_code": 200}), 200
    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to update password. Error: {err}", "successful": False, "status_code": 500}), 500


@app.route("/users/get-facilities/<int:manager_id>", methods=[ "GET"])
@jwt_required()
def get_facilities(manager_id):
    facilities = Facility.query.filter_by(manager_id=manager_id).all()

    if not facilities:
        return jsonify({"message": "There are no facilities", "status_code": 404, "successful": False}), 404

    facilities_data = []

    for facility in facilities:
        facilities_data.append({
            "id": facility.id,
            "name": facility.name,
            "location": facility.location,
            "type": facility.type
        })
    return jsonify({"message": facilities_data, "successful": True, "status_code": 200 }), 200


@app.route("/users/get/facilities", methods=["GET"])
@jwt_required()
def get_all_facilities():
    facilities = Facility.query.all()

    facilities_list =[]
    for facility in facilities:
        facilities_list.append({
            "id": facility.id,
            "name": facility.name,
            "location": facility.location,
            "type": facility.type,
            "manager_id": facility.manager_id
        })

    return jsonify({ "message": facilities_list, "status_code": 200, "successful": True}), 200 


@app.route("/users/create/facility", methods=["POST"])
@jwt_required()
def create_facility():
    data = request.get_json()

    if not data:
        return jsonify({ "message": "There are no facilities", "status_code": 400, "successful": False}), 400
    
    name = data.get("name")
    location = data.get("location")
    type_ = data.get("type")
    manager_id = data.get("manager_id")

    if not name or not location or not type_ or not manager_id:
        return jsonify({"message": "Missing required fields", "status_code": 400, "successful": False}), 400
    
    if not all(isinstance(item, str) for item in [name, location, type_]):
        return jsonify({ "message": "Fields 'name', 'location', and 'type' must be strings", "status_code": 400, "successful": False}), 400
    
    new_facility = Facility(name=name, location=location, type=type_, manager_id=manager_id)

    try:
        db.session.add(new_facility)
        db.session.commit()
        return jsonify({"message": "Facility created successfully", "status_code": 201, "successful": True}), 201
    except Exception as err:
        db.session.rollback()
        return jsonify({ "message": f"Failed to create facility: Error:  {err}", "status_code": 500, "successful": False}), 500


@app.route('/images/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route("/users/get-responses/<int:manager_id>", methods=["GET"])
@jwt_required()
def get_responses(manager_id):
    try:
        responses = db.session.query(Response).join(User, Response.merchandiser_id == User.id) \
            .filter(Response.manager_id == manager_id, Response.status == "pending") \
            .options(joinedload(Response.merchandiser)).all()

        if not responses:
            return jsonify({"message": "There are no responses yet.", "status_code": 404, "successful": False}), 404

        responses_list = []

        for response in responses:
            formatted_response = {
                "id": response.id,
                "merchandiser_id": response.merchandiser_id,
                "merchandiser": f"{response.merchandiser.first_name} {response.merchandiser.last_name}",
                "manager_id": response.manager_id,
                "route_plan_id": response.route_plan_id,
                "instruction_id": response.instruction_id,
                "date_time": response.date_time.strftime("%a, %d %b %Y %H:%M:%S GMT"),
                "status": response.status,
                "response": {}
            }

            # Process response data including images
            for key, value in response.response.items():
                formatted_response["response"][key] = {
                    "text": value.get("text", ""),
                    "image": ""
                }
                if value.get("image"):
                    formatted_response["response"][key]["image"] = f"{request.url_root}images/{value['image']}"

            responses_list.append(formatted_response)

        return jsonify({"message": responses_list, "status_code": 200, "successful": True}), 200

    except Exception as e:
        return jsonify({"message": f"Failed to retrieve responses: {str(e)}", "status_code": 500, "successful": False}), 500


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/users/post/response", methods=["POST"])
@jwt_required()
def create_response():
    try:
        # Extract data from request
        merchandiser_id = request.form.get("merchandiser_id")
        manager_id = request.form.get("manager_id")
        route_plan_id = request.form.get("route_plan_id")
        instruction_id = request.form.get("instruction_id")
        date_time = request.form.get("date_time")
        status = request.form.get("status").lower()
        responses = {}

        # Validate required fields
        if not all([merchandiser_id, manager_id, route_plan_id, instruction_id, date_time, status]):
            return jsonify({"message": "Missing required fields.", "status_code": 400, "successful": False}), 400

        # Ensure status is 'pending'
        if status != "pending":
            return jsonify({"message": "Status must be 'pending'", "status_code": 400, "successful": False}), 400

        # Convert IDs to integers
        try:
            merchandiser_id = int(merchandiser_id)
            manager_id = int(manager_id)
            route_plan_id = int(route_plan_id)
        except ValueError:
            return jsonify({"message": "ID fields must be integers.", "status_code": 400, "successful": False}), 400

        # Parse date_time string into datetime object
        date_time = datetime.strptime(date_time, "%Y-%m-%d").date()

        # Process response data
        for key in request.form.keys():
            if key.startswith('response['):
                category = key.split('[')[1].split(']')[0]  # Extract category name
                field_type = key.split('[')[2].split(']')[0]  # Extract 'text' or 'image'

                if category not in responses:
                    responses[category] = {
                        "text": "",
                        "image": ""
                    }

                if field_type == 'text':
                    # Handle text data
                    responses[category]['text'] = request.form[key]

        for key in request.files.keys():
            if key.startswith('response['):
                category = key.split('[')[1].split(']')[0]  # Extract category name
                field_type = key.split('[')[2].split(']')[0]  # Extract 'text' or 'image'

                if field_type == 'image':
                    # Handle image file upload
                    file = request.files[key]
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)
                        responses[category]['image'] = filename

        # Retrieve the route plan and update the instruction status
        route_plan = RoutePlan.query.filter_by(id=route_plan_id).first()
        if not route_plan:
            return jsonify({"message": "Route plan not found.", "status_code": 404, "successful": False}), 404

        instructions = json.loads(route_plan.instructions)
        instruction_found = False

        for instruction in instructions:
            if instruction['id'] == instruction_id:
                instruction['status'] = 'submitted'
                instruction_found = True
                break

        if not instruction_found:
            return jsonify({"message": "Instruction not found.", "status_code": 404, "successful": False}), 404

        # Persist the updated instructions
        route_plan.instructions = json.dumps(instructions)
        db.session.commit()

        # Create new Response object
        new_response = Response(
            merchandiser_id=merchandiser_id,
            manager_id=manager_id,
            route_plan_id=route_plan_id,
            instruction_id=instruction_id,
            response=responses,
            date_time=date_time,
            status=status
        )
        db.session.add(new_response)
        db.session.commit()

        return jsonify({"message": "Response stored successfully.", "status_code": 201, "successful": True}), 201

    except Exception as e:
        return jsonify({"message": f"Failed to store response: {str(e)}", "status_code": 500, "successful": False}), 500


@app.route("/users/delete/responses/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_responses(id):
    response = Response.query.filter_by(id=id).first()

    if response:
        try:
            db.session.delete(response)
            db.session.commit()
            return jsonify({"message": "Response deleted successfully", "status_code": 204, "successful": True}), 204
        except Exception as err:
            db.session.rollback()
            return jsonify({"message": f"Failed to delete response: {err}", "status_code": 500, "successful": False}), 500
    else:
        return jsonify({"message": "Response not found", "status_code": 404, "successful": False}), 404


@app.route("/users/reject/response/<int:id>", methods=["PUT"])
@jwt_required()
def reject_response(id):
    data = request.get_json()
    route_plan_id = data.get("route_plan_id")
    instruction_id = data.get("instruction_id")
    manager_id = data.get("manager_id")
    merchandiser_id = data.get("merchandiser_id")
    message = data.get("message")

    if not all([route_plan_id, instruction_id, manager_id, merchandiser_id]):
        return jsonify({"message": "Missing required fields", "successful": False, "status_code": 400}), 400
    
    try:
        route_plan = RoutePlan.query.filter_by(id=route_plan_id).first()
        if not route_plan:
            return jsonify({"message": "Route plan not found.", "status_code": 404, "successful": False}), 404

        instructions = json.loads(route_plan.instructions)
        instruction_found = False

        for instruction in instructions:
            if instruction['id'] == instruction_id:
                instruction['status'] = 'pending'
                instruction_found = True
                break

        if not instruction_found:
            return jsonify({"message": "Instruction not found.", "status_code": 404, "successful": False}), 404

        # Persist the updated instructions
        route_plan.instructions = json.dumps(instructions)
        db.session.commit()

        response = Response.query.filter_by(id=id).first()
        if not response:
            return jsonify({"message": "Response not found.", "successful": False, "status_code": 400}), 400
        
        response.status = "rejected"
        db.session.commit()

        if not isinstance(message, str):
            return jsonify({"message": "Message must be a string", "successful": False, "status_code": 400}), 400
        
        new_notification = Message(
            manager_id=manager_id,
            merchandiser_id=merchandiser_id,
            message=message,
            status='unread'  
        )

        db.session.add(new_notification)
        db.session.commit()

        return jsonify({"message": "Response rejected and notification sent successfully.", "successful": True, "status_code": 200}), 200

    except Exception as e:
        db.session.rollback()  
        return jsonify({"message": f"An error occurred: {str(e)}", "successful": False, "status_code": 500}), 500


@app.route("/users/assign/merchandiser", methods=["POST"])
@jwt_required()
def assign_merchandiser():
    data = request.get_json()

    if not data:
        return jsonify({"message": "Invalid data: You did not provide any data.", "status_code": 400, "successful": False}), 400
    
    manager_id = data.get("manager_id")
    merchandiser_ids = data.get("merchandiser_id")
    date_time_str = data.get("date_time")

    if not all([manager_id, merchandiser_ids, date_time_str]):
        return jsonify({"message": "Missing required fields.", "status_code": 400, "successful": False}), 400

    try:
        date_time = datetime.strptime(date_time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return jsonify({"message": "Invalid date format. Please provide a valid datetime in the format 'YYYY-MM-DD HH:MM:SS'.", "status_code": 400, "successful": False}), 400

    # Check for existing assignments for the given month and year
    existing_assignments = AssignedMerchandiser.query.filter(
        extract('year', AssignedMerchandiser.date_time) == date_time.year,
        extract('month', AssignedMerchandiser.date_time) == date_time.month
    ).all()

    # Iterate through existing assignments and check for conflicts
    for assignment in existing_assignments:
        for merchandiser_id in merchandiser_ids:
            if str(merchandiser_id) in assignment.merchandisers_id:
                merchandiser = User.query.filter_by(id=merchandiser_id).first()
                if merchandiser:
                    return jsonify({
                        "message": f"The merchandiser {merchandiser.first_name} {merchandiser.last_name} is already assigned to another manager for the specified month.",
                        "status_code": 400,
                        "successful": False
                    }), 400

    # Add new assignments
    new_assignments = AssignedMerchandiser(
        manager_id=manager_id,
        merchandisers_id=json.dumps(merchandiser_ids),
        date_time=date_time
    )
    
    try:
        db.session.add(new_assignments)
        db.session.commit()
        return jsonify({"message": "Merchandisers assigned successfully.", "status_code": 201, "successful": True}), 201
    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to assign merchandisers: Error: {err}", "status_code": 500, "successful": False}), 500


@app.route("/users/get/merchandisers/<int:manager_id>", methods=["GET"])
@jwt_required()
def get_manager_merchandisers(manager_id):
    current_year = datetime.now().year
    current_month = datetime.now().month  # Get the numeric month

    assigned_merchandisers = AssignedMerchandiser.query.filter(
        AssignedMerchandiser.manager_id == manager_id,
        extract('month', AssignedMerchandiser.date_time) == current_month,
        extract('year', AssignedMerchandiser.date_time) == current_year
    ).all()

    if not assigned_merchandisers:
        return jsonify({"message": f"No merchandisers assigned for you for the month of {datetime.now().strftime('%B')} {current_year}.", "status_code": 404, "successful": False}), 404
    
    assigned_merchandisers_list = []

    for assignment in assigned_merchandisers:
        merchandisers_ids = json.loads(assignment.merchandisers_id)

        for merchandiser_id in merchandisers_ids:
            try:
                merchandiser_id_int = int(merchandiser_id)
                merchandiser_data = User.query.filter_by(id=merchandiser_id_int).first()

                if merchandiser_data:
                    assigned_merchandisers_list.append({
                        "assignment_id": assignment.id,
                        "merchandiser_id": merchandiser_data.id,
                        "staff_no": merchandiser_data.staff_no,
                        "merchandiser_name": f"{merchandiser_data.first_name} {merchandiser_data.last_name}",
                        "manager_id": assignment.manager_id,
                        "month": datetime.now().strftime('%B'),  
                        "year": current_year,
                    })
            except ValueError:
                # Handle cases where merchandiser_id cannot be converted to int (e.g., invalid format)
                pass

    return jsonify({"message": assigned_merchandisers_list, "status_code": 200, "successful": True}), 200


def merchandiser_performance(merchandiser_id, new_scores):
    current_datetime = datetime.now()
    start_of_day = current_datetime.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Fetch the performance entry for today
    performance_entry = MerchandiserPerformance.query.filter_by(merchandiser_id=merchandiser_id, date_time=start_of_day).first()
    
    # If no performance entry exists for today, create one
    if not performance_entry:
        performance_entry = MerchandiserPerformance(
            merchandiser_id=merchandiser_id,
            date_time=start_of_day,
            day=start_of_day.strftime('%A'),
            performance={}
        )
        db.session.add(performance_entry)
        db.session.commit()  

    # Ensure current performance is a dictionary
    current_performance = performance_entry.performance or {}

    # Update performance metrics
    for metric, new_score in new_scores.items():
        if metric in current_performance:
            current_value = current_performance[metric]
            updated_value = (current_value + new_score) / 2
        else:
            updated_value = new_score
        
        current_performance[metric] = updated_value
        performance_entry.performance = current_performance
        db.session.commit()

def compute_merch_scores(response):
    merchandiser_id = response['merchandiser_id']
    response_datetime = datetime.strptime(response['date_time'], '%Y-%m-%dT%H:%M:%S')

    # Retrieve all KPIs from the database
    kpis = KeyPerformaceIndicator.query.all()

    performance_dict = {}

    total_scores = []

    for kpi in kpis:
        kpi_metrics = kpi.performance_metric

        for metric, requirements in kpi_metrics.items():
            text_required = requirements.get('text', False)
            image_required = requirements.get('image', False)
            metric_response = response['response'].get(metric, {})

            text_score = 0
            image_score = 0

            if text_required:
                text = metric_response.get('text', "")
                if len(text) >= 500:
                    text_score = 1
                elif len(text) > 200:
                    text_score = 0.5

            if image_required and 'image' in metric_response and len(text) < 500:
                image_score = 0.5 

            total_score_metric = min(text_score + image_score, 1) * 100  # Convert to percentage
            total_scores.append(total_score_metric)
            performance_dict[metric] = total_score_metric

    # Calculate timeliness score
    route_plan_id = response['route_plan_id']
    route_plan = RoutePlan.query.filter_by(id=route_plan_id).first()
    timeliness_percentage = 0

    if route_plan:
        try:
            instructions = json.loads(route_plan.instructions)
            for instruction in instructions:
                if instruction.get('id') == response['instruction_id']:
                    instruction_start = datetime.strptime(instruction.get('start'), '%Y-%m-%dT%H:%M:%S')
                    if response_datetime.date() == instruction_start.date():
                        timeliness_percentage = 100
                    break
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON instructions: {e}")

    total_scores.append(timeliness_percentage)
    performance_dict['timeliness'] = timeliness_percentage

    # Calculate the average score of metrics and timeliness
    average_performance_score = sum(total_scores) / len(total_scores)
    weighted_performance_score = average_performance_score * 0.6

    # Calculate completeness score
    start_of_month = datetime(response_datetime.year, response_datetime.month, 1)
    end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(days=1)

    route_plans = RoutePlan.query.filter(RoutePlan.merchandiser_id == merchandiser_id,
                                         RoutePlan.date_range['start_date'].astext.cast(Date) >= start_of_month.date(),
                                         RoutePlan.date_range['end_date'].astext.cast(Date) <= end_of_month.date()).all()
    total_instructions = 0
    completed_instructions = 0

    for route_plan in route_plans:
        try:
            instructions = json.loads(route_plan.instructions)
            for instruction in instructions:
                total_instructions += 1
                if instruction.get('status').lower() == 'complete':
                    completed_instructions += 1
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON instructions: {e}")

    completeness_percentage = 0
    if total_instructions > 0:
        completeness_percentage = (completed_instructions / total_instructions) * 100

    weighted_completeness_score = completeness_percentage * 0.4
    performance_dict['completeness'] = completeness_percentage

    # Calculate total performance
    total_performance = weighted_performance_score + weighted_completeness_score
    performance_dict['total_performance'] = total_performance

    merchandiser_performance(merchandiser_id, performance_dict)

@app.route("/users/approve/response", methods=["PUT"])
@jwt_required()
def approve_response():
    data = request.get_json()

    if not data or 'response_id' not in data or 'instruction_id' not in data or 'route_plan_id' not in data:
        return jsonify({
            "message": "Invalid data: response_id, instruction_id, and route_plan_id are required.",
            "status_code": 400,
            "successful": False
        }), 400

    response_id = data.get("response_id")
    instruction_id = data.get("instruction_id")
    route_plan_id = data.get("route_plan_id")

    response_to_rate = Response.query.filter_by(id=response_id).first()
    if not response_to_rate:
        return jsonify({
            "message": "Response does not exist.",
            "status_code": 404,
            "successful": False
        }), 404

    route_plan = RoutePlan.query.filter_by(id=route_plan_id).first()
    if not route_plan:
        return jsonify({
            "message": "Route plan does not exist.",
            "status_code": 404,
            "successful": False
        }), 404

    # Parse and update the instruction status
    instructions = json.loads(route_plan.instructions)  # Ensure instructions are parsed as a list of dictionaries
    instruction_found = False

    for instruction in instructions:
        if instruction.get('id') == instruction_id:
            instruction['status'] = 'complete'
            instruction_found = True
            break

    if not instruction_found:
        return jsonify({
            "message": "Instruction does not exist.",
            "status_code": 404,
            "successful": False
        }), 404

    response = {
        "id": response_to_rate.id,
        "merchandiser_id": response_to_rate.merchandiser_id,
        "manager_id": response_to_rate.manager_id,
        "response": response_to_rate.response,
        "date_time": response_to_rate.date_time.strftime('%Y-%m-%dT%H:%M:%S'),
        "status": response_to_rate.status,
        "route_plan_id": route_plan_id,
        "instruction_id": instruction_id
    }
    
    response_to_rate.status = "Approved"

    try:
        # Commit the updated instructions back to the route plan
        route_plan.instructions = json.dumps(instructions)  # Ensure instructions are stored as a JSON string
        db.session.commit()

        compute_merch_scores(response)
        
        return jsonify({
            "message": "Response approved successfully.",
            "status_code": 201,
            "successful": True
        }), 201
    except SQLAlchemyError as err:
        db.session.rollback()
        return jsonify({
            "message": f"Failed to approve the response: Error: {err}",
            "status_code": 500,
            "successful": False
        }), 500


@app.route("/users/get/day/performance/<int:merch_id>", methods=["GET"])
@jwt_required()
def get_day_performance(merch_id):
    # Get the current date
    current_datetime = datetime.now()
    start_of_day = current_datetime.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = current_datetime.replace(hour=23, minute=59, second=59, microsecond=999999)

    # Query the performance for the given merchandiser and current day
    performance_entry = MerchandiserPerformance.query.filter_by(merchandiser_id=merch_id)\
                                                     .filter(MerchandiserPerformance.date_time >= start_of_day)\
                                                     .filter(MerchandiserPerformance.date_time <= end_of_day)\
                                                     .first()

    if performance_entry:
        performance_data = {
            "merchandiser_id": performance_entry.merchandiser_id,
            "date_time": performance_entry.date_time.strftime('%Y-%m-%dT%H:%M:%S'),
            "day": performance_entry.day,
            "performance": performance_entry.performance
        }
        return jsonify({"successful": True, "message": performance_data, "status_code": 200}), 200
    else:
        return jsonify({"successful": False, "message": "No performance data found for the given day", "status_code": 404}), 404


@app.route("/users/get/week/performance/<int:merch_id>", methods=["GET"])
@jwt_required()
def get_week_performance(merch_id):
    # Calculate the start of the week (Monday at midnight)
    current_datetime = datetime.now()
    start_of_week = current_datetime - timedelta(days=current_datetime.weekday())
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)

    # Query the performance data from the start of the week to now
    performance_entries = MerchandiserPerformance.query.filter_by(merchandiser_id=merch_id)\
                                                       .filter(MerchandiserPerformance.date_time >= start_of_week)\
                                                       .all()

    if not performance_entries:
        return jsonify({"successful": False, "message": "No performance data found for the given week", "status_code": 404}), 404

    # Initialize dictionaries to accumulate performance data and counts
    aggregated_performance = {}
    metric_counts = {}

    for entry in performance_entries:
        for metric, value in entry.performance.items():
            if metric not in aggregated_performance:
                aggregated_performance[metric] = 0
                metric_counts[metric] = 0
            aggregated_performance[metric] += value
            metric_counts[metric] += 1

    # Calculate the average for each performance metric
    averaged_performance = {metric: (total / metric_counts[metric]) for metric, total in aggregated_performance.items()}

    return jsonify({"successful": True, "message": averaged_performance, "status_code": 200}), 200


@app.route("/users/get/month/performance/<int:merch_id>", methods=["GET"])
@jwt_required()
def get_month_performance(merch_id):
    current_datetime = datetime.now()
    start_of_month = current_datetime.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    performance_entries = MerchandiserPerformance.query.filter_by(merchandiser_id=merch_id)\
                                                       .filter(MerchandiserPerformance.date_time >= start_of_month)\
                                                       .all()

    if not performance_entries:
        return jsonify({"successful": False, "message": "No performance data found for the given month", "status_code": 404}), 404

    aggregated_performance = {}
    metric_counts = {}

    for entry in performance_entries:
        for metric, value in entry.performance.items():
            if metric not in aggregated_performance:
                aggregated_performance[metric] = 0
                metric_counts[metric] = 0
            aggregated_performance[metric] += value
            metric_counts[metric] += 1

    averaged_performance = {metric: (total / metric_counts[metric]) for metric, total in aggregated_performance.items()}

    return jsonify({"successful": True, "message": averaged_performance, "status_code": 200}), 200


@app.route("/users/get/year/performance/<int:merch_id>", methods=["GET"])
@jwt_required()
def get_yearly_performance(merch_id):
    current_date = datetime.now()
    yearly_performance = {}

    for month_offset in range(12):  
        year = current_date.year if current_date.month > month_offset else current_date.year - 1
        month = (current_date.month - month_offset - 1) % 12 + 1

        start_of_month = datetime(year, month, 1)
        if month == 12:
            end_of_month = datetime(year + 1, 1, 1) - timedelta(days=1)
        else:
            end_of_month = datetime(year, month + 1, 1) - timedelta(days=1)

        performance_entries = MerchandiserPerformance.query.filter_by(merchandiser_id=merch_id)\
                                                           .filter(MerchandiserPerformance.date_time >= start_of_month)\
                                                           .filter(MerchandiserPerformance.date_time <= end_of_month)\
                                                           .all()

        total_performance_sum = sum(entry.performance['total_performance'] for entry in performance_entries)
        total_performance_avg = total_performance_sum / len(performance_entries) if performance_entries else 0

        if performance_entries:
            month_key = start_of_month.strftime("%B, %Y")

            yearly_performance[month_key] = {'total_performance': total_performance_avg}

    if yearly_performance:
        return jsonify({"successful": True, "message": yearly_performance, "status_code": 200}), 200
    else:
        return jsonify({"successful": False, "message": "No performance for this year", "status_code": 404}), 404


@app.route("/users/get/performance", methods=["GET"])
@jwt_required()
def get_performance_by_date():
    date_str = request.args.get('date')
    merch_id = request.args.get('merch_id')

    if not date_str or not merch_id:
        return jsonify({"successful": False, "message": "Date and merchandiser ID are required", "status_code": 400}), 400

    try:
        query_date = datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        return jsonify({"successful": False, "message": "Invalid date format. Use YYYY-MM-DD", "status_code": 400}), 400

    start_of_day = query_date.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = query_date.replace(hour=23, minute=59, second=59, microsecond=999999)

    performance_entry = MerchandiserPerformance.query.filter_by(merchandiser_id=merch_id)\
                                                     .filter(MerchandiserPerformance.date_time >= start_of_day)\
                                                     .filter(MerchandiserPerformance.date_time <= end_of_day)\
                                                     .first()

    if performance_entry:
        performance_data = {
            "merchandiser_id": performance_entry.merchandiser_id,
            "date_time": performance_entry.date_time.strftime('%Y-%m-%dT%H:%M:%S'),
            "day": performance_entry.day,
            "performance": performance_entry.performance
        }
        return jsonify({"successful": True, "message": performance_data, "status_code": 200}), 200
    else:
        return jsonify({"successful": False, "message": "No performance data found for the given date", "status_code": 404}), 404


@app.route("/users/get/monthly/performance", methods=["GET"])
@jwt_required()
def get_monthly_performance():
    month_str = request.args.get('month')
    year_str = request.args.get('year')
    merch_id = request.args.get('merch_id')

    if not month_str or not year_str or not merch_id:
        return jsonify({
            "successful": False, 
            "message": "Month, year, and merchandiser ID are required", 
            "status_code": 400
        }), 400

    try:
        month = int(month_str)
        year = int(year_str)
    except ValueError:
        return jsonify({"successful": False,  "message": "Invalid month or year format. Use MM and YYYY",  "status_code": 400}), 400

    start_of_month = datetime(year, month, 1, 0, 0, 0)
    if month == 12:
        end_of_month = datetime(year + 1, 1, 1, 0, 0, 0) - timedelta(seconds=1)
    else:
        end_of_month = datetime(year, month + 1, 1, 0, 0, 0) - timedelta(seconds=1)

    performance_entries = MerchandiserPerformance.query.filter_by(merchandiser_id=merch_id)\
                                                       .filter(MerchandiserPerformance.date_time >= start_of_month)\
                                                       .filter(MerchandiserPerformance.date_time <= end_of_month)\
                                                       .all()

    if not performance_entries:
        return jsonify({"successful": False,  "message": "No performance data found for the given month",  "status_code": 404}), 404

    aggregated_performance = {}
    metric_counts = {}

    for entry in performance_entries:
        for metric, value in entry.performance.items():
            if metric not in aggregated_performance:
                aggregated_performance[metric] = 0
                metric_counts[metric] = 0
            aggregated_performance[metric] += value
            metric_counts[metric] += 1

    averaged_performance = {metric: (total / metric_counts[metric]) for metric, total in aggregated_performance.items()}

    return jsonify({"successful": True, "message": averaged_performance, "status_code": 200}), 200


@app.route("/users/get/range/performance", methods=["GET"])
@jwt_required()
def get_range_performance():
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    merch_id = request.args.get('merch_id')

    if not start_date_str or not end_date_str or not merch_id:
        return jsonify({"successful": False, "message": "Start date, end date, and merchandiser ID are required", "status_code": 400}), 400

    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        end_date = end_date.replace(hour=23, minute=59, second=59)
    except ValueError:
        return jsonify({"successful": False, "message": "Invalid date format. Use YYYY-MM-DD", "status_code": 400}), 400

    performance_entries = MerchandiserPerformance.query.filter_by(merchandiser_id=merch_id)\
                                                       .filter(MerchandiserPerformance.date_time >= start_date)\
                                                       .filter(MerchandiserPerformance.date_time <= end_date)\
                                                       .all()

    if not performance_entries:
        return jsonify({"successful": False, "message": "No performance data found for the given date range", "status_code": 404}), 404

    aggregated_performance = {}
    total_entries = len(performance_entries)

    for entry in performance_entries:
        for metric, value in entry.performance.items():
            if metric not in aggregated_performance:
                aggregated_performance[metric] = []
            aggregated_performance[metric].append(value)

    averaged_performance = {}
    for metric, values in aggregated_performance.items():
        if len(values) == total_entries:
            averaged_performance[metric] = sum(values) / total_entries

    return jsonify({"successful": True, "message": averaged_performance, "status_code": 200}), 200

@app.route("/users/create/kpi", methods=["POST"])
@jwt_required()
def create_key_performance_indicators():
    if not request.is_json:
        return jsonify({"message": "Invalid data: You did not provide any data.", "status_code": 400, "successful": False}), 400

    data = request.get_json()
    sector_name = data.get("sector_name")
    company_name = data.get("company_name")
    admin_id = data.get("admin_id")
    performance_metric = data.get("performance_metric")

    if not sector_name or not isinstance(sector_name, str):
        return jsonify({"message": "Invalid data: 'sector_name' is required and must be a string.", "status_code": 400, "successful": False}), 400

    if not company_name or not isinstance(company_name, str):
        return jsonify({"message": "Invalid data: 'company_name' is required and must be a string.", "status_code": 400, "successful": False}), 400

    if admin_id is None or not isinstance(admin_id, int):
        return jsonify({"message": "Invalid data: 'admin_id' is required and must be an integer.", "status_code": 400, "successful": False}), 400

    if not performance_metric or not isinstance(performance_metric, dict):
        return jsonify({"message": "Invalid data: 'performance_metric' is required and must be a JSON object.", "status_code": 400, "successful": False}), 400

    try:
        kpi = KeyPerformaceIndicator(
            sector_name=sector_name,
            company_name=company_name,
            admin_id=admin_id,
            performance_metric=performance_metric
        )
        db.session.add(kpi)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "Database error: Could not create KPI. Check if the admin_id exists.", "status_code": 400, "successful": False}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"An error occurred: {str(e)}", "status_code": 500, "successful": False}), 500

    return jsonify({"message": "KPI created successfully.", "status_code": 201, "successful": True}), 201


@app.route("/users/get/kpis", methods=["GET"])
@jwt_required()
def get_key_performance_indicators():
    try:
        kpis = KeyPerformaceIndicator.query.all()

        if not kpis:
            return jsonify({"message": "No KPIs created", "status_code": 404, "successful": False}), 404
        kpi_list = []
        
        for kpi in kpis:
            kpi_data = {
                "id": kpi.id,
                "sector_name": kpi.sector_name,
                "company_name": kpi.company_name,
                "admin_id": kpi.admin_id,
                "performance_metric": kpi.performance_metric
            }
            kpi_list.append(kpi_data)
        
        return jsonify({"message": kpi_list, "status_code": 200, "successful": True}), 200
    
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}", "status_code": 500, "successful": False}), 500
  

@app.route("/users/delete/kpi/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_kpi(id):
    kpi = KeyPerformaceIndicator.query.get(id)
    
    if kpi:
        try:
            db.session.delete(kpi)
            db.session.commit()
            return jsonify({"status_code": 200, "message": "KPI deleted successfully", "successful": True}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"status_code": 500, "message": f"An error occurred: {str(e)}", "successful": False}), 500
    else:
        return jsonify({"status_code": 404, "message": "KPI not found", "successful": False}), 404


@app.route("/users/change/pass", methods=["PUT"])
@jwt_required()
def change_pass():
    data = request.get_json()
    email = data.get("email")
    new_password = data.get("new_password")

    if not email or not new_password:
        return jsonify({"message": "Email and new password are required", "successful": False, "status_code": 400}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found", "successful": False, "status_code": 404}), 404

    hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
    user.password = hashed_password

    try:
        db.session.commit()
        return jsonify({"message": "Password changed successfully", "successful": True, "status_code": 200}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Internal server error: {e}", "successful": False, "status_code": 500}), 500


@app.route("/users/performances", methods=["GET"])
@jwt_required()
def get_performance():
    performances = MerchandiserPerformance.query.all()

    if not performances:
        return jsonify({"message": "There is no performance", "successfull": False, "status_code": 404}), 404
    
    perormances_list=[]
    for performance in performances:
        perormances_list.append({
            "id": performance.id,
            "merchandiser_id": performance.merchandiser_id,
            "date_time": performance.date_time,
            "day": performance.day,
            "performance": performance.performance
        })

    return jsonify({"message": perormances_list, "successfull": True, "status_code": 200}), 200


@app.route("/users/get/all/routes", methods=["GET"])
@jwt_required()
def get_all_routes():
    route_plans = RoutePlan.query.all()

    if not route_plans:
        return jsonify({"successful": False, "message": "No route plans found", "status_code": 404}), 404

    formatted_route_plans = []
    for plan in route_plans:
        formatted_plan = {
            "date_range": {
                "start_date": plan.date_range['start_date'],
                "end_date": plan.date_range['end_date']
            },
            "id": plan.id,
            "instructions": plan.instructions,  
            "manager_id": plan.manager_id, 
            "staff_no": plan.merchandiser.staff_no,
            "status": plan.status
        }
        formatted_route_plans.append(formatted_plan)

    return jsonify({"successful": True, "message": formatted_route_plans, "status_code": 200}), 200


@app.route("/users/all/kpis", methods=["GET"])
@jwt_required()
def get_all_kpis():
    try:
        kpis = KeyPerformaceIndicator.query.all()
        
        formatted_kpis = []
        for kpi in kpis:
            formatted_kpi = {
                "id": kpi.id,
                "sector_name": kpi.sector_name,
                "company_name": kpi.company_name,
                "admin_id": kpi.admin_id,
                "performance_metric": kpi.performance_metric
            }
            formatted_kpis.append(formatted_kpi)
        
        return jsonify({"successful": True, "message": formatted_kpis, "status_code": 200}), 200
    
    except Exception as e:
        return jsonify({"successful": False, "message": f"Failed to fetch KPIs: {str(e)}", "status_code": 500}), 500


@app.route("/users/update/kpi/<int:id>", methods=["PUT"])
@jwt_required()
def update_kpi(id):
    new_performance_metric = request.json.get('performance_metric', None)

    kpi = KeyPerformaceIndicator.query.get(id)
    if not kpi:
        return jsonify({"successful": False, "message": "No KPI found", "status_code": 404}), 404

    if not isinstance(new_performance_metric, dict):
        return jsonify({"successful": False, "message": "Invalid data format", "status_code": 400}), 400

    kpi.performance_metric = new_performance_metric

    try:
        db.session.commit()
        return jsonify({"successful": True, "message": "KPI updated successfully", "status_code": 201}), 201
    except Exception as err:
        db.session.rollback()
        return jsonify({"successful": False, "message": f"Failed: Error: {err}", "status_code": 500}), 500
    
@app.route("/users/leaderboard/performance", methods=["GET"])
@jwt_required()
def get_leaderboard_performance():
    try:
        current_datetime = datetime.now()
        current_month = current_datetime.strftime("%B")

        start_of_month = current_datetime.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_of_month = (start_of_month.replace(month=start_of_month.month % 12 + 1, day=1) - timedelta(days=1)).replace(hour=23, minute=59, second=59)

        performance_entries = MerchandiserPerformance.query.filter(MerchandiserPerformance.date_time >= start_of_month,
                                                                  MerchandiserPerformance.date_time <= end_of_month)\
                                                           .all()

        if not performance_entries:
            return jsonify({"successful": False, "message": "No performance data found for the current month", "status_code": 404}), 404

        merchandiser_scores = {}
        for entry in performance_entries:
            if entry.merchandiser_id not in merchandiser_scores:
                merchandiser_scores[entry.merchandiser_id] = {"total_score": 0, "count": 0}
            merchandiser_scores[entry.merchandiser_id]["total_score"] += entry.performance["total_performance"]
            merchandiser_scores[entry.merchandiser_id]["count"] += 1

        leaderboard = []
        for merchandiser_id, data in merchandiser_scores.items():
            average_score = data["total_score"] / data["count"] if data["count"] > 0 else 0

            user = User.query.filter_by(id=merchandiser_id).first()
            if user:
                name = f"{user.first_name} {user.last_name}"
            else:
                name = "Unknown"

            leaderboard.append({"name": name, "score": average_score, "month": current_month})

        leaderboard = sorted(leaderboard, key=lambda x: x["score"], reverse=True)

        return jsonify({"successful": True, "message": leaderboard, "status_code": 200}), 200

    except Exception as e:
        return jsonify({"successful": False, "message": f"An error occurred: {str(e)}", "status_code": 500}), 500


@app.route("/users/complete/route/plan/<int:id>", methods=["PUT"])
@jwt_required()
def complete_route_plan(id):
    try:
        route_plan = RoutePlan.query.get(id)

        if not route_plan:
            return jsonify({"message": "Route plan not found.", "status_code": 404, "successful": False}), 404

        route_plan.status = "complete"
        db.session.commit()

        return jsonify({"message": f"Route plan {id} marked as complete successfully.", "status_code": 201, "successful": True}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Failed to mark route plan {id} as complete. Error: {str(e)}", "status_code": 500, "successful": False}), 500

@app.route("/users/notifications/edit-status/<int:notification_id>", methods=["PUT"])
@jwt_required()
def edit_notification_status(notification_id):
    try:
        notification = Message.query.get(notification_id)
        if not notification:
            return jsonify({"message": "Notification not found", "status_code": 404, "successful": False}), 404

        notification.status = "read"
        db.session.commit()
        return jsonify({"message": "Notification status updated successfully", "status_code": 201, "successful": True}), 201
    
    except SQLAlchemyError as e:
        db.session.rollback()
        error_message = str(e.__dict__.get('orig') or e)
        return jsonify({"message": f"Failed to update notification status: {error_message}", "status_code": 500, "successful": False}), 500


@app.route("/users/reply/to/notification", methods=["POST"])
@jwt_required()
def reply_to_notification():
    data = request.get_json()
    message_id = data.get("message_id")
    reply_text = data.get("reply")
    sender = data.get("sender")

    if not all([message_id, reply_text, sender]):
        return jsonify({"message": "Missing required fields", "status_code": 400, "successful": False}), 400

    message = Message.query.filter_by(id=message_id).first()
    if not message:
        return jsonify({"message": "Message not found", "status_code": 404, "successful": False}), 404

    if not isinstance(sender, str) or not isinstance(reply_text, str):
        return jsonify({"message": "Message and sender must be strings", "status_code": 400, "successful": False}), 400

    reply = Reply(
        manager_id=message.manager_id,
        merchandiser_id=message.merchandiser_id,
        message_id=message_id,
        reply=reply_text,
        sender=sender,
        status="unread"  
    )

    try:
        db.session.add(reply)
        db.session.commit()
        return jsonify({"message": "Reply posted successfully", "status_code": 201, "successful": True}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": str(e), "status_code": 500, "successful": False}), 500


@app.route("/users/notifications/unread/<int:id>", methods=["GET"])
@jwt_required()
def get_unread_notifications(id):
    try:
        notifications = Message.query.filter(
            or_(Message.merchandiser_id == id, Message.manager_id == id),
            Message.status == 'unread'
        ).all()

        if not notifications:
            return jsonify({"message": "No unread notifications found", "status_code": 404, "successful": False}), 404

        unread_notifications = []
        for notification in notifications:
            replies = Reply.query.filter_by(message_id=notification.id).all()
            reply_list = [{
                "id": reply.id,
                "manager_id": reply.manager_id,
                "merchandiser_id": reply.merchandiser_id,
                "reply": reply.reply,
                "sender": reply.sender,
                "status": reply.status
            } for reply in replies]

            unread_notifications.append({
                "id": notification.id,
                "manager_id": notification.manager_id,
                "message": notification.message,
                "status": notification.status,
                "replies": reply_list
            })
        return jsonify({"message": unread_notifications, "status_code": 200, "successful": True}), 200
    except SQLAlchemyError as e:
        error_message = str(e.__dict__.get('orig') or e)
        return jsonify({"message": f"Failed to fetch notifications: {error_message}", "status_code": 500, "successful": False}), 500




if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5555, debug=True)




