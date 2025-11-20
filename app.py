import os
import re
import base64
import math
from datetime import datetime, timezone, timedelta

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from pymongo import MongoClient, ASCENDING, errors as mongo_errors
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
from bson import ObjectId

# ------------------------------------------------------------
# Env & config
# ------------------------------------------------------------
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB = os.getenv("MONGODB_DB", "dogwalk")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")  # change in prod!
PORT = int(os.getenv("PORT", "5000"))

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = JWT_SECRET
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

jwt = JWTManager(app)

# CORS (tune ALLOWED_ORIGINS in .env for prod)
allowed = os.getenv("ALLOWED_ORIGINS", "*")
if allowed.strip() == "*":
    CORS(
        app,
        resources={r"/api/*": {"origins": "*"}},
        supports_credentials=False,
        allow_headers=["Content-Type", "Authorization"],
        expose_headers=["Authorization"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=86400,
    )
else:
    origins = [o.strip() for o in allowed.split(",") if o.strip()]
    CORS(
        app,
        resources={r"/api/*": {"origins": origins}},
        supports_credentials=False,
        allow_headers=["Content-Type", "Authorization"],
        expose_headers=["Authorization"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=86400,
    )

# ------------------------------------------------------------
# DB
# ------------------------------------------------------------
mongo = MongoClient(MONGODB_URI)
db = mongo[MONGODB_DB]

users = db["users"]
dogs = db["dogs"]
walks = db["walks"]
chats = db["chats"]
messages = db["messages"]
walk_locations = db["walk_locations"]

try:
    users.create_index([("email", ASCENDING)], unique=True)

    dogs.create_index([("ownerEmail", ASCENDING)])
    dogs.create_index([("ownerEmail", ASCENDING), ("name", ASCENDING)])

    walks.create_index([("status", ASCENDING), ("district", ASCENDING)])
    walks.create_index([("ownerEmail", ASCENDING)])
    walks.create_index([("walkerEmail", ASCENDING)])
    walks.create_index([("startAt", ASCENDING)])

    chats.create_index([("walkId", ASCENDING)])
    chats.create_index([("ownerEmail", ASCENDING)])
    chats.create_index([("walkerEmail", ASCENDING)])
    chats.create_index([("updatedAt", -1)])

    messages.create_index([("chatId", ASCENDING), ("createdAt", ASCENDING)])
    walk_locations.create_index([("walkId", ASCENDING), ("capturedAt", ASCENDING)])
    walk_locations.create_index([("walkId", ASCENDING), ("capturedAt", ASCENDING)])
except mongo_errors.PyMongoError as e:
    print("Index creation warning:", e)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=]+\Z")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def safe_oid(oid_str: str):
    try:
        return ObjectId(oid_str)
    except Exception:
        return None


def parse_iso_datetime(value: str):
    """
    Accepts ISO strings, optionally ending with 'Z'. Returns aware datetime or None.
    """
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def parse_number(val):
    if val is None or val == "":
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def clean_user(doc):
    if not doc:
        return None
    return {
        "id": str(doc["_id"]),
        "email": doc["email"],
        "phone": doc.get("phone"),
        "name": doc.get("name"),
        "surname": doc.get("surname"),
        "role": doc.get("role"),
        "createdAt": doc.get("createdAt"),
    }


def clean_dog(doc):
    if not doc:
        return None
    return {
        "id": str(doc["_id"]),
        "photoBase64": doc.get("photoBase64"),
        "photo": doc.get("photo"),  # legacy / optional URL field
        "name": doc.get("name"),
        "breed": doc.get("breed"),
        "age": doc.get("age"),
        "weight": doc.get("weight"),
        "specialNotes": doc.get("specialNotes"),
        "ownerEmail": doc.get("ownerEmail"),
        "createdAt": doc.get("createdAt"),
        "updatedAt": doc.get("updatedAt"),
    }


def load_dog_snapshot(doc):
    pet_id = doc.get("petId")
    if not pet_id:
        return None
    lookup = pet_id
    if isinstance(pet_id, str):
        lookup = safe_oid(pet_id)
    if not isinstance(lookup, ObjectId):
        return None
    dog_doc = dogs.find_one({"_id": lookup})
    if not dog_doc:
        return None
    return clean_dog(dog_doc)


def load_user_snapshot(email):
    if not email:
        return None
    user_doc = users.find_one({"email": email})
    if not user_doc:
        return None
    return clean_user(user_doc)


def clean_walk(doc):
    if not doc:
        return None
    applications = clean_applications(doc)
    dog_snapshot = load_dog_snapshot(doc)
    owner_snapshot = load_user_snapshot(doc.get("ownerEmail"))
    walker_snapshot = load_user_snapshot(doc.get("walkerEmail"))
    last_location = doc.get("lastLocation")
    return {
        "id": str(doc["_id"]),
        "ownerEmail": doc.get("ownerEmail"),
        "petId": str(doc["petId"]) if doc.get("petId") else None,
        "district": doc.get("district"),
        "startAt": doc.get("startAt"),  # ISO string
        "status": doc.get("status"),  # open, pending_owner, confirmed, canceled, declined
        "candidateWalkerEmail": doc.get("candidateWalkerEmail"),
        "walkerEmail": doc.get("walkerEmail"),
        "chatId": str(doc["chatId"]) if doc.get("chatId") else None,
        "createdAt": doc.get("createdAt"),
        "updatedAt": doc.get("updatedAt"),
        "notes": doc.get("notes"),
        "applications": applications,
        "liveStartedAt": doc.get("liveStartedAt"),
        "completedAt": doc.get("completedAt"),
        "plannedMinutes": doc.get("plannedMinutes"),
        "distanceMeters": doc.get("distanceMeters", 0),
        "dog": dog_snapshot,
        "ownerProfile": owner_snapshot,
        "walkerProfile": walker_snapshot,
        "lastLocation": clean_location(last_location),
    }


def clean_chat(doc):
    if not doc:
        return None
    created_at = doc.get("createdAt")
    updated_at = doc.get("updatedAt")
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()
    if isinstance(updated_at, datetime):
        updated_at = updated_at.isoformat()
    owner_snapshot = load_user_snapshot(doc.get("ownerEmail"))
    walker_snapshot = load_user_snapshot(doc.get("walkerEmail"))
    item = {
        "id": str(doc["_id"]),
        "walkId": str(doc["walkId"]) if doc.get("walkId") else None,
        "ownerEmail": doc.get("ownerEmail"),
        "walkerEmail": doc.get("walkerEmail"),
        "status": doc.get("status"),  # active, closed, declined
        "createdAt": created_at,
        "updatedAt": updated_at,
        # New fields expected by iOS client:
        "lastMessage": doc.get("lastMessage") or "",
        "unreadOwner": int(doc.get("unreadOwner") or 0),
        "unreadWalker": int(doc.get("unreadWalker") or 0),
        "dogName": doc.get("dogName"),
        "ownerProfile": owner_snapshot,
        "walkerProfile": walker_snapshot,
    }

    # Optional lazy enrichment if dogName not stored on chat
    if not item["dogName"] and doc.get("walkId"):
        wdoc = walks.find_one({"_id": doc["walkId"]})
        if wdoc and wdoc.get("petId"):
            ddoc = dogs.find_one({"_id": wdoc["petId"]})
            if ddoc:
                item["dogName"] = ddoc.get("name")

    return item


def clean_location(doc):
    if not doc:
        return None
    captured = doc.get("capturedAt")
    if isinstance(captured, datetime):
        captured = captured.isoformat()
    return {
        "id": str(doc.get("_id", "")),
        "latitude": doc.get("latitude"),
        "longitude": doc.get("longitude"),
        "capturedAt": captured,
    }


def clean_applications(doc):
    applications = []
    raw = doc.get("applications") or []
    for entry in raw:
        applications.append({
            "id": str(entry.get("_id") or entry.get("id")),
            "walkerEmail": entry.get("walkerEmail"),
            "status": entry.get("status"),
            "chatId": str(entry.get("chatId")) if entry.get("chatId") else None,
            "createdAt": entry.get("createdAt"),
            "updatedAt": entry.get("updatedAt"),
        })
    if not applications and doc.get("status") == "pending_owner" and not doc.get("walkerEmail") and doc.get(
            "candidateWalkerEmail"):
        applications.append({
            "id": f"legacy-{doc.get('_id')}",
            "walkerEmail": doc.get("candidateWalkerEmail"),
            "status": "pending_owner",
            "chatId": str(doc.get("chatId")) if doc.get("chatId") else None,
            "createdAt": doc.get("createdAt"),
            "updatedAt": doc.get("updatedAt"),
        })
    return applications


def clean_message(doc):
    if not doc:
        return None
    return {
        "id": str(doc["_id"]),
        "chatId": str(doc["chatId"]) if doc.get("chatId") else None,
        "walkId": str(doc["walkId"]) if doc.get("walkId") else None,
        "senderEmail": doc.get("senderEmail"),
        "senderRole": doc.get("senderRole"),
        "text": doc.get("text"),
        "createdAt": doc.get("createdAt"),
        "type": doc.get("type"),
        "imageBase64": doc.get("imageBase64"),
        "mime": doc.get("mime"),
        "latitude": doc.get("latitude"),
        "longitude": doc.get("longitude"),
        "title": doc.get("title"),
    }


def issue_tokens(identity: str):
    access = create_access_token(identity=identity)
    refresh = create_refresh_token(identity=identity)
    return access, refresh


def get_current_user_doc():
    email = get_jwt_identity()
    return users.find_one({"email": email})


def haversine_meters(lat1, lon1, lat2, lon2):
    if None in (lat1, lon1, lat2, lon2):
        return 0.0
    r = 6371000.0  # Earth radius in meters
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return r * c


# ---------------------- Validators --------------------------
def validate_register_payload(data):
    required = ["email", "password", "phone", "name", "surname", "role"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return f"Missing fields: {', '.join(missing)}"

    if data["role"] not in ["owner", "walker"]:
        return "Role must be 'owner' or 'walker'."

    try:
        v = validate_email(data["email"], check_deliverability=False)
        data["email"] = v.normalized
    except EmailNotValidError as e:
        return f"Invalid email: {e}"

    if len(data["password"]) < 8:
        return "Password must be at least 8 characters."

    if len(data["name"]) < 2 or len(data["surname"]) < 2:
        return "Name and surname must be at least 2 characters."

    if len(data["phone"]) < 6:
        return "Phone number looks too short."

    return None


def validate_login_payload(data):
    required = ["email", "password"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return f"Missing fields: {', '.join(missing)}"
    try:
        v = validate_email(data["email"], check_deliverability=False)
        data["email"] = v.normalized
    except EmailNotValidError:
        return "Invalid email."
    return None


def normalize_dog_payload(data: dict, partial: bool = False):
    """
    Accepts keys: photoBase64, photo, name, breed (alias 'bread'), age, weight, specialNotes
    Returns (dog_dict, error_message)
    """
    # alias
    if "breed" not in data and "bread" in data:
        data["breed"] = data["bread"]

    dog = {}

    if not partial:
        required = ["name"]
        missing = [f for f in required if not data.get(f)]
        if missing:
            return None, f"Missing fields: {', '.join(missing)}"

    # base64 photo
    if "photoBase64" in data and isinstance(data["photoBase64"], str):
        b64_str = data["photoBase64"].strip()
        if not b64_str:
            dog["photoBase64"] = None
        else:
            # strip data URI prefix if present
            if b64_str.startswith("data:"):
                b64_str = b64_str.split(",")[-1]
            if not BASE64_PATTERN.match(b64_str):
                return None, "Invalid base64 image data."
            try:
                base64.b64decode(b64_str, validate=True)
            except Exception:
                return None, "Invalid base64 image data."
            dog["photoBase64"] = b64_str

    # optional legacy URL field
    if "photo" in data and isinstance(data["photo"], str):
        dog["photo"] = data["photo"].strip()

    for key in ["name", "breed", "specialNotes"]:
        if key in data and isinstance(data[key], str):
            dog[key] = data[key].strip()

    if "age" in data:
        age = parse_number(data["age"])
        if data["age"] not in (None, "") and age is None:
            return None, "Field 'age' must be a number."
        dog["age"] = age

    if "weight" in data:
        weight = parse_number(data["weight"])
        if data["weight"] not in (None, "") and weight is None:
            return None, "Field 'weight' must be a number."
        dog["weight"] = weight

    return dog, None


# ------------------------------------------------------------
# Auth Routes
# ------------------------------------------------------------
@app.post("/api/auth/register")
def register():
    """
    Body:
    {
      "email": "owner@example.com",
      "password": "secret123",
      "phone": "+380961234567",
      "name": "John",
      "surname": "Doe",
      "role": "owner"  // or "walker"
    }
    """
    data = request.get_json(silent=True) or {}
    err = validate_register_payload(data)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    email = data["email"]
    pwd_hash = generate_password_hash(data["password"])
    doc = {
        "email": email,
        "password_hash": pwd_hash,
        "phone": data["phone"].strip(),
        "name": data["name"].strip(),
        "surname": data["surname"].strip(),
        "role": data["role"].strip().lower(),
        "createdAt": now_iso(),
    }

    try:
        users.insert_one(doc)
    except mongo_errors.DuplicateKeyError:
        return jsonify({"ok": False, "error": "Email already registered."}), 409
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    access, refresh = issue_tokens(email)
    return jsonify({"ok": True, "access": access, "refresh": refresh, "user": clean_user(doc)}), 201


@app.post("/api/auth/login")
def login():
    """
    Body:
    {
      "email": "owner@example.com",
      "password": "secret123"
    }
    """
    data = request.get_json(silent=True) or {}
    err = validate_login_payload(data)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    email = data["email"]
    password = data["password"]

    doc = users.find_one({"email": email})
    if not doc or not check_password_hash(doc.get("password_hash", ""), password):
        return jsonify({"ok": False, "error": "Invalid credentials."}), 401

    access, refresh = issue_tokens(email)
    return jsonify({"ok": True, "access": access, "refresh": refresh, "user": clean_user(doc)}), 200


@app.post("/api/auth/refresh")
@jwt_required(refresh=True)
def refresh():
    """
    Authorization: Bearer <REFRESH_TOKEN>
    """
    email = get_jwt_identity()
    access, _ = issue_tokens(email)
    return jsonify({"ok": True, "access": access}), 200


@app.get("/api/auth/me")
@jwt_required()
def me():
    """Authorization: Bearer <ACCESS_TOKEN>"""
    email = get_jwt_identity()
    doc = users.find_one({"email": email})
    if not doc:
        return jsonify({"ok": False, "error": "User not found."}), 404
    return jsonify({"ok": True, "user": clean_user(doc)}), 200


# ------------------------------------------------------------
# Dogs CRUD (scoped to owner)
# ------------------------------------------------------------
@app.get("/api/dogs")
@jwt_required()
def list_dogs():
    email = get_jwt_identity()
    cur = dogs.find({"ownerEmail": email}).sort("createdAt", ASCENDING)
    return jsonify({"ok": True, "items": [clean_dog(d) for d in cur]}), 200


@app.post("/api/dogs")
@jwt_required()
def create_dog():
    """
    Body:
    {
      "photoBase64": "data:image/jpeg;base64,...",  // or raw base64 payload
      "name": "Buddy",
      "breed": "Golden Retriever",  // alias: 'bread' supported
      "age": 3,
      "weight": 28.5,
      "specialNotes": "Sensitive stomach"
    }
    """
    email = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    dog, err = normalize_dog_payload(data, partial=False)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    doc = {
        **dog,
        "ownerEmail": email,
        "createdAt": now_iso(),
        "updatedAt": now_iso(),
    }
    try:
        res = dogs.insert_one(doc)
        doc["_id"] = res.inserted_id
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "item": clean_dog(doc)}), 201


@app.get("/api/dogs/<dog_id>")
@jwt_required()
def get_dog(dog_id):
    email = get_jwt_identity()
    oid = safe_oid(dog_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid dog id."}), 400

    doc = dogs.find_one({"_id": oid, "ownerEmail": email})
    if not doc:
        return jsonify({"ok": False, "error": "Dog not found."}), 404

    return jsonify({"ok": True, "item": clean_dog(doc)}), 200


@app.put("/api/dogs/<dog_id>")
@jwt_required()
def update_dog_put(dog_id):
    return _update_dog_common(dog_id, partial=False)


@app.patch("/api/dogs/<dog_id>")
@jwt_required()
def update_dog_patch(dog_id):
    return _update_dog_common(dog_id, partial=True)


def _update_dog_common(dog_id, partial: bool):
    email = get_jwt_identity()
    oid = safe_oid(dog_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid dog id."}), 400

    data = request.get_json(silent=True) or {}
    dog, err = normalize_dog_payload(data, partial=partial)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    if not partial and not dog.get("name"):
        return jsonify({"ok": False, "error": "Field 'name' is required for full update."}), 400

    dog["updatedAt"] = now_iso()
    try:
        res = dogs.update_one({"_id": oid, "ownerEmail": email}, {"$set": dog})
        if res.matched_count == 0:
            return jsonify({"ok": False, "error": "Dog not found."}), 404
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    doc = dogs.find_one({"_id": oid, "ownerEmail": email})
    return jsonify({"ok": True, "item": clean_dog(doc)}), 200


@app.delete("/api/dogs/<dog_id>")
@jwt_required()
def delete_dog(dog_id):
    email = get_jwt_identity()
    oid = safe_oid(dog_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid dog id."}), 400

    try:
        res = dogs.delete_one({"_id": oid, "ownerEmail": email})
        if res.deleted_count == 0:
            return jsonify({"ok": False, "error": "Dog not found."}), 404
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True}), 200


# ------------------------------------------------------------
# Walks + Chats
# ------------------------------------------------------------
# Statuses:
# - open           : created by owner, not yet taken
# - pending_owner  : walker applied, waiting for owner decision
# - live           : walker started walk
# - ready          : owner confirmed walker, waiting for walker
# - paused         : walker temporarily paused the walk
# - completed      : walk finished
# - canceled       : owner canceled

@app.post("/api/walks")
@jwt_required()
def create_walk():
    """
    Owner creates a walk.

    Body:
    {
      "petId": "<DOG_ID>",
      "district": "Downtown",
      "startAt": "2025-11-15T10:30:00Z",
      "notes": "Optional notes"
    }
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user.get("role") != "owner":
        return jsonify({"ok": False, "error": "Only owners can create walks."}), 403

    data = request.get_json(silent=True) or {}
    required = ["petId", "district", "startAt"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"ok": False, "error": f"Missing fields: {', '.join(missing)}"}), 400

    pet_id = safe_oid(data["petId"])
    if not pet_id:
        return jsonify({"ok": False, "error": "Invalid petId."}), 400

    # ensure dog belongs to this owner
    dog_doc = dogs.find_one({"_id": pet_id, "ownerEmail": user["email"]})
    if not dog_doc:
        return jsonify({"ok": False, "error": "Dog not found for this owner."}), 404

    dt = parse_iso_datetime(data["startAt"])
    if not dt:
        return jsonify({"ok": False, "error": "Invalid startAt datetime format."}), 400

    planned_minutes = data.get("plannedMinutes")
    try:
        planned_minutes = int(planned_minutes)
        if planned_minutes <= 0 or planned_minutes > 240:
            planned_minutes = 30
    except (TypeError, ValueError):
        planned_minutes = 30

    doc = {
        "ownerEmail": user["email"],
        "petId": pet_id,
        "district": data["district"].strip(),
        "startAt": dt.astimezone(timezone.utc).isoformat(),
        "status": "open",
        "candidateWalkerEmail": None,
        "walkerEmail": None,
        "chatId": None,
        "liveStartedAt": None,
        "completedAt": None,
        "plannedMinutes": planned_minutes,
        "distanceMeters": 0,
        "lastLocation": None,
        "notes": data.get("notes", "").strip() if isinstance(data.get("notes"), str) else "",
        "createdAt": now_iso(),
        "updatedAt": now_iso(),
        "applications": [],
    }

    try:
        res = walks.insert_one(doc)
        doc["_id"] = res.inserted_id
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "item": clean_walk(doc)}), 201


@app.get("/api/walks/mine")
@jwt_required()
def list_my_walks():
    """
    Owner: walks they created.
    Walker: walks they are confirmed on OR applied to.
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    email = user["email"]
    role = user.get("role")

    if role == "owner":
        cur = walks.find({"ownerEmail": email}).sort("startAt", ASCENDING)
    else:  # walker
        cur = walks.find({
            "$or": [
                {"walkerEmail": email},
                {"candidateWalkerEmail": email},
            ]
        }).sort("startAt", ASCENDING)

    return jsonify({"ok": True, "items": [clean_walk(w) for w in cur]}), 200


@app.get("/api/walks/available")
@jwt_required()
def list_available_walks():
    """
    Walker sees open walks.

    Query params:
      - district (optional, exact match for now)
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user.get("role") != "walker":
        return jsonify({"ok": False, "error": "Only walkers can view available walks."}), 403

    q = {"status": "open"}
    district = request.args.get("district")
    if district:
        q["district"] = district

    cur = walks.find(q).sort("startAt", ASCENDING)
    return jsonify({"ok": True, "items": [clean_walk(w) for w in cur]}), 200


@app.get("/api/walks/<walk_id>")
@jwt_required()
def get_walk(walk_id):
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404

    oid = safe_oid(walk_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid walk id."}), 400

    w = walks.find_one({"_id": oid})
    if not w:
        return jsonify({"ok": False, "error": "Walk not found."}), 404

    email = user["email"]

    # simple access control:
    if w["status"] != "open" and email not in {
        w.get("ownerEmail"),
        w.get("walkerEmail"),
        w.get("candidateWalkerEmail"),
    }:
        return jsonify({"ok": False, "error": "Forbidden."}), 403

    return jsonify({"ok": True, "item": clean_walk(w)}), 200


@app.post("/api/walks/<walk_id>/apply")
@jwt_required()
def walker_apply_walk(walk_id):
    """
    Walker sees a walk and applies (wants to take it).
    This:
      - sets candidateWalkerEmail
      - sets status to pending_owner
      - creates chat (if not exists) with summary fields for chat list
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user.get("role") != "walker":
        return jsonify({"ok": False, "error": 'Only walkers can apply for walks.'}), 403

    email = user["email"]
    oid = safe_oid(walk_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid walk id."}), 400

    w = walks.find_one({"_id": oid})
    if not w:
        return jsonify({"ok": False, "error": "Walk not found."}), 404

    if w["ownerEmail"] == email:
        return jsonify({"ok": False, "error": "You cannot apply for your own walk."}), 400

    if w.get("status") != "open":
        return jsonify({"ok": False, "error": f"Walk is not open (status: {w.get('status')})."}), 409

    if w.get("candidateWalkerEmail") or w.get("walkerEmail"):
        return jsonify({"ok": False, "error": "Walk already has a walker candidate."}), 409

    # Create chat
    timestamp = now_iso()
    chat_doc = {
        "walkId": oid,
        "ownerEmail": w["ownerEmail"],
        "walkerEmail": email,
        "status": "active",
        "createdAt": timestamp,
        "updatedAt": timestamp,
        # Initialize fields used by MessagesListView
        "lastMessage": "",
        "unreadOwner": 0,
        "unreadWalker": 0,
        "dogName": None,
    }

    # Persist dogName from walk->petId if available
    try:
        if w.get("petId"):
            dog_doc = dogs.find_one({"_id": w["petId"]})
            if dog_doc:
                chat_doc["dogName"] = dog_doc.get("name")
    except mongo_errors.PyMongoError:
        pass  # don't block creation if enrichment fails

    try:
        chat_res = chats.insert_one(chat_doc)
        chat_doc["_id"] = chat_res.inserted_id

        application_entry = {
            "_id": ObjectId(),
            "walkerEmail": email,
            "status": "pending_owner",
            "chatId": chat_doc["_id"],
            "createdAt": timestamp,
            "updatedAt": timestamp,
        }
        walks.update_one(
            {"_id": oid},
            {
                "$push": {"applications": application_entry},
                "$set": {
                    "candidateWalkerEmail": email,
                    "status": "pending_owner",
                    "chatId": chat_doc["_id"],
                    "updatedAt": timestamp,
                }
            },
        )
        w = walks.find_one({"_id": oid})
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({
        "ok": True,
        "walk": clean_walk(w),
        "chat": clean_chat(chat_doc),
    }), 200


@app.post("/api/walks/<walk_id>/owner-confirm")
@jwt_required()
def owner_confirm_walk(walk_id):
    """
    Owner confirms the candidate walker after chat.
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user.get("role") != "owner":
        return jsonify({"ok": False, "error": "Only owners can confirm walkers."}), 403

    owner_email = user["email"]
    oid = safe_oid(walk_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid walk id."}), 400

    w = walks.find_one({"_id": oid, "ownerEmail": owner_email})
    if not w:
        return jsonify({"ok": False, "error": "Walk not found for this owner."}), 404

    if w.get("status") != "pending_owner":
        return jsonify({"ok": False, "error": "No walker candidate to confirm."}), 400

    candidate = None
    applications = w.get("applications") or []
    selected_app_id = None
    data = request.get_json(silent=True) or {}
    if applications:
        app_id = data.get("applicationId")
        if app_id:
            target = next(
                (app for app in applications if str(app.get("_id") or app.get("id")) == app_id),
                None
            )
            if not target or target.get("status") != "pending_owner":
                return jsonify({"ok": False, "error": "Application not found or already processed."}), 400
            candidate = target.get("walkerEmail")
            selected_app_id = str(target.get("_id") or target.get("id"))
        else:
            pending = next((app for app in applications if app.get("status") == "pending_owner"), None)
            if pending:
                candidate = pending.get("walkerEmail")
                selected_app_id = str(pending.get("_id") or pending.get("id"))
    if not candidate:
        candidate = w.get("candidateWalkerEmail")
    if not candidate:
        return jsonify({"ok": False, "error": "No walker candidate to confirm."}), 400

    now = now_iso()
    updated_apps = []
    if not applications and candidate:
        temp_id = ObjectId()
        updated_apps.append({
            "_id": temp_id,
            "walkerEmail": candidate,
            "status": "accepted",
            "chatId": w.get("chatId"),
            "createdAt": now,
            "updatedAt": now,
        })
        selected_app_id = str(temp_id)
    else:
        for app in applications:
            entry = dict(app)
            identifier = str(app.get("_id") or app.get("id"))
            if identifier == selected_app_id:
                entry["status"] = "accepted"
                entry["updatedAt"] = now
            elif entry.get("status") == "pending_owner":
                entry["status"] = "declined"
                entry["updatedAt"] = now
            updated_apps.append(entry)

    try:
        walks.update_one(
            {"_id": oid},
            {
                "$set": {
                    "status": "ready",
                    "walkerEmail": candidate,
                    "candidateWalkerEmail": None,
                    "liveStartedAt": None,
                    "completedAt": None,
                    "updatedAt": now,
                    "applications": updated_apps,
                }
            },
        )

        if w.get("chatId"):
            chats.update_one(
                {"_id": w["chatId"]},
                {"$set": {"status": "active", "updatedAt": now}},
            )
        w = walks.find_one({"_id": oid})
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "item": clean_walk(w)}), 200


@app.post("/api/walks/<walk_id>/owner-decline")
@jwt_required()
def owner_decline_walk(walk_id):
    """
    Owner declines the candidate walker.
    The walk goes back to 'open' without a candidate.
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user.get("role") != "owner":
        return jsonify({"ok": False, "error": "Only owners can decline walkers."}), 403

    owner_email = user["email"]
    oid = safe_oid(walk_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid walk id."}), 400

    w = walks.find_one({"_id": oid, "ownerEmail": owner_email})
    if not w:
        return jsonify({"ok": False, "error": "Walk not found for this owner."}), 404

    if w.get("status") != "pending_owner" or not w.get("candidateWalkerEmail"):
        return jsonify({"ok": False, "error": "No walker candidate to decline."}), 400

    candidate = w.get("candidateWalkerEmail")
    applications = w.get("applications") or []
    now = now_iso()
    updated_apps = []
    if not applications and candidate:
        updated_apps.append({
            "_id": ObjectId(),
            "walkerEmail": candidate,
            "status": "declined",
            "chatId": w.get("chatId"),
            "createdAt": w.get("createdAt"),
            "updatedAt": now,
        })
    else:
        for app in applications:
            entry = dict(app)
            if entry.get("walkerEmail") == candidate and entry.get("status") == "pending_owner":
                entry["status"] = "declined"
                entry["updatedAt"] = now
            updated_apps.append(entry)

    try:
        walks.update_one(
            {"_id": oid},
            {
                "$set": {
                    "status": "open",
                    "candidateWalkerEmail": None,
                    "walkerEmail": None,
                    "liveStartedAt": None,
                    "updatedAt": now,
                    "applications": updated_apps,
                }
            },
        )
        if w.get("chatId"):
            chats.update_one(
                {"_id": w["chatId"]},
                {"$set": {"status": "declined", "updatedAt": now}},
            )
        w = walks.find_one({"_id": oid})
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "item": clean_walk(w)}), 200


@app.post("/api/walks/<walk_id>/cancel")
@jwt_required()
def owner_cancel_walk(walk_id):
    """
    Owner cancels the walk (before or after matching).
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user.get("role") != "owner":
        return jsonify({"ok": False, "error": "Only owners can cancel walks."}), 403

    owner_email = user["email"]
    oid = safe_oid(walk_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid walk id."}), 400

    w = walks.find_one({"_id": oid, "ownerEmail": owner_email})
    if not w:
        return jsonify({"ok": False, "error": "Walk not found for this owner."}), 404

    if w.get("status") not in {"open", "pending_owner", "ready"}:
        return jsonify({"ok": False, "error": "Only open, pending, or ready walks can be canceled."}), 400

    applications = w.get("applications") or []
    now = now_iso()
    updated_apps = []
    for app in applications:
        entry = dict(app)
        if entry.get("status") in {"pending_owner", "accepted"}:
            entry["status"] = "canceled"
            entry["updatedAt"] = now
        updated_apps.append(entry)

    try:
        walks.update_one(
            {"_id": oid},
            {
                "$set": {
                    "status": "canceled",
                    "walkerEmail": None,
                    "candidateWalkerEmail": None,
                    "liveStartedAt": None,
                    "updatedAt": now,
                    "applications": updated_apps,
                }
            },
        )
        if w.get("chatId"):
            chats.update_one(
                {"_id": w["chatId"]},
                {"$set": {"status": "closed", "updatedAt": now}},
            )
        w = walks.find_one({"_id": oid})
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "item": clean_walk(w)}), 200


@app.post("/api/walks/<walk_id>/start")
@jwt_required()
def walker_start_walk(walk_id):
    """
    Walker starts an assigned walk.
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user.get("role") != "walker":
        return jsonify({"ok": False, "error": "Only walkers can start walks."}), 403

    walker_email = user["email"]
    oid = safe_oid(walk_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid walk id."}), 400

    w = walks.find_one({"_id": oid, "walkerEmail": walker_email})
    if not w:
        return jsonify({"ok": False, "error": "Walk not found for this walker."}), 404

    if w.get("status") != "ready":
        return jsonify({"ok": False, "error": "Walk is not ready to start."}), 400

    now = now_iso()
    try:
        walks.update_one(
            {"_id": oid},
            {
                "$set": {
                    "status": "live",
                    "liveStartedAt": now,
                    "updatedAt": now,
                }
            }
        )
        w = walks.find_one({"_id": oid})
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "item": clean_walk(w)}), 200


@app.post("/api/walks/<walk_id>/pause")
@jwt_required()
def walker_pause_walk(walk_id):
    """
    Walker pauses an ongoing walk.
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user.get("role") != "walker":
        return jsonify({"ok": False, "error": "Only walkers can pause walks."}), 403

    walker_email = user["email"]
    oid = safe_oid(walk_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid walk id."}), 400

    w = walks.find_one({"_id": oid, "walkerEmail": walker_email})
    if not w:
        return jsonify({"ok": False, "error": "Walk not found for this walker."}), 404

    if w.get("status") != "live":
        return jsonify({"ok": False, "error": "Only live walks can be paused."}), 400

    now = now_iso()
    try:
        walks.update_one(
            {"_id": oid},
            {"$set": {"status": "paused", "updatedAt": now}}
        )
        w = walks.find_one({"_id": oid})
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "item": clean_walk(w)}), 200


@app.post("/api/walks/<walk_id>/resume")
@jwt_required()
def walker_resume_walk(walk_id):
    """
    Walker resumes a paused walk.
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user.get("role") != "walker":
        return jsonify({"ok": False, "error": "Only walkers can resume walks."}), 403

    walker_email = user["email"]
    oid = safe_oid(walk_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid walk id."}), 400

    w = walks.find_one({"_id": oid, "walkerEmail": walker_email})
    if not w:
        return jsonify({"ok": False, "error": "Walk not found for this walker."}), 404

    if w.get("status") != "paused":
        return jsonify({"ok": False, "error": "Only paused walks can be resumed."}), 400

    now = now_iso()
    try:
        walks.update_one(
            {"_id": oid},
            {"$set": {"status": "live", "updatedAt": now}}
        )
        w = walks.find_one({"_id": oid})
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "item": clean_walk(w)}), 200


@app.post("/api/walks/<walk_id>/complete")
@jwt_required()
def walker_complete_walk(walk_id):
    """
    Walker marks the walk as completed.
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user.get("role") != "walker":
        return jsonify({"ok": False, "error": "Only walkers can complete walks."}), 403

    walker_email = user["email"]
    oid = safe_oid(walk_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid walk id."}), 400

    w = walks.find_one({"_id": oid, "walkerEmail": walker_email})
    if not w:
        return jsonify({"ok": False, "error": "Walk not found for this walker."}), 404

    if w.get("status") not in {"live", "paused"}:
        return jsonify({"ok": False, "error": "Walk must be live or paused to complete."}), 400

    now = now_iso()
    try:
        walks.update_one(
            {"_id": oid},
            {"$set": {"status": "completed", "completedAt": now, "updatedAt": now}}
        )
        if w.get("chatId"):
            chats.update_one(
                {"_id": w["chatId"]},
                {"$set": {"status": "closed", "updatedAt": now}}
            )
        w = walks.find_one({"_id": oid})
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "item": clean_walk(w)}), 200


@app.post("/api/walks/<walk_id>/location")
@jwt_required()
def walker_post_location(walk_id):
    """
    Walker posts current GPS point.
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user.get("role") != "walker":
        return jsonify({"ok": False, "error": "Only walkers can update location."}), 403

    walker_email = user["email"]
    oid = safe_oid(walk_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid walk id."}), 400

    w = walks.find_one({"_id": oid, "walkerEmail": walker_email})
    if not w:
        return jsonify({"ok": False, "error": "Walk not found for this walker."}), 404

    if w.get("status") not in {"live", "paused"}:
        return jsonify({"ok": False, "error": "Walk must be live or paused to record location."}), 400

    data = request.get_json(silent=True) or {}
    lat = data.get("latitude")
    lon = data.get("longitude")
    if lat is None or lon is None:
        return jsonify({"ok": False, "error": "latitude and longitude are required."}), 400
    try:
        lat = float(lat)
        lon = float(lon)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "latitude and longitude must be numbers."}), 400

    captured_dt = datetime.now(timezone.utc)
    captured_iso = captured_dt.isoformat()
    doc = {
        "walkId": oid,
        "walkerEmail": walker_email,
        "latitude": lat,
        "longitude": lon,
        "capturedAt": captured_dt,
    }

    prev = w.get("lastLocation") or walk_locations.find_one(
        {"walkId": oid}, sort=[("capturedAt", -1)]
    )
    delta = 0.0
    if prev:
        delta = haversine_meters(
            prev.get("latitude"),
            prev.get("longitude"),
            lat,
            lon
        )

    total_distance = (w.get("distanceMeters") or 0) + delta

    try:
        res = walk_locations.insert_one(doc)
        doc["_id"] = res.inserted_id
        walks.update_one(
            {"_id": oid},
            {
                "$set": {
                    "lastLocation": {
                        "latitude": lat,
                        "longitude": lon,
                        "capturedAt": captured_iso,
                        "id": str(res.inserted_id),
                    },
                    "distanceMeters": total_distance,
                    "updatedAt": captured_iso,
                }
            },
        )
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({
        "ok": True,
        "location": clean_location(doc),
        "distanceMeters": total_distance,
    }), 201


@app.get("/api/walks/<walk_id>/locations")
@jwt_required()
def list_walk_locations(walk_id):
    """
    Owner/walker fetches recorded GPS points.
    Optional query: ?since=<ISO8601>
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404

    oid = safe_oid(walk_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid walk id."}), 400

    w = walks.find_one({"_id": oid})
    if not w:
        return jsonify({"ok": False, "error": "Walk not found."}), 404

    email = user["email"]
    if email not in {w.get("ownerEmail"), w.get("walkerEmail")}:
        return jsonify({"ok": False, "error": "Forbidden."}), 403

    since_param = request.args.get("since")
    query = {"walkId": oid}
    if since_param:
        since_dt = parse_iso_datetime(since_param)
        if not since_dt:
            return jsonify({"ok": False, "error": "Invalid 'since' timestamp."}), 400
        query["capturedAt"] = {"$gt": since_dt.astimezone(timezone.utc)}

    cur = walk_locations.find(query).sort("capturedAt", ASCENDING)
    items = [clean_location(doc) for doc in cur]
    return jsonify({
        "ok": True,
        "items": items,
        "distanceMeters": w.get("distanceMeters", 0),
    }), 200


# ------------------------------------------------------------
# Chats & Messages
# ------------------------------------------------------------

@app.get("/api/chats")
@jwt_required()
def list_chats():
    """
    List chats for current user (owner or walker).
    Returns items enriched with lastMessage, unreadOwner/unreadWalker, dogName.
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404

    email = user["email"]

    cur = chats.find({
        "$or": [
            {"ownerEmail": email},
            {"walkerEmail": email},
        ]
    }).sort("updatedAt", -1)  # newest first

    return jsonify({
        "ok": True,
        "items": [clean_chat(c) for c in cur],
    }), 200


@app.get("/api/chats/<chat_id>")
@jwt_required()
def get_chat(chat_id):
    """
    Get single chat (only participants can see it).
    Returns item enriched with lastMessage, unreadOwner/unreadWalker, dogName.
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404

    email = user["email"]
    oid = safe_oid(chat_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid chat id."}), 400

    c = chats.find_one({"_id": oid})
    if not c:
        return jsonify({"ok": False, "error": "Chat not found."}), 404

    if email not in {c.get("ownerEmail"), c.get("walkerEmail")}:
        return jsonify({"ok": False, "error": "Forbidden."}), 403

    return jsonify({"ok": True, "item": clean_chat(c)}), 200


@app.post("/api/chats/<chat_id>/mark-read")
@jwt_required()
def mark_chat_read(chat_id):
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404

    email = user["email"]
    role = user.get("role")
    oid = safe_oid(chat_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid chat id."}), 400

    c = chats.find_one({"_id": oid})
    if not c:
        return jsonify({"ok": False, "error": "Chat not found."}), 404

    if email not in {c.get("ownerEmail"), c.get("walkerEmail")}:
        return jsonify({"ok": False, "error": "Forbidden."}), 403

    if role == "owner":
        update = {"$set": {"unreadOwner": 0}}
    else:
        update = {"$set": {"unreadWalker": 0}}

    try:
        chats.update_one({"_id": oid}, update)
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True}), 200


@app.get("/api/chats/<chat_id>/messages")
@jwt_required()
def list_chat_messages(chat_id):
    """
    Get all messages for a chat (ordered oldest -> newest).
    Only owner/walker for this chat can access.
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404

    email = user["email"]
    oid = safe_oid(chat_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid chat id."}), 400

    c = chats.find_one({"_id": oid})
    if not c:
        return jsonify({"ok": False, "error": "Chat not found."}), 404

    if email not in {c.get("ownerEmail"), c.get("walkerEmail")}:
        return jsonify({"ok": False, "error": "Forbidden."}), 403

    cur = messages.find({"chatId": oid}).sort("createdAt", ASCENDING)

    return jsonify({
        "ok": True,
        "items": [clean_message(m) for m in cur],
    }), 200


@app.post("/api/chats/<chat_id>/messages")
@jwt_required()
def send_chat_message(chat_id):
    """
    Send a message in a chat.

    Body:
    Text:
      { "text": "Hi!" }

    Photo (base64):
      {
        "type": "photo",
        "imageBase64": "<BASE64 STRING>",
        "mime": "image/jpeg"  # optional, default image/jpeg
      }

    Location:
      {
        "type": "location",
        "latitude": 49.8397,
        "longitude": 24.0297,
        "title": "View Location"
      }
    """
    user = get_current_user_doc()
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404

    email = user["email"]
    role = user.get("role")
    oid = safe_oid(chat_id)
    if not oid:
        return jsonify({"ok": False, "error": "Invalid chat id."}), 400

    c = chats.find_one({"_id": oid})
    if not c:
        return jsonify({"ok": False, "error": "Chat not found."}), 404

    if email not in {c.get("ownerEmail"), c.get("walkerEmail")}:
        return jsonify({"ok": False, "error": "Forbidden."}), 403

    if c.get("status") in ["closed", "declined"]:
        return jsonify({"ok": False, "error": "Chat is closed."}), 400

    data = request.get_json(silent=True) or {}
    msg_type = (data.get("type") or "").lower().strip()
    created_at = now_iso()

    msg_doc = {
        "chatId": oid,
        "walkId": c.get("walkId"),
        "senderEmail": email,
        "senderRole": role,
        "createdAt": created_at,
    }

    if msg_type == "photo":
        image_b64 = data.get("imageBase64")
        mime = (data.get("mime") or "image/jpeg").lower()
        if not image_b64:
            return jsonify({"ok": False, "error": "imageBase64 is required"}), 400
        try:
            base64.b64decode(image_b64, validate=True)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid base64"}), 400
        msg_doc.update({
            "type": "photo",
            "imageBase64": image_b64,
            "mime": mime,
            "text": "[photo]"  # for legacy clients and list previews
        })

    elif msg_type == "location":
        lat = data.get("latitude")
        lon = data.get("longitude")
        title = (data.get("title") or "View Location").strip()
        if lat is None or lon is None:
            return jsonify({"ok": False, "error": "latitude and longitude are required"}), 400
        msg_doc.update({
            "type": "location",
            "latitude": float(lat),
            "longitude": float(lon),
            "title": title,
            "text": "[location]"  # legacy fallback
        })

    else:
        text = (data.get("text") or "").strip()
        if not text:
            return jsonify({"ok": False, "error": "Message text is required."}), 400
        msg_doc["type"] = "text"
        msg_doc["text"] = text

    # Build preview for chat list
    if msg_type == "photo":
        preview_text = "[photo]"
    elif msg_type == "location":
        preview_text = "[location]"
    else:
        preview_text = msg_doc.get("text", "")

    # Increment unread for the recipient
    inc_update = {}
    if role == "owner":
        inc_update["unreadWalker"] = 1
    else:
        inc_update["unreadOwner"] = 1

    try:
        res = messages.insert_one(msg_doc)
        msg_doc["_id"] = res.inserted_id

        chats.update_one(
            {"_id": oid},
            {
                "$set": {"updatedAt": created_at, "lastMessage": preview_text},
                "$inc": inc_update
            }
        )
    except mongo_errors.PyMongoError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "item": clean_message(msg_doc)}), 201


# ------------------------------------------------------------
# Health
# ------------------------------------------------------------
@app.get("/health")
def health():
    return {"ok": True, "service": "dogwalk-backend", "time": now_iso()}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=os.getenv("FLASK_ENV") == "development")
