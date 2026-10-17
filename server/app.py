import os
import re
from functools import wraps
from pathlib import Path

import firebase_admin

from firebase_admin import auth, firestore

from flask import (
    Flask,
    g,
    jsonify,
    request,
    send_from_directory,
)

from google.api_core.exceptions import AlreadyExists


PROJECT_ID = "smart-campus-9aafa"

firebase_admin.initialize_app(
    options={
        "projectId": PROJECT_ID,
    }
)

db = firestore.client()

PUBLIC_DIRECTORY = (
    Path(__file__).resolve().parent.parent / "public"
)

app = Flask(
    __name__,
    static_folder=None,
)

app.config["MAX_CONTENT_LENGTH"] = 32 * 1024


# --------------------------------------------------
# Administrator authentication
# --------------------------------------------------

def require_admin(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        authorization = request.headers.get(
            "Authorization", ""
        )

        if not authorization.startswith("Bearer "):
            return jsonify(
                ok=False,
                message="Please sign in as administrator.",
            ), 401

        token = authorization[7:]

        try:
            decoded = auth.verify_id_token(
                token,
                check_revoked=True,
            )

        except (
            ValueError,
            firebase_admin.exceptions.FirebaseError,
        ):
            return jsonify(
                ok=False,
                message="Session expired. Please sign in again.",
            ), 401

        snapshot = (
            db.collection("users")
            .document(decoded["uid"])
            .get()
        )

        profile = (
            snapshot.to_dict()
            if snapshot.exists
            else {}
        )

        if (
            profile.get("role") != "admin"
            or profile.get("active") is not True
        ):
            return jsonify(
                ok=False,
                message=(
                    "An active administrator account is required."
                ),
            ), 403

        g.admin_uid = decoded["uid"]

        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------
# Validation
# --------------------------------------------------

def read_json():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        raise ValueError("Send a valid JSON object.")

    return data


def read_text(
    data,
    key,
    maximum,
    required=False,
):
    value = data.get(key, "")

    if not isinstance(value, str):
        raise ValueError(
            f"Enter a valid {key}."
        )

    value = value.strip()

    if len(value) > maximum:
        raise ValueError(
            f"{key}: maximum {maximum} characters."
        )

    if required and not value:
        raise ValueError(
            f"{key} is required."
        )

    return value


def read_teacher_details(data):
    email = read_text(
        data,
        "email",
        254,
        required=True,
    ).lower()

    if not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email,
    ):
        raise ValueError(
            "Enter a valid email address."
        )

    return {
        "name": read_text(
            data,
            "name",
            100,
            required=True,
        ),

        "teacher_no": read_text(
            data,
            "teacher_no",
            80,
            required=True,
        ),

        "email": email,

        "department": read_text(
            data,
            "department",
            150,
        ),

        "phone": read_text(
            data,
            "phone",
            150,
        ),

        "designation": read_text(
            data,
            "designation",
            150,
        ),
    }


def read_password(data):
    password = data.get(
        "new_password", ""
    )

    confirmation = data.get(
        "confirm_password", ""
    )

    if (
        not isinstance(password, str)
        or not 8 <= len(password) <= 128
    ):
        raise ValueError(
            "Password must contain 8–128 characters."
        )

    if password != confirmation:
        raise ValueError(
            "Passwords do not match."
        )

    return password


def find_teacher(uid):
    snapshot = (
        db.collection("users")
        .document(uid)
        .get()
    )

    profile = (
        snapshot.to_dict()
        if snapshot.exists
        else {}
    )

    if profile.get("role") != "teacher":
        return None

    return profile


# --------------------------------------------------
# Error responses
# --------------------------------------------------

@app.errorhandler(ValueError)
def validation_error(error):
    return jsonify(
        ok=False,
        message=str(error),
    ), 400


@app.errorhandler(auth.EmailAlreadyExistsError)
def email_exists(error):
    return jsonify(
        ok=False,
        message=(
            "This email is already in use. "
            "No existing account was changed."
        ),
    ), 409


@app.errorhandler(auth.UserNotFoundError)
def account_not_found(error):
    return jsonify(
        ok=False,
        message="Firebase login account was not found.",
    ), 404


@app.errorhandler(
    firebase_admin.exceptions.FirebaseError
)
def firebase_error(error):
    return jsonify(
        ok=False,
        message=(
            "Firebase could not complete the request. "
            "Check the server connection and permissions."
        ),
    ), 503


@app.after_request
def response_headers(response):
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    return response


# --------------------------------------------------
# Create teacher
# --------------------------------------------------

@app.post("/api/teachers")
@require_admin
def create_teacher():
    data = read_json()

    details = read_teacher_details(data)
    password = read_password(data)

    request_id = data.get(
        "request_id", ""
    )

    if (
        not isinstance(request_id, str)
        or not re.fullmatch(
            r"[a-f0-9]{32}",
            request_id,
        )
    ):
        raise ValueError(
            "Refresh the form before creating an account."
        )

    # Same request ID prevents duplicate creation on retry.
    uid = "teacher-" + request_id

    reference = (
        db.collection("users")
        .document(uid)
    )

    existing = reference.get()

    if existing.exists:
        current = existing.to_dict()

        if (
            current.get("role") != "teacher"
            or current.get("created_by") != g.admin_uid
            or current.get("creation_request") != request_id
            or current.get("email") != details["email"]
        ):
            return jsonify(
                ok=False,
                message=(
                    "Account operation does not match. "
                    "No profile was changed."
                ),
            ), 409

        account = auth.get_user(uid)

        if account.disabled:
            if current.get("provisioning") != "pending":
                return jsonify(
                    ok=False,
                    message=(
                        "This account is disabled. "
                        "Use Settings to enable it."
                    ),
                ), 409

            auth.update_user(
                uid,
                disabled=False,
            )

            reference.update({
                "provisioning": "complete",
            })

        return jsonify(
            ok=True,
            uid=uid,
            message=(
                "Teacher account created successfully."
            ),
        )

    try:
        auth.create_user(
            uid=uid,
            email=details["email"],
            password=password,
            display_name=details["name"],
            disabled=True,
        )

    except auth.UidAlreadyExistsError:
        # Recover an interrupted creation.
        account = auth.get_user(uid)

        if (
            not account.disabled
            or account.email.lower() != details["email"]
        ):
            return jsonify(
                ok=False,
                message=(
                    "A different login account already "
                    "exists for this operation."
                ),
            ), 409

        auth.update_user(
            uid,
            password=password,
            display_name=details["name"],
        )

    try:
        reference.create({
            **details,

            "role": "teacher",
            "active": True,

            "created_by": g.admin_uid,
            "creation_request": request_id,

            "created_at": (
                firestore.SERVER_TIMESTAMP
            ),

            "provisioning": "pending",
        })

    except AlreadyExists:
        current = (
            reference.get().to_dict() or {}
        )

        if (
            current.get("created_by") != g.admin_uid
            or current.get("creation_request") != request_id
        ):
            return jsonify(
                ok=False,
                message=(
                    "Account creation conflict. "
                    "Refresh before retrying."
                ),
            ), 409

    except Exception:
        return jsonify(
            ok=False,
            message=(
                "Login reserved but profile saving failed. "
                "Keep the same form and retry. "
                "The login remains disabled until setup finishes."
            ),
        ), 503

    auth.update_user(
        uid,
        disabled=False,
    )

    reference.update({
        "provisioning": "complete",
    })

    return jsonify(
        ok=True,
        uid=uid,
        message="Teacher account created successfully.",
    )


# --------------------------------------------------
# Update teacher details and email
# --------------------------------------------------

@app.post("/api/teachers/<uid>/account")
@require_admin
def update_teacher_account(uid):
    current = find_teacher(uid)

    if current is None:
        return jsonify(
            ok=False,
            message="Teacher not found.",
        ), 404

    data = read_json()

    details = read_teacher_details(data)

    active = data.get("active")

    if not isinstance(active, bool):
        raise ValueError(
            "Choose a valid account status."
        )

    changes = {
        "email": details["email"],
        "display_name": details["name"],
        "disabled": not active,
    }

    email_changed = (
        current.get("email")
        != details["email"]
    )

    if email_changed:
        changes["email_verified"] = False

    auth.update_user(
        uid,
        **changes,
    )

    try:
        (
            db.collection("users")
            .document(uid)
            .update({
                **details,
                "active": active,
            })
        )

    except Exception:
        return jsonify(
            ok=False,
            message=(
                "Login details changed, but profile "
                "synchronization failed. "
                "Retry Save with the same values."
            ),
        ), 503

    if not active or email_changed:
        auth.revoke_refresh_tokens(uid)

    return jsonify(
        ok=True,
        message="Teacher account updated successfully.",
    )


# --------------------------------------------------
# Active / Inactive
# --------------------------------------------------

@app.post("/api/teachers/<uid>/status")
@require_admin
def update_teacher_status(uid):
    if find_teacher(uid) is None:
        return jsonify(
            ok=False,
            message="Teacher not found.",
        ), 404

    data = read_json()

    active = data.get("active")

    if not isinstance(active, bool):
        raise ValueError(
            "Choose a valid account status."
        )

    auth.update_user(
        uid,
        disabled=not active,
    )

    try:
        (
            db.collection("users")
            .document(uid)
            .update({
                "active": active,
            })
        )

    except Exception:
        return jsonify(
            ok=False,
            message=(
                "Login status changed, but profile "
                "status could not synchronize. "
                "Retry the same status."
            ),
        ), 503

    if not active:
        auth.revoke_refresh_tokens(uid)

    return jsonify(
        ok=True,
        message=(
            "Teacher enabled successfully."
            if active
            else "Teacher disabled successfully."
        ),
    )


# --------------------------------------------------
# Reset teacher password
# --------------------------------------------------

@app.post("/api/teachers/<uid>/password")
@require_admin
def reset_teacher_password(uid):
    if find_teacher(uid) is None:
        return jsonify(
            ok=False,
            message="Teacher not found.",
        ), 404

    data = read_json()

    password = read_password(data)

    auth.update_user(
        uid,
        password=password,
    )

    auth.revoke_refresh_tokens(uid)

    return jsonify(
        ok=True,
        message=(
            "Teacher password reset successfully. "
            "They must sign in with the new password."
        ),
    )


# --------------------------------------------------
# Serve the existing frontend
# --------------------------------------------------

@app.get("/")
def home():
    return send_from_directory(
        PUBLIC_DIRECTORY,
        "login.html",
    )


@app.get("/<path:path>")
def public_file(path):
    if path.startswith("api/"):
        return jsonify(
            ok=False,
            message="API route not found.",
        ), 404

    if path.endswith("/"):
        path += "index.html"

    return send_from_directory(
        PUBLIC_DIRECTORY,
        path,
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(
            os.environ.get("PORT", "5003")
        ),
        debug=False,
    )