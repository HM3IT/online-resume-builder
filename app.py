import os
import uuid
import json
import time
import requests
import cohere
import secrets
from urllib.parse import urlencode
from dotenv import load_dotenv


from db import get_session, init_db
from tables import Resume, Template, User
from models import SignUp, SignIn

from utils import (
    add_address,
    get_template,
    replace_newlines,
    get_sample_resume,
    save_template_file,
    save_profile_image,
    create_education_instances,
    create_language_instances,
    create_social_media_instances,
    create_skill_instances,
    create_work_experience_instances,
    extract_json,
)

from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
from sqlalchemy.orm.exc import NoResultFound
from bcrypt import hashpw, gensalt, checkpw
from flask import (
    Flask,
    request,
    render_template,
    jsonify,
    send_from_directory,
    current_app,
    redirect,
    url_for,
    session,
    abort,
    flash,
    make_response,
)

load_dotenv()

app = Flask("Resume-builder")

app.jinja_env.filters["replace_newlines"] = replace_newlines

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DB_URI"]
db = SQLAlchemy(app)
app.config["SECRET_KEY"] = secrets.token_hex(16)
app.config["OAUTH2_PROVIDERS"] = {
    # Google OAuth 2.0 documentation:
    # https://developers.google.com/identity/protocols/oauth2/web-server#httprest
    "google": {
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
        "authorize_url": "https://accounts.google.com/o/oauth2/auth",
        "token_url": "https://accounts.google.com/o/oauth2/token",
        "userinfo": {
            "url": "https://www.googleapis.com/oauth2/v3/userinfo",
            "email": lambda json: json["email"],
        },
        "scopes": ["https://www.googleapis.com/auth/userinfo.email"],
    }
}
login_manager = LoginManager()
login_manager.init_app(app)
# redirect to signup page if not auntenticated
# login_manager.login_view = "render_signup_page"

# ============================================
#  ==== OAuth2.0 Setup for Authentication ====
# ============================================
"""
OAuth2.0 Setup
Adapted from: "OAuth Authentication with Flask in 2023" by Miguel Grinberg
https://blog.miguelgrinberg.com/post/oauth-authentication-with-flask-in-2023

"""


@app.route("/authorize/<provider>")
def oauth2_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for("index"))

    provider_data = current_app.config["OAUTH2_PROVIDERS"].get(provider)
    if provider_data is None:
        abort(404)

    # generate a random string for the state parameter
    session["oauth2_state"] = secrets.token_urlsafe(16)

    # create a query string with all the OAuth2 parameters
    redirect_uri = url_for("oauth2_callback", provider=provider, _external=True)
    print("redirect_uri")
    print(redirect_uri)
    query_str = urlencode(
        {
            "client_id": provider_data["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(provider_data["scopes"]),
            "state": session["oauth2_state"],
        }
    )

    # redirect the user to the OAuth2 provider authorization URL
    return redirect(provider_data["authorize_url"] + "?" + query_str)


@app.route("/callback/<provider>")
def oauth2_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for("index"))

    provider_data = current_app.config["OAUTH2_PROVIDERS"].get(provider)
    if provider_data is None:
        abort(404)

    # if there was an authentication error, flash the error messages and exit
    if "error" in request.args:
        for k, v in request.args.items():
            if k.startswith("error"):
                flash(f"{k}: {v}")
        return redirect(url_for("index"))

    # make sure that the state parameter matches the one we created in the
    # authorization request
    if request.args["state"] != session.get("oauth2_state"):
        abort(401)

    # make sure that the authorization code is present
    if "code" not in request.args:
        abort(401)

    redirect_uri = url_for("oauth2_callback", provider=provider, _external=True)

    # exchange the authorization code for an access token
    response = requests.post(
        provider_data["token_url"],
        data={
            "client_id": provider_data["client_id"],
            "client_secret": provider_data["client_secret"],
            "code": request.args["code"],
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        },
        headers={"Accept": "application/json"},
    )
    if response.status_code != 200:
        abort(401)
    oauth2_token = response.json().get("access_token")
    if not oauth2_token:
        abort(401)

    # use the access token to get the user's email address
    response = requests.get(
        provider_data["userinfo"]["url"],
        headers={
            "Authorization": "Bearer " + oauth2_token,
            "Accept": "application/json",
        },
    )
    if response.status_code != 200:
        abort(401)
    email = provider_data["userinfo"]["email"](response.json())

    # find or create the user in the database
    try:
        with get_session() as db_session:
            user = db_session.query(User).filter(User.email == email).first()

            if user is None:
                user = User(
                    name=email.split("@")[0],
                    email=email,
                )
                db_session.add(user)
                db_session.commit()

            # Log the user in
            login_user(user)
            return redirect(url_for("index"))
    except Exception as e:

        print(f"Error occurred: {e}")
        return "Failed to login", 500


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.context_processor
def inject_user():
    return dict(user=current_user)


# =================================
# ====APIs for Authentication =====
# =================================
@login_manager.unauthorized_handler
def unauthorized_callback():
    flash("Please Log in first or create an accout to build your Resume.", "warning")
    return redirect(url_for("render_signup_page"))


@app.route("/signup", methods=["POST"])
def signup():
    try:

        data = request.json
        signup_data = SignUp(**data)
        signup_data.validate()

        hashed_password = hashpw(signup_data.password.encode("utf-8"), gensalt())
        with get_session() as db_session:
            existing_user = (
                db_session.query(User).filter(User.email == signup_data.email).first()
            )
            if existing_user:
                return jsonify({"error": "User already exists"}), 409

            new_user = User(
                name=signup_data.name,
                email=signup_data.email,
                password=hashed_password.decode("utf-8"),
            )
            db_session.add(new_user)
            db_session.commit()
            login_user(new_user)

        return jsonify({"message": "Sign up successful"}), 201

    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    except Exception:
        return jsonify({"error": "Something went wrong"}), 500


@app.route("/signin", methods=["POST"])
def signin():
    try:
        data = request.json

        signin_data = SignIn(**data)
        signin_data.validate()

        with get_session() as db_session:
            user = (
                db_session.query(User).filter(User.email == signin_data.email).first()
            )

            if user:
                if checkpw(
                    signin_data.password.encode("utf-8"), user.password.encode("utf-8")
                ):
                    login_user(user)
                    return jsonify({"message": "Sign In successful"}), 200
                else:
                    return jsonify({"message": "Wrong email or password!"}), 401
            else:
                return jsonify({"message": "User not found!"}), 404

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "Something went wrong"}), 500


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("index"))


@app.route("/users/update", methods=["PUT"])
@login_required
def update_user_profile():
    user_id = request.form.get("id")
    new_name = request.form.get("name")

    with get_session() as db_session:
        user = db_session.query(User).get(user_id)

        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        user.name = new_name

        if "profile-image" in request.files:
            profile_img_file = request.files["profile-image"]
            if profile_img_file.filename != "":
                profile_folder_path = os.environ.get("PROFILE_FILE_PATH")
                file_name, file_path = save_profile_image(
                    file=profile_img_file, upload_folder_path=profile_folder_path
                )
                if file_name is None:
                    return (
                        jsonify({"success": False, "message": "Invalid file type"}),
                        400,
                    )

                user.profile_path = file_name

        db_session.commit()
        updated_data = {"name": user.name, "profile_path": user.profile_path}
        return jsonify({"success": True, "user": updated_data}), 200


# ============================================
# ====APIs for Cohere AI Text generation =====
# ============================================


@app.route("/contents/generate", methods=["POST"])
@login_required
def content_generator():
    """This API is retrieved text from the public API hosted by cohere
    command-light model is used  as it is the least token consume model.
    Other available models for text generation in Cohere include but not used due to token consumption:
    command-light-nightly, command-xlarge (Best for extensive text generation)
    and command-xlarge-nightly (Latest version of the xlarge model)
    """
    # Increase the 'retries' variable to ensure a valid response from text generation.
    retries = 2
    req_json = request.json
    section = req_json.get("section")
    profession = req_json.get("profession")
    if section is None or profession is None:
        return (
            jsonify(
                {"message": "section and profession must be included in the request!"}
            ),
            400,
        )

    prompt_template = os.getenv("PROMPT_TEMPLATE", "")

    if section == "skill":
        section = "skills that I should have"

    prompt = prompt_template.format(profession=profession, section=section)

    try:
        client = cohere.Client(os.environ.get("COHERE_API_KEY"))

        for i in range(0, retries):
            response = client.generate(
                model="command-light",
                prompt=prompt,
                max_tokens=105,
                temperature=0.2,
            )
            result = response.generations[0].text
            # result = """
            # ```json
            # [
            # "Collaborated with a team of engineers to design and implement advanced software solutions.",
            # "Solved complex technical issues through innovative coding methodologies and frameworks.",
            # "Assisted in creating robust software architectures and frameworks.",
            # "Conducted thorough code reviews and provided feedback to team members."
            # ]
            # """
            print("Response")
            print(result)
            result_list = extract_json(result)
            if result_list and len(result_list) > 0:
                break

        return (
            jsonify({"message": "Resume created successfully!", "result": result_list}),
            200,
        )

    except Exception as e:
        print(f"Error: {e}")
        return (
            jsonify({"message": "Free token usage exceeded"}),
            200,
        )


# =======================================
# ===========  APIs for Resume ==========
# =======================================
@app.route("/resume", methods=["POST"])
@login_required
def create_resume():
    with get_session() as db_session:

        data = request.json

        heading_info = data.get("headingInfo")
        work_exp_info = data.get("workExpInfo")
        template_info = data.get("templateInfo")
        education_info = data.get("eduInfo")
        skill_info = data.get("skillInfo")
        summary = data.get("summary")
        additional_info = data.get("additionalInfo")

        # JSON parsing
        heading = json.loads(heading_info)
        work_experiences = json.loads(work_exp_info)
        template_data = json.loads(template_info)
        educations = json.loads(education_info)
        skills = json.loads(skill_info)
        if additional_info:

            additional_data = json.loads(additional_info)
            social_media = additional_data.get("socialMediaInfo")
            languages = additional_data.get("langInfo")

        owner: User = current_user
        user_id = str(owner.id)

        address_id = add_address(db_session, heading["city"], heading["country"])
        resume_id = str(uuid.uuid4())
        profile_file_name = heading.get("profile_file_name")
        if profile_file_name:
            file_path = f"images/profile/{profile_file_name}"
        else:
            file_path = ""
        resume = Resume(
            id=resume_id,
            template_id=template_data["templateId"],
            template_theme=template_data["templateTheme"],
            user_id=user_id,
            username=heading["username"],
            profession=heading["profession"],
            phone=heading.get("phone"),
            is_headshot=template_data.get("isHeadshot", False),
            image_file_path=file_path,
            email=heading["email"],
            address_id=address_id,
            summary=summary,
        )
        if social_media:
            social_media = create_social_media_instances(
                resume_id=resume_id, data=social_media
            )
            resume.social_media = social_media
        if languages and len(languages) > 0:
            languages = create_language_instances(resume_id=resume_id, data=languages)
            resume.languages = languages

        resume.work_experiences = create_work_experience_instances(
            resume_id=resume_id, data=work_experiences
        )
        resume.educations = create_education_instances(
            resume_id=resume_id, data=educations
        )
        resume.skills = create_skill_instances(resume_id, skills)
        resume.template = get_template(
            session=db_session, template_id=template_data["templateId"]
        )

        try:
            db_session.add(resume)
            db_session.commit()

            return (
                jsonify(
                    {"message": "Resume created successfully!", "resume_id": resume_id}
                ),
                201,
            )

        except Exception as err:

            print(err)
            abort(500, description="An error occurred while processing the request")

    return resume, 200


@app.route("/profile/<string:file_name>", methods=["GET"])
def get_profile(file_name: str):
    if file_name == "":
        return jsonify({"success": False, "message": "Invalid file type"}), 400

    profile_folder_path = os.environ.get("PROFILE_FILE_PATH")

    try:
        return send_from_directory(profile_folder_path, file_name)
    except FileNotFoundError:
        return jsonify({"success": False, "message": "File not found"}), 404


@app.route("/templates/<string:template_id>", methods=["GET"])
def get_template_html(template_id):

    template_path = f"templates/resume-templates/{template_id}.html"
    try:
        with open(template_path, "r") as file:
            template = file.read()
    except FileNotFoundError:
        return "Template not found", 404

    return template


# ========================================
# ====== APIs for file uploading =========
# ========================================


@app.route("/profile/upload", methods=["POST"])
def upload_profile():
    if "profile-image" not in request.files:
        return jsonify({"success": False, "message": "No File part"}), 400
    profile_img_file = request.files["profile-image"]

    profile_folder_path = os.environ.get("PROFILE_FILE_PATH")

    file_name, file_path = save_profile_image(
        file=profile_img_file, upload_folder_path=profile_folder_path
    )
    if file_name is None:
        return jsonify({"success": False, "message": "Invalid file type"}), 400

    return jsonify({"success": True, "file_name": file_name}), 200


@app.route("/template/upload", methods=["POST"])
def upload_template():

    if "template_file" not in request.files:
        return "Missing file part", 400

    template_file = request.files["template_file"]

    template_folder_path = os.environ.get("TEMPLATE_FILE_PATH")

    file_name, file_path = save_template_file(
        file=template_file, upload_folder_path=template_folder_path
    )

    # Remove the "template/" prefix as Jinja loading already handles it during file rendering
    file_path = file_path.replace("templates/", "", 1)
    if file_name is None:
        return "Invalid file type", 400

    with get_session() as db_session:
        try:
            template = Template(name=file_name, template_file_path=file_path)
            db_session.add(template)
            db_session.commit()

            return render_template(
                "template-uploader.html",
                contents={"message": "File uploaded successfully"},
            )
        except Exception as err:
            print(err)
            return "Failed to save file to db", 500


# ==================================================
# ====== APIs for Rendering front-end Pages ========
# ==================================================


@app.route("/")
@app.route("/home")
def index():
    DB_FILE_PATH = os.environ.get("DB_FILE_PATH")
    if not os.path.exists(DB_FILE_PATH):
        init_db()
    return render_template("index.html")


@app.route("/resume/section/select-template")
@login_required
def render_resume_template_page():

    with get_session() as db_session:
        template_instances = db_session.query(Template).all()
        contents = {"resumes": []}
        for template in template_instances:

            sample_resume = get_sample_resume(template=template)
            contents["resumes"].append(sample_resume)

        return render_template("template-resume.html", contents=contents)


@app.route("/resume/section/heading", methods=["GET"])
@login_required
def render_heading_page():
    template_id = request.args.get("template_id")
    if template_id is None:
        return jsonify({"message": "Template id must be included"}), 403

    with get_session() as db_session:
        template = get_template(db_session, template_id)

        sample_resume = get_sample_resume(template=template)
        return render_template("header-resume.html", resume=sample_resume)


@app.route("/resume/section/education", methods=["GET"])
@login_required
def render_education_page():
    template_id = request.args.get("template_id")
    if template_id is None:
        return jsonify({"message": "Template id must be included"}), 403

    with get_session() as db_session:
        template = get_template(db_session, template_id)

        sample_resume = get_sample_resume(template=template)
        return render_template("edu-resume.html", resume=sample_resume)


@app.route("/resume/section/work_experience", methods=["GET"])
@login_required
def render_work_experience_page():
    template_id = request.args.get("template_id")
    if template_id is None:
        return jsonify({"message": "Template id must be included"}), 403

    with get_session() as db_session:
        template = get_template(db_session, template_id)

        sample_resume = get_sample_resume(template=template)

        return render_template("work-exp-resume.html", resume=sample_resume)


@app.route("/resume/section/skill", methods=["GET"])
@login_required
def render_skill_page():
    template_id = request.args.get("template_id")
    if template_id is None:
        return jsonify({"message": "Template id must be included"}), 403

    with get_session() as db_session:
        template = get_template(db_session, template_id)

        sample_resume = get_sample_resume(template=template)

        return render_template("skill-resume.html", resume=sample_resume)


@app.route("/resume/section/summary", methods=["GET"])
@login_required
def render_summary_page():
    template_id = request.args.get("template_id")
    if template_id is None:
        return jsonify({"message": "Template id must be included"}), 403

    with get_session() as db_session:
        template = get_template(db_session, template_id)

        sample_resume = get_sample_resume(template=template)

        return render_template("summary-resume.html", resume=sample_resume)


@app.route("/resume/section/finalize", methods=["GET"])
@login_required
def render_finalize_page():
    template_id = request.args.get("template_id")
    if template_id is None:
        return jsonify({"message": "Template id must be included"}), 403

    with get_session() as db_session:
        template = get_template(db_session, template_id)

        sample_resume = get_sample_resume(template=template)

        return render_template("finalize-resume.html", resume=sample_resume)


@app.route("/resume/section/complete", methods=["GET"])
@login_required
def render_completed_resume():
    resume_id = request.args.get("resume_id")
    if resume_id is None:
        return jsonify({"message": "Resume id must be included"}), 403

    with get_session() as db_session:
        resume: Resume = (
            db_session.query(Resume)
            .filter_by(id=resume_id)
            .options(
                joinedload(Resume.work_experiences),
                joinedload(Resume.educations),
                joinedload(Resume.skills),
                joinedload(Resume.address),
                joinedload(Resume.template),
                joinedload(Resume.user),
            )
            .one()
        )
        selected_template_path = resume.template.template_file_path

        return render_template(
            "complete-resume.html",
            contents={"template_path": selected_template_path, "resume": resume},
        )


@app.route("/signup", methods=["GET"])
def render_signup_page():
    return render_template("signup.html")


@app.route("/resumes/view/<resume_id>", methods=["GET"])
@login_required
def render_template_preview(resume_id):

    with get_session() as db_session:
        resume: Resume = (
            db_session.query(Resume)
            .filter_by(id=resume_id)
            .options(
                joinedload(Resume.work_experiences),
                joinedload(Resume.educations),
                joinedload(Resume.skills),
                joinedload(Resume.address),
                joinedload(Resume.template),
                joinedload(Resume.user),
            )
            .one()
        )

        template_file_path = resume.template.template_file_path

        return render_template(
            "view-resume.html", template_path=template_file_path, resume=resume
        )


@app.route("/resumes/delete/<resume_id>", methods=["DELETE"])
def delete_resume(resume_id: str):
    with get_session() as db_session:
        resume = db_session.query(Resume).get(resume_id)
        if resume:
            db_session.delete(resume)
            db_session.commit()
            return jsonify({"message": "Resume deleted successfully"}), 200
        else:
            return jsonify({"error": "Resume not found"}), 404


@app.route("/resumes/<user_id>", methods=["GET"])
def render_user_resumes(user_id: str):
    try:
        with get_session() as db_session:
            user: User = (
                db_session.query(User)
                .filter_by(id=user_id)
                .options(joinedload(User.resumes))
                .one()
            )

            resumes = user.resumes

            return render_template("my-resumes.html", resumes=resumes)

    except NoResultFound:
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/about", methods=["GET"])
def render_about_page():
    return render_template("about.html")


@app.route("/profile", methods=["GET"])
@login_required
def redner_profile_page():
    return render_template("profile-edit.html")


# Used this route to upload resume template
@app.route("/auth/template", methods=["GET"])
def template_page():
    return render_template("template-uploader.html")


if __name__ == "__main__":
    app.debug
