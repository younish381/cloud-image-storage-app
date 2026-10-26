"""Cloud-Based Image Storage Application - S. Younish (5325128021)
Files -> OCI Object Storage (or local folder in demo mode)
Metadata -> cloud database via DATABASE_URL (SQLite by default for local demo)
"""
import os, uuid, io
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for, session,
                   flash, abort, send_file, Response)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

BASE = os.path.dirname(os.path.abspath(__file__))
ALLOWED = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_BYTES = 5 * 1024 * 1024
QUOTA_BYTES = 1024 * 1024 * 1024   # illustrative 1 GB quota shown in the storage meter
CATEGORIES = ["General", "Personal", "College", "Work", "Private"]

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///" + os.path.join(BASE, "app.db"))
app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES + 1024 * 100
db = SQLAlchemy(app)
signer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

OCI_ENABLED = os.environ.get("OCI_ENABLED", "false").lower() == "true"

# ---------------------------------------------------------------- storage
class LocalStorage:
    mode = "local"
    def __init__(self):
        self.dir = os.path.join(BASE, "uploads"); os.makedirs(self.dir, exist_ok=True)
    def put(self, key, data, content_type):
        path = os.path.join(self.dir, key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
    def get(self, key): return open(os.path.join(self.dir, key), "rb").read()
    def delete(self, key):
        p = os.path.join(self.dir, key)
        if os.path.exists(p): os.remove(p)
    def share_url(self, key, hours, token_url): return token_url

class OciStorage:
    mode = "oci"
    def __init__(self):
        import oci
        self.oci = oci
        self.cfg = oci.config.from_file()            # ~/.oci/config
        self.client = oci.object_storage.ObjectStorageClient(self.cfg)
        self.ns = os.environ["OCI_NAMESPACE"]; self.bucket = os.environ["OCI_BUCKET"]
        self.region = os.environ.get("OCI_REGION", self.cfg.get("region"))
    def put(self, key, data, content_type):
        self.client.put_object(self.ns, self.bucket, key, data, content_type=content_type)
    def get(self, key):
        return self.client.get_object(self.ns, self.bucket, key).data.content
    def delete(self, key):
        self.client.delete_object(self.ns, self.bucket, key)
    def share_url(self, key, hours, token_url):
        """Controlled sharing = OCI Pre-Authenticated Request with an expiry time."""
        d = self.oci.object_storage.models.CreatePreauthenticatedRequestDetails(
            name="share-" + uuid.uuid4().hex[:8], object_name=key, access_type="ObjectRead",
            time_expires=datetime.utcnow() + timedelta(hours=hours))
        par = self.client.create_preauthenticated_request(self.ns, self.bucket, d).data
        return f"https://objectstorage.{self.region}.oraclecloud.com{par.access_uri}"

storage = OciStorage() if OCI_ENABLED else LocalStorage()

# ---------------------------------------------------------------- models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    storage_key = db.Column(db.String(300), nullable=False)      # storage reference (object name)
    category = db.Column(db.String(40), default="General")
    tags = db.Column(db.String(200), default="")
    size = db.Column(db.Integer, default=0)
    content_type = db.Column(db.String(60))
    storage_mode = db.Column(db.String(10))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    share_link = db.Column(db.String(600))

with app.app_context():
    db.create_all()

# ---------------------------------------------------------------- auth helpers
def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not current_user():
            return redirect(url_for("login"))
        return f(*a, **k)
    return w

def own_image_or_404(iid):
    img = db.session.get(Image, iid)
    if not img or img.owner_id != session.get("uid"):
        abort(404)                                    # restricted access
    return img

def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB": return f"{n:.1f} {u}" if u != "B" else f"{n} B"
        n /= 1024
app.jinja_env.filters["human"] = human

# ---------------------------------------------------------------- routes
@app.route("/")
def home():
    return redirect(url_for("gallery") if current_user() else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].strip().lower(); pw = request.form["password"]
        if "@" not in email or len(pw) < 6:
            flash("Enter a valid email and a password of at least 6 characters.", "err")
        elif User.query.filter_by(email=email).first():
            flash("Email already registered.", "err")
        else:
            db.session.add(User(email=email, password_hash=generate_password_hash(pw))); db.session.commit()
            flash("Account created. Please log in.", "ok"); return redirect(url_for("login"))
    return render_template("auth.html", title="Create account", register=True)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = User.query.filter_by(email=request.form["email"].strip().lower()).first()
        if u and check_password_hash(u.password_hash, request.form["password"]):
            session["uid"] = u.id; return redirect(url_for("gallery"))
        flash("Wrong email or password.", "err")
    return render_template("auth.html", title="Welcome back", register=False)

@app.post("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/gallery")
@login_required
def gallery():
    q = Image.query.filter_by(owner_id=session["uid"])
    name = request.args.get("q", "").strip(); cat = request.args.get("category", "")
    d1 = request.args.get("from", ""); d2 = request.args.get("to", "")
    if name: q = q.filter(Image.file_name.ilike(f"%{name}%") | Image.tags.ilike(f"%{name}%"))
    if cat: q = q.filter_by(category=cat)
    try:
        if d1: q = q.filter(Image.uploaded_at >= datetime.strptime(d1, "%Y-%m-%d"))
        if d2: q = q.filter(Image.uploaded_at < datetime.strptime(d2, "%Y-%m-%d") + timedelta(days=1))
    except ValueError:
        flash("Invalid date.", "err")
    images = q.order_by(Image.uploaded_at.desc()).all()
    used = sum(i.size or 0 for i in Image.query.filter_by(owner_id=session["uid"]))
    return render_template("gallery.html", images=images, cats=CATEGORIES, used=used,
                           quota=QUOTA_BYTES, pct=min(100, used * 100 / QUOTA_BYTES), mode=storage.mode)

@app.post("/upload")
@login_required
def upload():
    files = [f for f in request.files.getlist("files") if f and f.filename]
    cat = request.form.get("category", "General"); tags = request.form.get("tags", "")[:200]
    if cat not in CATEGORIES: cat = "General"
    if not files: flash("Choose at least one image.", "err")
    for f in files:
        name = secure_filename(f.filename); ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        data = f.read()
        if ext not in ALLOWED:
            flash(f"{name}: unsupported type (allowed: PNG, JPG, JPEG, GIF, WEBP).", "err"); continue
        if len(data) > MAX_BYTES:
            flash(f"{name}: larger than 5 MB.", "err"); continue
        if not data[:4] in (b"\x89PNG", b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", b"\xff\xd8\xff\xdb", b"\xff\xd8\xff\xee") \
           and data[:3] != b"GIF" and data[8:12] != b"WEBP":
            flash(f"{name}: file content is not a valid image.", "err"); continue
        key = f"user{session['uid']}/{cat.lower()}/{uuid.uuid4().hex[:8]}-{name}"   # folder-style organisation
        ctype = f.mimetype or "application/octet-stream"
        storage.put(key, data, ctype)
        db.session.add(Image(owner_id=session["uid"], file_name=name, storage_key=key, category=cat, tags=tags,
                             size=len(data), content_type=ctype, storage_mode=storage.mode))
        db.session.commit(); flash(f"{name} uploaded to {storage.mode.upper()} storage.", "ok")
    return redirect(url_for("gallery"))

@app.route("/image/<int:iid>")
@login_required
def detail(iid):
    return render_template("detail.html", img=own_image_or_404(iid))

@app.route("/img/<int:iid>")
@login_required
def serve(iid):                       # thumbnails/full image streamed from private storage to the owner only
    img = own_image_or_404(iid)
    return Response(storage.get(img.storage_key), mimetype=img.content_type or "image/jpeg")

@app.post("/image/<int:iid>/share")
@login_required
def share(iid):
    img = own_image_or_404(iid); hours = min(max(int(request.form.get("hours", 24)), 1), 168)
    token = signer.dumps({"id": iid, "exp_h": hours})
    token_url = url_for("shared", token=token, _external=True)
    img.share_link = storage.share_url(img.storage_key, hours, token_url)
    db.session.commit(); flash(f"Share link created (valid {hours} h).", "ok")
    return redirect(url_for("detail", iid=iid))

@app.route("/s/<token>")
def shared(token):                    # demo share route (local mode); OCI mode uses a real PAR URL
    try:
        data = signer.loads(token, max_age=168 * 3600)
        signer.loads(token, max_age=data["exp_h"] * 3600)   # per-link expiry chosen by the owner
    except (BadSignature, SignatureExpired):
        abort(410)                                          # link expired / invalid
    img = db.session.get(Image, data["id"])
    if not img: abort(404)
    return Response(storage.get(img.storage_key), mimetype=img.content_type or "image/jpeg")

@app.post("/image/<int:iid>/delete")
@login_required
def delete(iid):
    img = own_image_or_404(iid)
    storage.delete(img.storage_key); db.session.delete(img); db.session.commit()
    flash("Image deleted from storage and database.", "ok"); return redirect(url_for("gallery"))

if __name__ == "__main__":
    app.run(debug=True)
