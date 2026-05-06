# ============================================================================
# Chaos Test 10: Security vulnerability patterns
# Tests: Ensure security rules catch real-world attack patterns
# ============================================================================

# SQL Injection - classic
def classic_sql_injection(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input
    cursor.execute(query)
    return cursor.fetchall()

# SQL Injection - ORM with raw
def orm_sql_injection(user_input):
    return db.session.execute(
        text("SELECT * FROM users WHERE id = " + user_input)
    )

# Command Injection
def command_injection(user_input):
    os.system("ls -la " + user_input)
    subprocess.call(user_input, shell=True)
    os.popen(user_input).read()
    subprocess.run(user_input.split(), shell=False)

# Path Traversal
def path_traversal(user_file):
    with open("/var/www/" + user_file) as f:
        return f.read()
    
    os.path.join("/static/", user_file)
    pathlib.Path("/data/") / user_file

# Eval/Exec injection
def code_injection(user_code):
    eval(user_code)
    exec(user_code)
    compile(user_code, '<string>', 'exec')

# Deserialization
def deserialization(payload):
    import pickle
    import yaml
    
    data = pickle.loads(payload)  # Unsafe!
    config = yaml.unsafe_load(user_input)  # Unsafe!

# Hardcoded secrets
API_KEY = "sk-abcdef1234567890abcdef1234567890"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
JWT_SECRET = "super_secret_key_12345"
DATABASE_URL = "postgresql://admin:password123@localhost:5432/db"

# Insecure randomness
def weak_random():
    import random
    return random.random()  # Not cryptographically secure
    import uuid
    return uuid.uuid4()  # Not for security purposes

# Insecure hash
def weak_hash(data):
    import hashlib
    return hashlib.md5(data).hexdigest()  # Weak!
    return hashlib.sha1(data).hexdigest()  # Weak!

# SSRF
def ssrf_vulnerability(url):
    import requests
    return requests.get(url).text  # Could hit internal services

# XXE simulation (Python XML parsing)
def xxe_like(url):
    import xml.etree.ElementTree as ET
    ET.parse(url)  # Could be XXE if URL points to malicious XML

# XSS simulation (template injection)
def xss_template(user_input, template):
    return template.replace("{{content}}", user_input)

# Insecure cookie settings
SESSION_CONFIG = {
    "secure": False,  # Should be True
    "httponly": False,  # Should be True
    "samesite": "none",  # Should be "strict" or "lax"
}

# Login without rate limiting
def login_no_rate_limit(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return login_user(user)
    return None

# Race condition (TOCTOU)
def race_condition():
    if not os.path.exists("/tmp/lock"):
        open("/tmp/lock", "w").write(str(os.getpid()))
        # Time gap here allows race condition
        do_critical_operation()

# Improper certificate validation
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False  # Should be True
ctx.verify_mode = ssl.CERT_NONE  # Should be CERT_REQUIRED

# SQLAlchemy injection
from sqlalchemy import text
def sqlalchemy_injection(user_input):
    result = db.session.execute(
        text("SELECT * FROM users WHERE name = '" + user_input + "'")
    )
