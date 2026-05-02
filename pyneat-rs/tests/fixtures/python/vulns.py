# Test fixtures for PyNEAT integration tests
# Each file contains intentionally vulnerable code patterns
# to verify that security rules are working correctly.
#
# DO NOT use these files as templates for real code!

# ---- SQL Injection ----
def unsafe_query(user_id):
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
    cursor.execute(f"SELECT * FROM users WHERE name='{username}'")
    db.session.execute("SELECT * FROM orders WHERE id=" + order_id)

# ---- Command Injection ----
def run_command(filename):
    os.system("ls -la " + filename)
    subprocess.run(cmd, shell=True)
    os.popen("cat " + filename)

# ---- eval/exec ----
def process_data(data):
    result = eval(data)
    exec('print("debug")')
    compiled = compile(user_code, '<string>', 'exec')

# ---- Unsafe Deserialization ----
def load_data(payload):
    data = yaml.load(user_yaml)  # should flag
    obj = pickle.loads(user_data)
    obj = marshal.loads(untrusted_bytes)
    obj = shelve.open(user_file)

# ---- Path Traversal ----
def read_file(filename):
    with open(user_filename) as f:
        return f.read()
    content = Path(user_input).read_text()

# ---- Hardcoded Secrets ----
API_KEY = "sk-1234567890abcdef12345678"
password = "SuperSecret123!"
aws_key = "AKIAIOSFODNN7EXAMPLE"
private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAL\n-----END RSA PRIVATE KEY-----"

# ---- Weak Crypto ----
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
    return hashlib.sha1(data)
    return hashlib.new('md4', data)
    return Crypto.Cipher.DES.new(key)

# ---- NoSQL/MongoDB Injection ----
def get_user(user_id):
    result = db.users.find_one({"_id": user_id})
    db.command({"user": input_data})

# ---- JWT Algorithm Confusion ----
def decode_token(token):
    return jwt.decode(token, options={"verify_signature": False})

# ---- SSRF ----
def fetch_url(url):
    response = urllib.request.urlopen(user_url)
    result = requests.get(url)

# ---- Dynamic Import ----
def load_plugin(name):
    mod = __import__(user_module_name)
    exec("import " + module_name)
