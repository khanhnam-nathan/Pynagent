# Vulnerable Python code that hackingtool tools exploit
# Test data for SEC-126 (SQL Injection Sink), SEC-127 (XSS Sink),
# SEC-128 (LFI/Path Traversal), SEC-129 (CSRF), SEC-130 (SSRF), SEC-131 (Open Redirect)

from flask import Flask, request, render_template_string, render_template
from django.http import HttpResponse
from django.utils.safestring import mark_safe
from starlette.responses import HTMLResponse
from werkzeug.utils import safe_join
import os
import requests
from pathlib import Path

app = Flask(__name__)

# ============================================================
# SEC-126: SQL Injection Vulnerable Sinks (Sqlmap, DSSS target)
# ============================================================

# Sink 1: f-string in cursor.execute
cursor.execute(f"SELECT * FROM users WHERE name='{username}'")
cursor.execute(f"SELECT * FROM products WHERE id={request.args.get('id')}")
db.execute(f"SELECT * FROM logs WHERE user='{request.form['user']}'")

# Sink 2: %-formatting in SQL
cursor.execute("SELECT * FROM admin WHERE pass='%s'" % password)
db.execute("DELETE FROM logs WHERE id=%s" % user_id)

# Sink 3: .format() in SQL
cursor.execute("SELECT * FROM users WHERE email='{}'".format(email))
session.execute("UPDATE accounts SET balance={} WHERE id={}".format(new_balance, account_id))

# Sink 4: String concatenation building SQL query
query = "SELECT * FROM items WHERE category='" + category + "'"
cursor.execute(query)
sql = "SELECT * FROM " + table_name + " WHERE id=" + request.args.get('id')
cursor.execute(sql)

# Sink 5: SQLAlchemy text() with f-string
from sqlalchemy import text
session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))

# Sink 6: ORM filter with raw string
User.query.filter(f"id == {user_input}")
Model.query.filter_by(id=user_id)

# Sink 7: Direct user input in SQL template
cursor.execute("SELECT * FROM users WHERE name = '{}' AND pass = '{}'".format(username, password))


# ============================================================
# SEC-127: XSS Vulnerable Sinks (DalFox, XSStrike target)
# ============================================================

# Sink 1: render_template_string with user input — SSTI/XSS
render_template_string(request.args.get('template', ''))
render_template_string(request.form['content'])
render_template_string(f"<h1>{user_name}</h1>")

# Sink 2: mark_safe in Django with user input
mark_safe(request.GET['content'])
mark_safe(request.POST['html'])
content = mark_safe(user_input_from_form)

# Sink 3: HttpResponse with user content
HttpResponse(request.GET.get('html'))
HttpResponse(user_generated_content, content_type='text/html')

# Sink 4: FastAPI HTMLResponse with user data
HTMLResponse(content=user_input)
HTMLResponse(request.query_params['html_body'])

# Sink 5: Jinja2 | safe filter on user data
# In template: {{ user_content | safe }}
# {{ request.args.get('xss') | safe }}

# Sink 6: Tornado self.write
self.write(request.args['data'])
self.write(user_input)

# Sink 7: autoescape disabled
# {% autoescape false %} ... {% endautoescape %}

# Sink 8: Mako template with raw ${}
# ${request.params.get('name')}


# ============================================================
# SEC-128: LFI / Path Traversal (Commix, Dirsearch target)
# ============================================================

# Sink 1: open() with user input in path
with open(f"templates/{request.args.get('page')}.html") as f:
    content = f.read()
open(request.GET['file'])
open(os.path.join('uploads', request.form['filename']))

# Sink 2: send_from_directory with user-controlled filename
send_from_directory('static', request.args.get('file'))
send_from_directory(directory, filename_from_user)

# Sink 3: send_file with path concatenation
send_file(os.path.join(UPLOAD_DIR, request.args['name']))

# Sink 4: pathlib.Path with user input
Path(request.args['path'])
pathlib.Path(user_controlled_path)

# Sink 5: read operations with user-controlled paths
Path(request.GET['file']).read_text()
pathlib.Path(user_input).read_bytes()

# Sink 6: Template loading with user input
loader.get_template(request.args.get('template'))


# ============================================================
# SEC-129: CSRF Vulnerable Sinks (CSRF exploit tools target)
# ============================================================

# Sink 1: @csrf_exempt decorator
@csrf_exempt
@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']
    account.balance -= int(amount)

# Sink 2: POST route without CSRF token validation
@app.route('/update_profile', methods=['POST'])
def update_profile():
    email = request.form['email']
    user.email = email

# Sink 3: State-changing function without CSRF
def reset_password(request):
    new_pass = request.form['password']
    user.set_password(new_pass)

# Sink 4: FastAPI mutation without CSRF
@app.post("/admin/delete")
async def delete_user(user_id: str):
    db.delete(user_id)

# Sink 5: Django CBV without CSRF
class UserUpdateView(View):
    def post(self, request):
        user.profile.update(request.POST)


# ============================================================
# SEC-130: SSRF Vulnerable Sinks (Commix, SSRFMap target)
# ============================================================

# Sink 1: requests with user-controlled URL
requests.get(request.args.get('url'))
requests.post(request.form['endpoint'])
httpx.get(request.query_params['fetch_url'])

# Sink 2: urllib with user URL
import urllib.request
urllib.request.urlopen(request.args.get('target'))
urllib.request.urlopen(request.form['url'])

# Sink 3: subprocess curl/wget with user URL
import subprocess
subprocess.run(['curl', request.args['url']])
subprocess.check_output(['wget', request.form['link']])

# Sink 4: AWS metadata endpoint access
requests.get('http://169.254.169.254/latest/meta-data/')
requests.get(f"http://{host}/latest/meta-data/iam/security-credentials/")

# Sink 5: aiohttp with user URL
async with aiohttp.ClientSession() as session:
    await session.get(request.query_params['url'])

# Sink 6: URL built from user input
url = request.args.get('api') + '/data'
requests.get(url)


# ============================================================
# SEC-131: Open Redirect Vulnerable Sinks (Commix, scanners target)
# ============================================================

# Sink 1: Flask redirect with user input
@app.route('/go')
def go():
    return redirect(request.args.get('next'))

@app.route('/return')
def return_to():
    return redirect(request.form['redirect_url'])

# Sink 2: Django HttpResponseRedirect with user input
from django.http import HttpResponseRedirect
def redirect_view(request):
    return HttpResponseRedirect(request.GET['next'])

# Sink 3: FastAPI RedirectResponse
from fastapi import FastAPI
from fastapi.responses import RedirectResponse

@app.get("/redirect")
async def redirect_user(next: str = None):
    return RedirectResponse(url=next)

# Sink 4: Redirect with base + user path
@app.route('/jump')
def jump():
    base = "https://example.com"
    return redirect(base + request.args.get('path'))

# Sink 5: next/redirect parameter pattern
@app.route('/auth')
def auth():
    next_url = request.args.get('next', '/dashboard')
    return redirect(next_url)
