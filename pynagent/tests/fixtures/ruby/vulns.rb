# Test fixtures for Ruby security rules
# DO NOT use as templates!

# Hardcoded Secrets
API_KEY = "sk_live_abcdef1234567890"
PASSWORD = "SuperSecret123!"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# SQL Injection
def unsafe_query(user_id)
  result = db.execute("SELECT * FROM users WHERE id=#{user_id}")
  User.where("name = '#{username}'")
end

# Command Injection
def run_command(cmd)
  system(user_input)
  `#{user_command}`
  exec(userInput)
  spawn(userCmd)
end

# Path Traversal
def read_file(filename)
  File.read(user_filename)
  IO.read(userInput)
end

# eval / dynamic code
def dynamic_code(code)
  eval(user_code)
  instance_eval(userInput)
  class_eval(code)
end

# Debug statements
def process_order(order)
  puts "Processing order: #{order}"
  p user_data
  pp data
  print "Debug: #{data}"
end

# Weak crypto
def hash_password(pwd)
  Digest::MD5.hexdigest(pwd)
  Digest::SHA1.data(data)
end

# XSS risk
def render_user_content(html)
  puts user_input
end
