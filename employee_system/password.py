from werkzeug.security import generate_password_hash
hashed_password = generate_password_hash('admin123', method='pbkdf2:sha256')
print(hashed_password)