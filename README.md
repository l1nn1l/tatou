# tatou
A web platform for pdf watermarking. This project is intended for pedagogical use, and contain security vulnerabilities. Do not deploy on an open network.

## Instructions

The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.

To clone the repo, you can simply run:

```bash
git clone https://github.com/nharrand/tatou.git
```

Note that you should probably fork the repo and clone your own repo.


### Run python unit tests

```bash
cd tatou/server

# Create a python virtual environement
python3 -m venv .venv

# Activate your virtual environement
. .venv/bin/activate

# Install the necessary dependencies
pip install -e "server/[dev]"

# Run the unit tests
python -m pytest
```

### Deploy

From the root of the directory:

```bash
# Create a file to set environement variables like passwords.
cp sample.env .env

# Edit .env and pick the passwords you want

# Rebuild the docker image and deploy the containers
docker compose up --build -d

# Monitor logs in realtime 
docker compose logs -f

# Test if the API is up
http -v :5000/healthz

# Open your browser at 127.0.0.1:5000 to check if the website is up.
```



# README.md from group 10 

# Clone
```bash
git clone https://github.com/l1nn1l/tatou
cd tatou

```
### Configuration & Secrets
```bash
    # These are consumed by Docker and/or the app:
    TATOU_LINK_KEY — required by signed link utilities. # Set in docker-compose.yml under services.server.environment.
    Keys: keys/ is bind-mounted into the container:
    server_priv.asc (required)
    server_pub.asc
    tatou/keys/pki/ (group public keys)
#Ports
    App: container listens on 5000, published as 5000 on the host.
    DB: MariaDB on 3306 (host → container).
```
### Deployment
```bash
# From repo root, build & start the stack
docker compose up -d --build

# Verify containers:
docker compose ps

#You should see:
    tatou-db-1       Up (healthy)   0.0.0.0:3306->3306/tcp
    tatou-server-1   Up             0.0.0.0:5000->5000/tcp

# The compose file:

Publishes app on http://127.0.0.1:5000
Initializes MariaDB with db/tatou.sql
Mounts /keys to /app/keys
Persists user files under a Docker volume at /app/storage

```
### Health Check & Basic Smoke Tests
```bash
curl -s http://127.0.0.1:5000/healthz
# → {"db_connected": true, "message": "The server is up and running."}

### Minimal API smoke (create user → login → upload 1-page "PDF")
EMAIL="demo_$(date +%s)@example.com"
PWD="P@ssw0rd!"
curl -s -H "Content-Type: application/json" \
  -d "{\"login\":\"${EMAIL%%@*}\",\"password\":\"$PWD\",\"email\":\"$EMAIL\"}" \
  http://127.0.0.1:5000/api/create-user >/dev/null

TOKEN=$(curl -s -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PWD\"}" \
  http://127.0.0.1:5000/api/login | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')

printf '%s\n' '%PDF-1.4' '1 0 obj<<>>endobj' '%%EOF' > /tmp/min.pdf
curl -i -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/min.pdf;type=application/pdf" -F "name=mini" \
  http://127.0.0.1:5000/api/upload-document
# → 201 Created

```
### Running Tests
```bash

Python venv
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt         


### Unit/API tests (pytest)
# Some tests require runtime env vars for imports to succeed:
    export TATOU_LINK_KEY="dev-link-key"         # any non-empty string
    export TATOU_BASE="http://127.0.0.1:5000"    # server must be running

pytest -q <name-of-test> will run the specific test.

#XMP tests
pytest -q server/test/test_xmp_perpage.py
pytest -q server/test/unit/test_xmp_perpage_unit.py

# All tests will be picked up automatically by pytest. If a test needs authentication, it should create a user and login programmatically.
```

### Coverage report
```bash
pytest --cov=server/src --cov-report=term-missing --cov-report=html 
# To view the report in the browser
xdg-open htmlcov/index.html
```

### Collect Rmap PDFs
```bash
PYTHONPATH=. .venv/bin/python collect_rmap_pdfs.py
# successful PDF collections will be stored in tatou/collected_pdfs
```

### Mutation test
```bash
pip install mutmut
mutmut run
mutmut results
```

### Environment variables and keys 
```bash
# Create a local .env (not committed) containing:
    MARIADB_USER=app
    MARIADB_PASSWORD=app
    MARIADB_ROOT_PASSWORD=rootpass123
    TATOU_LINK_KEY=<random-hex-or-base64-string>

#The server also requires OpenPGP keys mounted at /keys/:
keys/
  server_priv.asc
  server_pub.asc
  pki/
# These files must not be committed. The directory is bind-mounted into the container at /app/keys. If server_priv.asc is missing, the server will not start. 
```

### Troubleshooting
```bash
# Port in use (5000/5000)
# Another process might be bound. Change the host port in docker-compose.yml:

 ports:
  - "5050:5000"
# … or stop the other process.


