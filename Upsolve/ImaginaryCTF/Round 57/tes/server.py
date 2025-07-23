from flask import *
import os, time, threading, asyncio
from playwright.async_api import async_playwright

async def visit_url(note_id, name="", random=""):
    async with async_playwright() as p:
        browser = await p.firefox.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        await context.add_cookies([{
            "name": "whatsthis",
            "value": os.getenv("PASSWORD"),
            "domain": "localhost", # change this on remote
            "path": "/flag",
            "httpOnly": True,
            "secure": False,
            "sameSite": "Strict"
        }])

        await page.goto(os.getenv("URL") + "/note?note_id=" + note_id + "&name=" + name + "&random=" + random, wait_until="networkidle")
        await browser.close()

app = Flask(__name__, static_url_path="", static_folder="public", template_folder="templates")
contents = {}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/report", methods=["GET", "POST"])
def report():
    if request.method == "GET":
        return render_template("report.html")
    elif request.method == "POST":
        note_id = str(request.form.get("note_id"))
        name = str(request.form.get("name"))
        random = str(request.form.get("random"))

        if len(name) > 10 or len(random) > 10 or len(note_id) < 1 or any(x in note_id or x in name or x in random for x in "[]`@#?$%^&*()-+\r\n"):
            return "???????? 😡"

        def async_wrapper():
            asyncio.run(visit_url(note_id, name, random))
        
        thread = threading.Thread(target=async_wrapper)
        thread.start()

        return "hopefully visited 🤞🤞🤞🤞🤞🤞🤞🤞🤞🤞🤞🤞"

@app.route("/createnote", methods=["GET", "POST"])
def note():
    if request.method == "GET":
        return render_template("createnote.html")
    elif request.method == "POST":
        note_content = str(request.form.get("note_content"))

        if len(note_content) < 3 or len(note_content) > 50:
            return "????????"

        note_id = os.urandom(16).hex()
        contents[note_id] = note_content
        return f"made note with id {note_id}"

@app.route("/note", methods=["GET"])
def view_note():
    note_id = str(request.args.get("note_id"))
    name = str(request.args.get("name"))
    random = str(request.args.get("random"))

    try:
        note_content = contents[note_id[:32]]
        resp = make_response(render_template("note.html", note_content=note_content, name=name, random=random))
        resp.headers.set("Link", f"<{os.getenv('URL')}/info?note_id={note_id}>; rel=\"preload\"")
        return resp
    except:
        return "hmm i think not"

@app.route("/info", methods=["GET"])
def info():
    note_id = request.args.get("note_id")
    if contents.get(note_id) != None:
        return f"very very interesting data here"
    else:
        return "no extremely useful info for you 😤"

@app.route("/flag", methods=["GET"])
def flag():
    if request.headers.get("referer") != None:
        return "suspicious request 🤨"

    password = request.cookies.get("whatsthis")
    if password == os.getenv("PASSWORD"):
        return os.getenv("FLAG")
    else:
        return "not funny 😔"

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Security-Policy"] = "object-src 'none'; script-src 'self'; frame-ancestors 'none';"
    return resp

if __name__ == "__main__":
    app.run("0.0.0.0", 8000)