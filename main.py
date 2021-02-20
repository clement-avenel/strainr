from flask import Flask, render_template
from scan import scan

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.route('/', methods=['GET'])
def Home():
    scan('https://url.fr')
    return render_template('pages/Home.html')
