from flask import Flask, render_template, request

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.route('/', methods=['GET'])
def Home():
    return render_template('pages/Home.html')
