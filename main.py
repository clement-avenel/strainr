from flask import Flask, render_template, request, redirect
from datetime import datetime
from scan import SecurityScan

#--------------------CONFIG--------------------#
app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

#--------------------ROUTES--------------------#
@app.route('/', methods=["GET", "POST"])
def Home():
    if request.method == "POST":
        req = request.form
        url = req.get("url")
        return redirect('/report?url=' + url)

    if request.method == "GET":
        return render_template('pages/Home.html')

@app.route('/report', methods=['GET'])
def Report():

    #-------------GENERAL INFORMATIONS-------------#
    url = request.args.get('url')
    date = datetime.utcnow().strftime("%m/%d/%Y, %H:%M:%S")

    #----------------SECURITY SCANS----------------#
    headers = SecurityScan().check_headers(url)
    https = SecurityScan().test_https(url)
    https_redirect = SecurityScan().test_http_to_https(url, 5)
    risk={'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}

    for value in https.values():
        if value == False:
            risk['High']+=1

    if https_redirect == False:
        risk['High']+=1

    for header, value in headers.items():
        warn = value.get('warn')
        if warn == 3:
            risk['High']+=1
        elif warn == 2:
            risk['Medium']+=1
        elif warn == 1:
            risk['Low']+=1
        else:
            risk['Info']+=1

    return render_template('pages/Report.html', url=url, date=date, risk=risk, headers = headers, https=https, https_redirect=https_redirect )
