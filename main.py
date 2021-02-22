from flask import Flask, render_template
from scan import SecurityHeaders

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

url="https://google.com"

#CHECK Headers
headers = SecurityHeaders().check_headers(url)

if not headers:
    print ("Failed to fetch headers, exiting...")
    sys.exit(1)

okColor = '\033[92m'
warnColor = '\033[93m'
endColor = '\033[0m'
for header, value in headers.items():
    if value['warn'] == 1:
        if value['defined'] == False:
            print('Header \'' + header + '\' is missing ... [ ' + warnColor + 'WARN' + endColor + ' ]')
        else:
            print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                ' ... [ ' + warnColor + 'WARN' + endColor + ' ]')
    elif value['warn'] == 0:
        if value['defined'] == False:
            print('Header \'' + header + '\' is missing ... [ ' + okColor + 'OK' + endColor +' ]')
        else:
            print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                ' ... [ ' + okColor + 'OK' + endColor + ' ]')

# CHECK https
https = SecurityHeaders().test_https(url)
if https['supported']:
    print('HTTPS supported ... [ ' + okColor + 'OK' + endColor + ' ]')
else:
    print('HTTPS supported ... [ ' + warnColor + 'FAIL' + endColor + ' ]')

if https['certvalid']:
    print('HTTPS valid certificate ... [ ' + okColor + 'OK' + endColor + ' ]')
else:
    print('HTTPS valid certificate ... [ ' + warnColor + 'FAIL' + endColor + ' ]')

# CHECK http to https
if SecurityHeaders().test_http_to_https(url, 5):
    print('HTTP -> HTTPS redirect ... [ ' + okColor + 'OK' + endColor + ' ]')
else:
    print('HTTP -> HTTPS redirect ... [ ' + warnColor + 'FAIL' + endColor + ' ]')

@app.route('/', methods=['GET'])
def Home():
    return render_template('pages/Home.html')
