import os

from flask import Flask, request, render_template

print('---PRENDE---')

LOCAL_ENV = 'dev'
PROJECT_ID_CEREBRO = os.getenv('PROJECT_ID_CEREBRO', f'vanti-data-cerebro-fact-{LOCAL_ENV}')


app = Flask(__name__)


@app.route("/")
def main():
    print(f'---INICIA--- {request} ---')
    img_url = ""
    return render_template("index.html", request=request.args.get('hola'))
    #return f'NO_URL_FOR: Hello'
    

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)

