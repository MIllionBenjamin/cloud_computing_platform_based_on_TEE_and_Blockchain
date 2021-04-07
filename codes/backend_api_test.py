from flask import Flask, abort, request, jsonify
from flask.views import MethodView

app = Flask(__name__)



class Hello(MethodView):
    def get(self):
        return jsonify({"hello": "hello"})
    
app.add_url_rule('/hello', view_func = Hello.as_view(name='hello'))



if __name__ == '__main__':
    app.run(host = "0.0.0.0", port = 8383)