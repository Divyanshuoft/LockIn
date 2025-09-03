from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

# Uncomment for a second test route
# @app.route('/test')
# def test():
#     return "Test route works!", 200

if __name__ == '__main__':
    app.run(debug=True)