from flask import Flask, render_template, request
from walker import walk

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    findings = []
    error = None

    if request.method == "POST":
        target = request.form.get("target")
        history = "history" in request.form

        try:
            findings = list(walk(target, history=history))
        except Exception as e:
            error = str(e)

    return render_template(
        "index.html",
        findings=findings,
        error=error
    )

if __name__ == "__main__":
    app.run(debug=True)