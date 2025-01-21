from flask import Flask, render_template, request
import os

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def form():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        return f"Vielen Dank, {name}! Deine E-Mail-Adresse {email} wurde empfangen."
    return render_template("form.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Render nutzt PORT-Variable
    app.run(host="0.0.0.0", port=port)

