from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        child_firstname = request.form["child_firstname"]
        child_lastname = request.form["child_lastname"]
        birthdate = request.form["birthdate"]
        allergy = request.form["allergy"]
        club = request.form.getlist("club")  # Mehrfachauswahl bei Checkbox
        parent_firstname = request.form["parent_firstname"]
        parent_lastname = request.form["parent_lastname"]
        phone_code = request.form["phone_code"]
        phone_number = request.form["phone_number"]
        email = request.form["email"]
        consent = request.form.get("consent")

        return render_template("confirmation.html", child_firstname=child_firstname)
    
    return render_template("form.html")

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
