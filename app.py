import os
from flask import Flask, render_template, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SelectField, EmailField, TelField
from wtforms.validators import DataRequired, Email, Length
from flask_talisman import Talisman
import logging
from logging.handlers import RotatingFileHandler
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError

app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True  # CSRF-Schutz aktivieren
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # Token ist 1 Stunde gültig
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')

# Logging-Konfiguration
log_handler = RotatingFileHandler("error.log", maxBytes=10000, backupCount=3)
log_handler.setLevel(logging.ERROR)
log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler.setFormatter(log_format)
app.logger.addHandler(log_handler)

# Content Security Policy (CSP) mit SVG-Unterstützung
csp = {
    'default-src': [
        "'self'",  
        'https://stackpath.bootstrapcdn.com',  
        'https://cdnjs.cloudflare.com'  
    ],
    'img-src': [
        "'self'",  
        'data:',  
        'blob:',  
        'https://example.com',  
    ],
    'script-src': [
        "'self'",
        'https://stackpath.bootstrapcdn.com',
        'https://cdnjs.cloudflare.com'
    ],
    'style-src': [
        "'self'",
        'https://stackpath.bootstrapcdn.com',
        'https://fonts.googleapis.com'
    ],
    'frame-ancestors': "'none'",  
}

Talisman(
    app,
    content_security_policy=csp,  
    force_https=True,  # HTTPS aktivieren
    strict_transport_security=True,  # HSTS aktivieren
    frame_options="DENY"
)

class RegistrationForm(FlaskForm):
    child_firstname = StringField("Vorname des Kindes", validators=[DataRequired(), Length(max=50)])
    child_lastname = StringField("Nachname des Kindes", validators=[DataRequired(), Length(max=50)])
    birthdate = DateField("Geburtsdatum", format='%Y-%m-%d', validators=[DataRequired()])
    allergies = StringField("Lebensmittelallergien", validators=[Length(max=100)])
    club_membership = SelectField("Vereinsmitgliedschaft", choices=[
        ("TSV Bitzfeld 1922 e.V.", "TSV Bitzfeld 1922 e.V."),
        ("TSV Schwabbach 1947 e.V.", "TSV Schwabbach 1947 e.V.")
    ], validators=[DataRequired()])
    parent_firstname = StringField("Vorname Elternteil", validators=[DataRequired(), Length(max=50)])
    parent_lastname = StringField("Nachname Elternteil", validators=[DataRequired(), Length(max=50)])
    phone_number = TelField("Telefonnummer", validators=[DataRequired(), Length(min=10, max=15)])
    email = EmailField("E-Mail", validators=[DataRequired(), Email()])

@app.route("/", methods=["GET", "POST"])
def register():
    print(f"Request method: {request.method}")

    form = RegistrationForm()
    if form.validate_on_submit():
        print("Form validated successfully")
        return render_template(
            "confirmation.html", 
            child_firstname=form.child_firstname.data,
            child_lastname=form.child_lastname.data,
            birthdate=form.birthdate.data
        )

    print("Form validation failed")
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"Fehler im Feld '{field}': {error}", "danger")

    return render_template("form.html", form=form)

@app.errorhandler(404)
def page_not_found(e):
    app.logger.error(f"404 Error: {request.url}")
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f"500 Error: {request.url}")
    return render_template("500.html"), 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("CSRF-Token ist ungültig oder fehlt. Bitte versuchen Sie es erneut.", "danger")
    return render_template("form.html"), 400




if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    
    if os.environ.get("RENDER"):  # Falls auf Render deployed
        from gunicorn.app.wsgiapp import run
        run()
    else:
        print(f"Running locally on http://127.0.0.1:{port} with Flask...")
        app.run(debug=True, host="127.0.0.1", port=port)


