#Kinderfasching

import os
from flask import Flask, render_template, request, flash, redirect, url_for, session, Response
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SelectField, EmailField, TelField, PasswordField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Email, Length, Regexp, ValidationError
from flask_talisman import Talisman
import logging
from logging.handlers import RotatingFileHandler
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError
from datetime import datetime, date
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
load_dotenv()
import pandas as pd
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import pytz

app = Flask(__name__)
csrf = CSRFProtect(app)

# Konfiguration der SQLite-Datenbank
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///registrations.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Sicherheitskonfiguration für Cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Cookies nur über HTTPS senden
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Zugriff auf Cookies nur über HTTP, nicht JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Schutz vor CSRF (Alternative: 'Strict' für höhere Sicherheit)

app.config['WTF_CSRF_ENABLED'] = True  # CSRF-Schutz aktivieren
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # Token ist 1 Stunde gültig
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')

app.config['SESSION_TYPE'] = 'filesystem'  # Sessions speichern
app.config['SECRET_KEY'] = 'dein_geheimer_schlüssel'

# Logging-Konfiguration
log_handler = RotatingFileHandler("error.log", maxBytes=10000, backupCount=3)
log_handler.setLevel(logging.ERROR)
log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler.setFormatter(log_format)
app.logger.addHandler(log_handler)

# Content Security Policy (CSP) mit SVG-Unterstützung
csp = {
    'default-src': ["'self'"],  # Verhindert externe Inhalte, außer von der eigenen Seite
    'script-src': [
        "'self'",
        'https://stackpath.bootstrapcdn.com',  # Bootstrap
        'https://cdnjs.cloudflare.com'  # Externe Scripts nur von diesen Quellen
    ],
    'style-src': [
        "'self'",
        'https://stackpath.bootstrapcdn.com',
        'https://fonts.googleapis.com'
    ],
    'img-src': [
        "'self'",
        'data:',  
        'blob:'
    ],
    'form-action': ["'self'"],  # Formulare dürfen nur an die eigene Domain gesendet werden
    'frame-ancestors': "'none'",  # Schutz vor Clickjacking, keine Einbettung in iFrames
    'object-src': "'none'",  # Verhindert das Einfügen unsicherer Plugins (z.B. Flash)
}

if os.environ.get("RENDER"):
    Talisman(
        app,
        content_security_policy=csp,  
        force_https=True,  # HTTPS nur auf Render erzwingen
        strict_transport_security=True,  
        strict_transport_security_max_age=31536000,  
        strict_transport_security_include_subdomains=True,  
        strict_transport_security_preload=True  
    )
else:
    Talisman(
        app,
        content_security_policy=csp,  
        force_https=False,  # Lokales HTTPS deaktiviert
        strict_transport_security=False  
    )

class RegistrationForm(FlaskForm):
    child_firstname = StringField(
        "Vorname des Kindes",
        validators=[
            DataRequired(),
            Length(max=50),
            Regexp(r'^[A-Za-zÄÖÜäöüß\s]+$')
        ]
    )

    child_lastname = StringField(
        "Nachname des Kindes",
        validators=[
            DataRequired(),
            Length(max=50),
            Regexp(r'^[A-Za-zÄÖÜäöüß\s]+$')
        ]
    )

    birthdate = DateField(
        "Geburtsdatum", format='%Y-%m-%d', 
        validators=[DataRequired()]
    )

    allergies = StringField(
        "Lebensmittelallergien", 
        validators=[Length(max=100)]
    )

    club_membership = SelectField(
        "Vereinsmitgliedschaft",
        choices=[
            ("", "Bitte auswählen"),
            ("TSV Bitzfeld 1922 e.V.", "TSV Bitzfeld 1922 e.V."),
            ("TSV Schwabbach 1947 e.V.", "TSV Schwabbach 1947 e.V.")
        ],
        validators=[DataRequired()]
    )

    parent_firstname = StringField(
        "Vorname Elternteil",
        validators=[
            DataRequired(),
            Length(max=50),
            Regexp(r'^[A-Za-zÄÖÜäöüß\s]+$')
        ]
    )

    parent_lastname = StringField(
        "Nachname Elternteil",
        validators=[
            DataRequired(),
            Length(max=50),
            Regexp(r'^[A-Za-zÄÖÜäöüß\s]+$')
        ]
    )

    phone_number = TelField(
        "Telefonnummer", 
	validators=[
            DataRequired(), 
            Length(min=6, max=15)
	]
    )

    email = EmailField(
	"E-Mail", 
	validators=[
            DataRequired()
	]
    )

class DeleteForm(FlaskForm):
    csrf_token = HiddenField()

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    child_firstname = db.Column(db.String(50), nullable=False)
    child_lastname = db.Column(db.String(50), nullable=False)
    birthdate = db.Column(db.String(10), nullable=False)
    allergies = db.Column(db.String(100))
    club_membership = db.Column(db.String(100), nullable=False)
    parent_firstname = db.Column(db.String(50), nullable=False)
    parent_lastname = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)


@app.route("/", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Datumsformat überprüfen und anpassen
        if isinstance(form.birthdate.data, (datetime, date)):
            formatted_date = form.birthdate.data.strftime("%d.%m.%Y")
        else:
            formatted_date = datetime.strptime(form.birthdate.data, "%Y-%m-%d").strftime("%d.%m.%Y")

        # Daten in die Datenbank speichern
        new_registration = Registration(
            child_firstname=form.child_firstname.data,
            child_lastname=form.child_lastname.data,
            birthdate=formatted_date,
            allergies=form.allergies.data,
            club_membership=form.club_membership.data,
            parent_firstname=form.parent_firstname.data,
            parent_lastname=form.parent_lastname.data,
            phone_number=form.phone_number.data,
            email=form.email.data
        )
        
        db.session.add(new_registration)
        db.session.commit()

        return render_template(
            "confirmation.html", 
            child_firstname=form.child_firstname.data,
            child_lastname=form.child_lastname.data,
            birthdate=formatted_date
        )

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

@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'  # MIME-Type-Sniffing verhindern
    response.headers['X-Frame-Options'] = 'DENY'  # Clickjacking-Schutz
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    return response

@app.route("/datenschutz")
def privacy():
    return render_template("privacy.html")

class AdminLoginForm(FlaskForm):
    password = PasswordField("Passwort", validators=[DataRequired()])
    submit = SubmitField("Login")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():  # Nutzt das Flask-WTF CSRF-Handling
        if form.password.data == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            return redirect(url_for("admin"))
        else:
            flash("Falsches Passwort. Bitte erneut versuchen.", "danger")
    return render_template("admin_login.html", form=form)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))  # Weiterleitung zur Login-Seite, falls nicht eingeloggt

    form = DeleteForm()

    if form.validate_on_submit():
        if 'delete_all' in request.form:
            try:
                db.session.query(Registration).delete()
                db.session.commit()
                flash("Alle Einträge wurden erfolgreich gelöscht.", "success")
            except Exception as e:
                db.session.rollback()
                flash("Fehler beim Löschen der Einträge.", "danger")
            return redirect(url_for("admin"))

    registrations = Registration.query.all()
    return render_template("admin.html", registrations=registrations, form=form)

@app.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    flash("Erfolgreich ausgeloggt.", "success")
    return redirect(url_for("admin_login"))

@app.route("/delete-entry/<int:entry_id>", methods=["POST"])
def delete_entry(entry_id):
    entry = db.session.get(Registration, entry_id)
    if entry:
        db.session.delete(entry)
        db.session.commit()
        flash("Eintrag wurde erfolgreich gelöscht.", "success")
    else:
        flash("Eintrag nicht gefunden.", "danger")
    return redirect(url_for("admin"))

def send_confirmation_email(entry):
    with app.app_context():  # Wichtig, damit Flask im Thread funktioniert
        try:
            # SMTP-Einstellungen für den Mail-Server
            SMTP_SERVER = "smtp.gmail.com" 
            SMTP_PORT = 587
            SMTP_USER = "anmeldung.tsvbitzfeld1922@gmail.com"  
            SMTP_PASS = "hfkl vsbc dcvp cuja" 

            # E-Mail-Versand vorbereiten
            msg = MIMEMultipart()
            msg["From"] = SMTP_USER
            msg["To"] = entry.email
            msg["Subject"] = "✅ Anmeldungsbestätigung 🎉"

            email_body = f"""
Hallo {entry.parent_firstname} {entry.parent_lastname},

hiermit bestätigen wir Ihnen die Anmeldung von {entry.child_firstname} {entry.child_lastname} zum Kinderfasching! 🎉
Ihre Zahlung ist erfolgreich eingegangen. 

Ihre Anmeldedaten im Überblick:

👤 Kind: {entry.child_firstname} {entry.child_lastname}  
📅 Geburtsdatum: {entry.birthdate}  
🌰 Lebensmittelallergien: {entry.allergies if entry.allergies else "-"}  
🏅 Verein: {entry.club_membership}  

👨‍👩‍👦 Erziehungsberechtigte/r: {entry.parent_firstname} {entry.parent_lastname}  
📞 Notfall-Telefonnummer: {entry.phone_number}  
📧 E-Mail: {entry.email}  


Falls Sie Fragen haben, erreichen Sie uns unter anmeldung.tsvbitzfeld1922@gmail.com.
Wir freuen uns auf einen tollen Tag! 🎊🎈


Viele Grüße

Jugendausschuss des TSV Bitzfeld

            """

            msg.attach(MIMEText(email_body, "plain"))

            # Verbindung zum SMTP-Server aufbauen und E-Mail senden
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, entry.email, msg.as_string())
            server.quit()

        except Exception as e:
            print(f"Mail wird im Hintergrund  gesendet: {e}")

@app.route("/confirm-mail/<int:entry_id>", methods=["POST"])
def confirm_mail(entry_id):
    with app.app_context():  # Stellt sicher, dass Flask im richtigen Kontext arbeitet
        entry = db.session.get(Registration, entry_id)  # Korrekte SQLAlchemy 2.0 Abfrage

        if entry:
            try:
                # Eintrag als "bestätigt" markieren
                entry.confirmed = True
                db.session.commit()

                # Sende die Mail in einem separaten Thread
                email_thread = threading.Thread(target=send_confirmation_email, args=(entry,))
                email_thread.start()

                flash("Bestätigungsmail wurde erfolgreich versandt.", "success")
            except Exception as e:
                flash(f"Fehler beim Senden der Bestätigungsmail: {e}", "danger")
        else:
            flash("Eintrag nicht gefunden.", "danger")

    return redirect(url_for("admin"))

@app.route("/delete-all-entries", methods=["POST"])
def delete_all_entries():
    try:
        db.session.query(Registration).delete()
        db.session.commit()
        flash("Alle Einträge wurden erfolgreich gelöscht.", "success")
    except Exception as e:
        db.session.rollback()
        flash("Fehler beim Löschen der Einträge.", "danger")
    return redirect(url_for("admin"))

@app.route("/export-excel")
def export_excel():
    # Überprüfen, ob der Benutzer als Admin eingeloggt ist
    if not session.get("admin_logged_in"):
        flash("Nicht autorisiert!", "danger")
        return redirect(url_for("admin_login"))

    # Daten aus der Datenbank abrufen
    registrations = Registration.query.all()
    data = [{
        "Vorname": r.child_firstname,
        "Nachname": r.child_lastname,
        "Geburtsdatum": r.birthdate,
        "Allergien": r.allergies if r.allergies else "-",
        "Vereinsmitgliedschaft": r.club_membership,
        "Telefon": r.phone_number,
        "E-Mail": r.email
    } for r in registrations]

    # Daten in ein Pandas-DataFrame umwandeln
    df = pd.DataFrame(data)

    # In eine BytesIO-Datei speichern, um sie im Speicher zu halten
    output = BytesIO()
    df.to_excel(output, index=False, engine='openpyxl')
    output.seek(0)

    # Zeitstempel im Format DDMMYYYY_HHMMSS mit Berücksichtigung der Zeitzone
    timezone = pytz.timezone("Europe/Berlin")
    timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")

    # Excel-Datei als Antwort zurückgeben
    response = Response(
        output.getvalue(),
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    response.headers["Content-Disposition"] = f"attachment; filename=Anmeldungen_Stand-{timestamp}.xlsx"
    
    return response




if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    
    if os.environ.get("RENDER"):  # Falls auf Render deployed
        from gunicorn.app.wsgiapp import run
        run()
    else:
        app.run(debug=False, host="127.0.0.1", port=port)