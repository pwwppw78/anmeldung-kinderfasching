function validateInput(input) {
    let pattern = new RegExp(input.getAttribute('pattern'));
    let errorMessage = document.getElementById(input.id + '_error');
    let errorText;

    if (input.type === "email") {
        errorText = "Bitte eine gültige E-Mail-Adresse eingeben!";
    } else if (input.tagName === "SELECT") {
        errorText = "Bitte eine Option auswählen!";
    } else {
        errorText = "Ungültige Eingabe. Bitte die Anforderungen beachten!";
    }

    if (!pattern.test(input.value.trim()) || input.value.trim() === '') {
        input.classList.add('input-error');
        errorMessage.textContent = errorText;
        errorMessage.style.display = 'block';
        return false;
    } else {
        input.classList.remove('input-error');
        errorMessage.textContent = '';
        errorMessage.style.display = 'none';
        return true;
    }
}


document.getElementById('registrationForm').addEventListener('submit', function(event) {
    let isValid = true;
    
    const clubSelect = document.getElementById('club_membership');
    let errorMessage = document.getElementById('club_membership_error');

    if (clubSelect.value === "") {
        clubSelect.classList.add('input-error');
        errorMessage.textContent = "Bitte eine gültige Option auswählen!";
        errorMessage.style.display = 'block';
        isValid = false;
    } else {
        clubSelect.classList.remove('input-error');
        errorMessage.textContent = "";
        errorMessage.style.display = 'none';
    }

    if (!isValid) {
        event.preventDefault();
    }
});



