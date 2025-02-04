// Constants and DOM element cache
const SELECTORS = {
    BANK_BUTTON: '.bank-button',
    BANK_DETAILS: '#bank-details',
    PAYPAL_BUTTON: '.paypal-button',
    ADD_CHILD_BUTTON: '#add-child-button',
    CHILDREN_CONTAINER: '#children-container',
    REGISTRATION_FORM: '#registrationForm',
    CSRF_TOKEN: 'input[name="csrf_token"]',
    CHILD_FORM: '.child-form'
};

const PAYPAL_URL = 'https://paypal.me/pascalweibler?country.x=DE&locale.x=de_DE';

// Main initialization function
document.addEventListener('DOMContentLoaded', () => {
    initializePaymentControls();
    initializeChildFormHandling();
    initializeFormSubmission();
    handleFlashMessages();
});

// Payment controls initialization
function initializePaymentControls() {
    const bankButton = document.querySelector(SELECTORS.BANK_BUTTON);
    const bankDetails = document.querySelector(SELECTORS.BANK_DETAILS);
    const paypalButton = document.querySelector(SELECTORS.PAYPAL_BUTTON);

    if (bankButton && bankDetails) {
        bankButton.addEventListener('click', () => {
            const isHidden = bankDetails.style.display === 'none' || !bankDetails.style.display;
            bankDetails.style.display = isHidden ? 'block' : 'none';
        });
    }

    if (paypalButton) {
        paypalButton.addEventListener('click', (event) => {
            event.preventDefault();
            window.open('https://paypal.me/pascalweibler?country.x=DE&locale.x=de_DE', '_blank');
        });
    }
}

// Child form handling
function initializeChildFormHandling() {
    const addButton = document.querySelector(SELECTORS.ADD_CHILD_BUTTON);
    const container = document.querySelector(SELECTORS.CHILDREN_CONTAINER);

    if (!addButton || !container) return;

    addButton.addEventListener('click', () => addChildForm(container));
    container.addEventListener('click', handleChildFormRemoval);
}

function validateForm() {
    let isValid = true;
    const requiredFields = document.querySelectorAll('[required]');
    
    // Clear previous error messages
    document.querySelectorAll('.validation-error').forEach(el => el.remove());
    document.querySelectorAll('.error-field').forEach(el => el.classList.remove('error-field'));
    
    requiredFields.forEach(field => {
        let errorMessage = '';
        
        // Validate based on input type and specific conditions
        if (!field.value.trim()) {
            errorMessage = 'Dieses Feld ist erforderlich';
        } else {
            switch(field.type) {
                case 'text':
                    if (field.name.includes('child_firstname') || field.name.includes('child_lastname') || 
                        field.name.includes('parent_firstname') || field.name.includes('parent_lastname')) {
                        if (field.value.trim().length < 2) {
                            errorMessage = 'Mindestens 2 Zeichen erforderlich';
                        } else if (!/^[A-Za-zÄÖÜäöüß\s-]+$/.test(field.value.trim())) {
                            errorMessage = 'Nur Buchstaben und Bindestriche erlaubt';
                        }
                    }
                    break;
                case 'email':
                    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(field.value.trim())) {
                        errorMessage = 'Ungültige E-Mail-Adresse';
                    }
                    break;
                case 'tel':
                    if (!/^(\+\d{1,3}[- ]?)?\d{1,3}[- ]?\d{3,4}[- ]?\d{4,5}$/.test(field.value.trim())) {
                        errorMessage = 'Ungültiges Telefonnummerformat';
                    }
                    break;
                case 'date':
                    const selectedDate = new Date(field.value);
                    const currentDate = new Date();
                    if (selectedDate > currentDate) {
                        errorMessage = 'Geburtsdatum kann nicht in der Zukunft liegen';
                    }
                    break;
                case 'select-one':
                    if (field.value === '' || field.value === field.querySelector('option').value) {
                        errorMessage = 'Bitte eine Option auswählen';
                    }
                    break;
            }
        }
        
        // If there's an error, highlight and show message
        if (errorMessage) {
            isValid = false;
            const errorDiv = document.createElement('div');
            errorDiv.classList.add('validation-error');
            errorDiv.textContent = errorMessage;
            field.parentNode.insertBefore(errorDiv, field.nextSibling);
            field.classList.add('error-field');
            
            // Scroll to first error
            if (isValid === false) {
                field.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }
    });
    
    // Show overall error message if form is invalid
    if (!isValid) {
        addFlashMessage('❌ Bitte überprüfen Sie Ihre Eingaben.', 'error');
    }
    
    return isValid;
}

function handleFlashMessages() {
    document.querySelectorAll('.flash-message:not([data-handled])').forEach(message => {
        message.dataset.handled = 'true';
        
        // Style for centered, boxed messages
        message.style.position = 'fixed';
        message.style.top = '50%';
        message.style.left = '50%';
        message.style.transform = 'translate(-50%, -50%)';
        message.style.backgroundColor = 'rgba(0, 0, 0, 1)';
        message.style.color = 'white';
        message.style.padding = '15px 30px';
        message.style.borderRadius = '8px';
        message.style.zIndex = '1000';
        message.style.textAlign = 'center';
        
        // Fade out and remove after 3 seconds
        setTimeout(() => {
            message.style.transition = 'opacity 0.5s';
            message.style.opacity = '0';
            setTimeout(() => message.remove(), 500);
        }, 3000);
    });
}

function addFlashMessage(message, type) {
    const flashMsg = document.createElement('div');
    flashMsg.classList.add('flash-message', type);
    flashMsg.textContent = message;
    document.body.appendChild(flashMsg);
    handleFlashMessages(flashMsg);
}

function addChildForm(container) {
    const childCount = document.querySelectorAll(SELECTORS.CHILD_FORM).length + 1;
    const childForm = createChildFormElement(childCount);
    container.appendChild(childForm);
}

function createChildFormElement(childCount) {
    const div = document.createElement('div');
    div.classList.add('child-form');
    div.setAttribute('data-child-id', childCount);
    div.innerHTML = getChildFormTemplate(childCount);
    return div;
}

function getChildFormTemplate(childCount) {
    return `
        <hr class="child-child-divider">
        <h3>Kind ${childCount}</h3>
        <label>Name des Kindes *</label>
        <div class="name-fields">
            <input type="text" name="child_firstname_${childCount}" placeholder="Vorname" required>
            <input type="text" name="child_lastname_${childCount}" placeholder="Nachname" required>
        </div>
        <label>Geburtsdatum des Kindes *</label>
        <input type="date" name="birthdate_${childCount}" required>
        <label>Hat das Kind Lebensmittelallergien?</label>
        <input type="text" name="allergies_${childCount}" placeholder="Bitte Allergien angeben (falls vorhanden)">
        <label>Vereinsmitgliedschaft *</label>
        <select name="club_membership_${childCount}" required>
            <option value="">Bitte auswählen</option>
            <option value="TSV Bitzfeld 1922 e.V.">TSV Bitzfeld 1922 e.V.</option>
            <option value="TSV Schwabbach 1947 e.V.">TSV Schwabbach 1947 e.V.</option>
        </select>
        <div class="change-child-button-container">
            <button type="button" class="change-child-button">Dieses Kind entfernen</button>
        </div>
    `;
}

function handleChildFormRemoval(event) {
    if (!event.target.classList.contains('change-child-button')) return;
    
    const childForm = event.target.closest(SELECTORS.CHILD_FORM);
    if (childForm) {
        childForm.remove();
        updateChildNumbers();
    }
}

function updateChildNumbers() {
    document.querySelectorAll(SELECTORS.CHILD_FORM).forEach((form, index) => {
        const newIndex = index + 1;
        updateChildFormIndices(form, newIndex);
    });
}

function updateChildFormIndices(form, newIndex) {
    form.querySelector('h3').textContent = `Kind ${newIndex}`;
    form.setAttribute('data-child-id', newIndex);

    const inputs = {
        'child_firstname': 'input[name^="child_firstname"]',
        'child_lastname': 'input[name^="child_lastname"]',
        'birthdate': 'input[name^="birthdate"]',
        'allergies': 'input[name^="allergies"]',
        'club_membership': 'select[name^="club_membership"]'
    };

    Object.entries(inputs).forEach(([key, selector]) => {
        const element = form.querySelector(selector);
        if (element) element.setAttribute('name', `${key}_${newIndex}`);
    });
}

// Form submission handling
function initializeFormSubmission() {
    const form = document.querySelector(SELECTORS.REGISTRATION_FORM);
    if (!form) return;
    form.addEventListener('submit', handleFormSubmit);
}

async function handleFormSubmit(event) {
    event.preventDefault();
    
    if (!validateForm()) {
        return;
    }

    try {
        const formData = collectFormData();
        if (!formData) return;

        const response = await submitForm(formData);
        handleSubmissionResponse(response);
    } catch (error) {
        console.error('Submission error:', error);
        addFlashMessage(`❌Fehler beim Absenden: ${error.message}`, 'error');
    }
}

function collectFormData() {
    const children = collectChildrenData();
    if (children.length === 0) {
        addFlashMessage('❌Bitte fügen Sie mindestens ein Kind hinzu.', 'error');
        return null;
    }

    const csrfToken = document.querySelector(SELECTORS.CSRF_TOKEN)?.value?.trim();
    if (!csrfToken) {
        addFlashMessage('❌CSRF-Token fehlt. Bitte laden Sie die Seite neu.', 'error');
        return null;
    }

    return {
        csrf_token: csrfToken,
        children,
        parent_firstname: document.getElementById('parent_firstname').value,
        parent_lastname: document.getElementById('parent_lastname').value,
        phone_number: document.getElementById('phone_number').value,
        email: document.getElementById('email').value
    };
}

function collectChildrenData() {
    const children = [];
    document.querySelectorAll(SELECTORS.CHILD_FORM).forEach(form => {
        const childData = {
            child_firstname: form.querySelector('input[name^="child_firstname"]')?.value?.trim() || '',
            child_lastname: form.querySelector('input[name^="child_lastname"]')?.value?.trim() || '',
            birthdate: form.querySelector('input[name^="birthdate"]')?.value || '',
            allergies: form.querySelector('input[name^="allergies"]')?.value?.trim() || 'Keine',
            club_membership: form.querySelector('select[name^="club_membership"]')?.value || ''
        };

        if (validateChildData(childData)) {
            children.push(childData);
        }
    });
    return children;
}

function validateChildData(childData) {
    return childData.child_firstname && 
           childData.child_lastname && 
           childData.birthdate && 
           childData.club_membership;
}

async function submitForm(formData) {
    const csrfToken = formData.csrf_token;
    const response = await fetch('/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken,
            'X-Requested-With': 'XMLHttpRequest'  // Add this line
        },
        credentials: 'same-origin',
        body: JSON.stringify(formData)
    });

    const data = await response.json();
    if (data.errors) {
        Object.entries(data.errors).forEach(([field, messages]) => {
            const input = document.querySelector(`[name="${field}"]`);
            if (input) {
                const errorDiv = document.createElement('div');
                errorDiv.classList.add('validation-error');
                errorDiv.textContent = messages[0];
                input.parentNode.insertBefore(errorDiv, input.nextSibling);
                input.classList.add('error-field');
            }
        });
        return { success: false };
    }
    return data;
}

function handleSubmissionResponse(data) {
    if (data.success) {
        addFlashMessage('✅ Anmeldung erfolgreich! Sie werden weitergeleitet.', 'success');
        setTimeout(() => window.location.href = '/confirmation', 3000);
    } else {
        addFlashMessage('❌ Fehler bei der Anmeldung: ' + data.error, 'error');
    }
}

// Handle delete confirmations
const deleteButtons = document.querySelectorAll('.delete-button');
deleteButtons.forEach(button => {
    button.addEventListener('click', function(e) {
        e.preventDefault();
        const confirmDiv = document.createElement('div');
        confirmDiv.classList.add('flash-message', 'warning');
        confirmDiv.innerHTML = `
            <p>Möchten Sie diesen Eintrag wirklich löschen?</p>
            <button onclick="this.parentElement.remove();">Abbrechen</button>
            <button onclick="this.closest('form').submit();">Löschen</button>
        `;
        document.body.appendChild(confirmDiv);
    });
});