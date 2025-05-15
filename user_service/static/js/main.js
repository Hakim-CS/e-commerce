// Common functionality for user service frontend

// Password strength meter function
function checkPasswordStrength(password) {
    // Initialize variables
    let strength = 0;
    let tips = [];

    // If password is empty, return no strength
    if (password.length === 0) {
        return {
            strength: 0,
            message: "",
            tips: ["Enter a password"],
            color: "transparent"
        };
    }

    // Check password length
    if (password.length < 8) {
        tips.push("Make the password longer than 8 characters");
    } else {
        strength += 1;
    }

    // Check for mixed case
    if (password.match(/[a-z]/) && password.match(/[A-Z]/)) {
        strength += 1;
    } else {
        tips.push("Use both lowercase and uppercase letters");
    }

    // Check for numbers
    if (password.match(/\d/)) {
        strength += 1;
    } else {
        tips.push("Include at least one number");
    }

    // Check for special characters
    if (password.match(/[^a-zA-Z\d]/)) {
        strength += 1;
    } else {
        tips.push("Include at least one special character");
    }

    // Return the strength score and color
    let message, color;
    if (strength < 2) {
        message = "Weak";
        color = "#dc3545"; // Bootstrap danger color
    } else if (strength < 4) {
        message = "Medium";
        color = "#ffc107"; // Bootstrap warning color
    } else {
        message = "Strong";
        color = "#198754"; // Bootstrap success color
    }

    return {
        strength: strength,
        message: message,
        tips: tips,
        color: color
    };
}

// Function to validate form inputs
function validateForm(formId, fields) {
    const form = document.getElementById(formId);
    if (!form) return false;

    let isValid = true;

    fields.forEach(field => {
        const input = form.querySelector(`[name="${field.name}"]`);
        const feedbackEl = form.querySelector(`#${field.name}-feedback`);
        
        if (!input) return;

        let valid = true;
        let feedbackMessage = '';

        // Check required
        if (field.required && !input.value.trim()) {
            valid = false;
            feedbackMessage = `${field.label} is required`;
        }
        // Check email format
        else if (field.type === 'email' && input.value.trim()) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(input.value.trim())) {
                valid = false;
                feedbackMessage = 'Please enter a valid email address';
            }
        }
        // Check min length
        else if (field.minLength && input.value.length < field.minLength) {
            valid = false;
            feedbackMessage = `${field.label} must be at least ${field.minLength} characters`;
        }
        // Check matching fields
        else if (field.matchWith && input.value !== form.querySelector(`[name="${field.matchWith}"]`).value) {
            valid = false;
            feedbackMessage = `${field.label} does not match`;
        }
        // Check custom validator if provided
        else if (field.validator && !field.validator(input.value)) {
            valid = false;
            feedbackMessage = field.validatorMessage || `Invalid ${field.label}`;
        }

        // Update validation UI
        if (valid) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            if (feedbackEl) {
                feedbackEl.textContent = '';
                feedbackEl.style.display = 'none';
            }
        } else {
            input.classList.remove('is-valid');
            input.classList.add('is-invalid');
            if (feedbackEl) {
                feedbackEl.textContent = feedbackMessage;
                feedbackEl.style.display = 'block';
            }
            isValid = false;
        }
    });

    return isValid;
}

// Initialize form validation for common forms
document.addEventListener('DOMContentLoaded', function() {
    // Setup password strength meter if needed
    const passwordInput = document.getElementById('new_password') || document.getElementById('password');
    const strengthMeter = document.getElementById('password-strength-meter');
    const strengthText = document.getElementById('password-strength-text');
    const strengthTips = document.getElementById('password-strength-tips');
    
    if (passwordInput && (strengthMeter || strengthText)) {
        passwordInput.addEventListener('input', function() {
            const result = checkPasswordStrength(this.value);
            
            if (strengthMeter) {
                strengthMeter.style.width = `${(result.strength / 4) * 100}%`;
                strengthMeter.style.backgroundColor = result.color;
            }
            
            if (strengthText) {
                strengthText.textContent = result.message;
                strengthText.style.color = result.color;
            }
            
            if (strengthTips) {
                strengthTips.innerHTML = result.tips.length > 0 ? 
                    '<ul>' + result.tips.map(tip => `<li>${tip}</li>`).join('') + '</ul>' : '';
            }
        });
    }
    
    // Setup form validation for login form
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const fields = [
                { name: 'username', label: 'Username', required: true },
                { name: 'password', label: 'Password', required: true }
            ];
            
            if (!validateForm('login-form', fields)) {
                e.preventDefault();
            }
        });
    }
    
    // Setup form validation for password change form
    const changePasswordForm = document.getElementById('change-password-form');
    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', function(e) {
            const fields = [
                { name: 'old_password', label: 'Current Password', required: true },
                { name: 'new_password', label: 'New Password', required: true, minLength: 8 },
                { name: 'confirm_password', label: 'Confirm Password', required: true, matchWith: 'new_password' }
            ];
            
            if (!validateForm('change-password-form', fields)) {
                e.preventDefault();
            }
        });
    }
});

// Utility function for making API calls
async function apiCall(url, method = 'GET', data = null, token = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json'
        }
    };
    
    if (token) {
        options.headers['Authorization'] = `Bearer ${token}`;
    }
    
    if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(url, options);
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || `HTTP error! Status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('API call error:', error);
        throw error;
    }
}

// Function to show toast notifications
function showToast(message, type = 'success', duration = 5000) {
    // Create toast container if it doesn't exist
    let toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    // Create toast element
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.setAttribute('id', toastId);
    
    // Toast content
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    // Add to container
    toastContainer.appendChild(toast);
    
    // Initialize and show toast
    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: duration
    });
    bsToast.show();
    
    // Remove from DOM after hiding
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}
