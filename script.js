// Function 1: Sanitize Input (Prevent XSS)
function sanitizeInput(input) {
    var element = document.createElement('div');
    element.innerText = input; // Automatically encodes special characters to prevent script execution
    return element.innerHTML;
}

// Function 2: Allowlist Input Validation (Only Alphanumeric Characters Allowed)
function allowlistInput(input) {
    const regex = /^[a-zA-Z0-9]+$/; // Only allows letters and numbers
    return regex.test(input);
}

// Function 3: Password Strength Validation
function validatePasswordStrength(password) {
    const regex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$/; // Minimum 8 characters, with at least one letter and one number
    return regex.test(password);
}

// Function 4: Encode Output (Prevent XSS)
function encodeOutput(input) {
    return input.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Function 5: Escape Special Characters for SQLi (for Server-Side Escaping)
function escapeForSQL(input) {
    const sqlMetaChars = ["'", '"', "\\", ";", "--"];
    for (let char of sqlMetaChars) {
        input = input.replace(new RegExp("\\" + char, "g"), "\\" + char); // Escape special characters for SQL
    }
    return input;
}

// Function 6: Prevent Direct Concatenation for SQLi (Use parameterized queries on server-side)
function preventSQLConcatenation(query, params) {
    // This is just a placeholder for server-side parameterized queries. On the server-side, always use prepared statements.
    // For example: `SELECT * FROM users WHERE username = ? AND password = ?`
    // Server-side framework like PDO or MySQLi should be used for this.
    return query; // Placeholder
}

// Validate the form
function validateForm() {
    let firstName = document.signupForm.firstName.value;
    let lastName = document.signupForm.lastName.value;
    let email = document.signupForm.email.value;
    let password = document.signupForm.password.value;
    let confirmPassword = document.signupForm.confirmPassword.value;

    // Check for empty fields
    if (firstName === "" || lastName === "" || email === "" || password === "" || confirmPassword === "") {
        showError("All fields are required.");
        return false;
    }

    // Function 2: Allowlist Input Validation (Only Alphanumeric Characters for Names)
    if (!allowlistInput(firstName) || !allowlistInput(lastName)) {
        showError("First name and last name can only contain letters and numbers.");
        return false;
    }

    // Function 3: Password Strength Validation
    if (!validatePasswordStrength(password)) {
        showError("Password must be at least 8 characters long and contain both letters and numbers.");
        return false;
    }

    // Password match check
    if (password !== confirmPassword) {
        showError("Passwords do not match.");
        return false;
    }

    // Sanitize inputs to prevent XSS
    firstName = sanitizeInput(firstName);
    lastName = sanitizeInput(lastName);
    email = sanitizeInput(email);
    password = sanitizeInput(password);
    confirmPassword = sanitizeInput(confirmPassword);

    // Escape SQL special characters
    firstName = escapeForSQL(firstName);
    lastName = escapeForSQL(lastName);
    email = escapeForSQL(email);
    password = escapeForSQL(password);

    // Clear any previous error message
    clearError();

    return true; // If everything is valid
}

// Display error message
function showError(message) {
    let errorDiv = document.getElementById('errorMessage');
    errorDiv.textContent = message;
}

// Clear error message
function clearError() {
    let errorDiv = document.getElementById('errorMessage');
    errorDiv.textContent = "";
}

// Password Strength Checker
function checkPasswordStrength() {
    const password = document.getElementById("password").value;
    const strengthIndicator = document.getElementById("passwordStrengthIndicator");

    if (password.length < 6) {
        strengthIndicator.textContent = "Weak";
        strengthIndicator.className = "password-strength weak";
    } else if (password.length >= 6 && password.length < 10) {
        strengthIndicator.textContent = "Medium";
        strengthIndicator.className = "password-strength medium";
    } else if (password.length >= 10) {
        strengthIndicator.textContent = "Strong";
        strengthIndicator.className = "password-strength strong";
    }
}
