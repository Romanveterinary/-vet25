function togglePasswordVisibility(fieldId) {
    const el = document.getElementById(fieldId);
    if (el) {
        el.type = (el.type === "password") ? "text" : "password";
    }
}