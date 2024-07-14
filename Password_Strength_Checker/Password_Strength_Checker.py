import re

# Common dictionary words and patterns (this list can be expanded)
common_patterns = [
    '12345', 'password', '123456789', 'qwerty', 'abc123', 'letmein', 
    '111111', 'welcome', 'monkey', 'football', 'iloveyou', 'admin', 
    'user', 'login', 'guest'
]

def check_password_strength(password):
    # Criteria weights
    length_weight = 2.0
    variety_weight = 2.0
    common_patterns_weight = 5.0
    repeated_char_weight = 3.0
    user_info_weight = 4.0

    # Password strength score
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += length_weight * len(password) / 12
    else:
        feedback.append("Password is too short. Use at least 12 characters.")

    # Character variety check
    if re.search(r'[a-z]', password):
        score += variety_weight
    else:
        feedback.append("Add lowercase letters to your password.")
    
    if re.search(r'[A-Z]', password):
        score += variety_weight
    else:
        feedback.append("Add uppercase letters to your password.")
    
    if re.search(r'\d', password):
        score += variety_weight
    else:
        feedback.append("Add digits to your password.")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += variety_weight
    else:
        feedback.append("Add special characters to your password.")

    # Common patterns check
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= common_patterns_weight
        feedback.append("Avoid common patterns or easily guessable passwords.")

    # Repeated characters check
    if re.search(r'(.)\1{2,}', password):
        score -= repeated_char_weight
        feedback.append("Avoid repeated characters or sequences.")

    # Calculate final score
    max_score = (length_weight * 2) + (variety_weight * 4)
    strength_percentage = min(max(score / max_score * 100, 0), 100)

    # Generate feedback
    if strength_percentage >= 80:
        feedback.append("Your password is strong.")
    elif strength_percentage >= 50:
        feedback.append("Your password is moderate. Consider making it stronger.")
    else:
        feedback.append("Your password is weak. Consider making it much stronger.")

    return strength_percentage, feedback

def main():
    password = input("Enter a password to check: ")

    strength_percentage, feedback = check_password_strength(password)

    print(f"Password strength: {strength_percentage:.2f}%")
    print("Feedback:")
    for comment in feedback:
        print(comment)

if __name__ == "__main__":
    main()