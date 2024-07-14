class PhishingAwarenessGame:
    def __init__(self):
        self.scenarios = [
            {
                "text": "You receive an email from your bank asking you to confirm your account details by clicking on a link.",
                "is_phishing": True,
                "explanation": "Legitimate banks never ask for sensitive information via email. This is a common phishing technique to steal your details."
            },
            {
                "text": "You get a message from a friend on social media with a link to a funny video.",
                "is_phishing": True,
                "explanation": "This could be a phishing attempt if your friend's account was compromised. Always verify the link before clicking."
            },
            {
                "text": "Your IT department sends an email asking you to reset your password through the company's internal portal.",
                "is_phishing": False,
                "explanation": "If the email comes from a known, trusted source and directs you to the official internal portal, it is likely legitimate. Always double-check the URL."
            },
            {
                "text": "You receive a promotional email from a well-known online store offering huge discounts, but the sender's email address looks suspicious.",
                "is_phishing": True,
                "explanation": "Check the sender's email address carefully. Phishers often use email addresses that look similar to legitimate ones."
            },
            {
                "text": "An email from your company's HR department asks you to complete a mandatory training by the end of the week.",
                "is_phishing": False,
                "explanation": "If the email is from a known HR representative and directs you to the company's official training platform, it is likely legitimate."
            }
        ]
        self.score = 0

    def start(self):
        print("Welcome to the Phishing Awareness Game!")
        print("Read each scenario and decide if it's a phishing attempt or not.\n")
        self.run_quiz()
        self.show_final_score()

    def run_quiz(self):
        for index, scenario in enumerate(self.scenarios):
            print(f"Scenario {index + 1}:")
            print(scenario["text"])
            answer = input("Is this a phishing attempt? (yes/no): ").strip().lower()
            self.check_answer(answer, scenario)
            print("\n")

    def check_answer(self, answer, scenario):
        if (answer == 'yes' and scenario["is_phishing"]) or (answer == 'no' and not scenario["is_phishing"]):
            self.score += 1
            print("Correct!")
        else:
            print("Incorrect.")
        print(f"Explanation: {scenario['explanation']}")

    def show_final_score(self):
        print(f"\nYour final score: {self.score}/{len(self.scenarios)}")
        if self.score == len(self.scenarios):
            print("Excellent! You have a good understanding of phishing techniques.")
        elif self.score >= len(self.scenarios) / 2:
            print("Good job! But there's still room for improvement.")
        else:
            print("It looks like you need to learn more about phishing. Stay vigilant and learn from the explanations.")

if __name__ == "__main__":
    game = PhishingAwarenessGame()
    game.start()
