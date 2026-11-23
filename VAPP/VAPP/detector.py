
import math
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix


class VAPPThreatDetector:
    def __init__(self):
        self.feature_names = [
            "failed_attempts",
            "unique_ports",
            "event_rate",
            "suspicious_keyword",
            "unusual_port"
        ]

        self.model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight="balanced"
        )

        self.train_model()

    def get_training_data(self):
        data = [
            [0, 1, 1, 0, 0, "Normal"],
            [1, 1, 2, 0, 0, "Normal"],
            [0, 1, 2, 0, 0, "Normal"],
            [2, 1, 3, 0, 0, "Normal"],

            [5, 1, 8, 1, 22, "Brute Force"],
            [8, 1, 12, 1, 22, "Brute Force"],
            [10, 1, 15, 1, 22, "Brute Force"],
            [15, 1, 20, 1, 22, "Brute Force"],

            [0, 5, 10, 1, 0, "Port Scan"],
            [0, 10, 20, 1, 0, "Port Scan"],
            [1, 15, 30, 1, 0, "Port Scan"],
            [0, 20, 40, 1, 0, "Port Scan"],

            [2, 1, 5, 1, 0, "Suspicious Activity"],
            [3, 2, 7, 1, 0, "Suspicious Activity"],
            [4, 2, 9, 1, 0, "Suspicious Activity"],
            [2, 3, 10, 1, 0, "Suspicious Activity"]
        ]

        columns = self.feature_names + ["label"]
        return pd.DataFrame(data, columns=columns)

    def train_model(self):
        data = self.get_training_data()
        X = data[self.feature_names]
        y = data["label"]
        self.model.fit(X, y)

    def validate_event(self, event):
        if not isinstance(event, dict):
            raise ValueError("Event must be a dictionary.")

        validated = {}

        integer_fields = [
            "failed_attempts",
            "unique_ports",
            "unusual_port"
        ]

        for field in self.feature_names:
            value = event.get(field, 0 if field in [
                "failed_attempts",
                "suspicious_keyword",
                "unusual_port"
            ] else 1)

            if isinstance(value, bool):
                value = int(value)

            try:
                value = float(value)
            except (TypeError, ValueError):
                raise ValueError(f"{field} must be numeric.")

            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{field} must be a finite non-negative number.")

            if field in integer_fields and not value.is_integer():
                raise ValueError(f"{field} must be a whole number.")

            if field == "suspicious_keyword" and value not in (0, 1):
                raise ValueError("suspicious_keyword must be 0 or 1.")

            if field == "unusual_port" and value > 65535:
                raise ValueError("unusual_port cannot exceed 65535.")

            validated[field] = int(value) if field in integer_fields else value

        return validated

    def analyze(self, event):
        validated_event = self.validate_event(event)

        features = pd.DataFrame(
            [validated_event],
            columns=self.feature_names
        )

        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        confidence = max(probabilities) * 100

        return {
            "threat_type": prediction,
            "confidence": round(confidence, 2)
        }

    def evaluate_model(self):
        data = self.get_training_data()
        X = data[self.feature_names]
        y = data["label"]

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.25,
            random_state=42,
            stratify=y
        )

        evaluation_model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight="balanced"
        )

        evaluation_model.fit(X_train, y_train)
        predictions = evaluation_model.predict(X_test)

        print("\nClassification Report:")
        print(classification_report(y_test, predictions, zero_division=0))

        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, predictions))

        print("\nNote: Evaluation uses a very small synthetic dataset.")
        print("It does not establish real-world detection accuracy.")


detector = VAPPThreatDetector()
