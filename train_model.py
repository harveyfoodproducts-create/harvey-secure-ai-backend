import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import pickle

# Load dataset
df = pd.read_csv("spam_dataset.csv")

# Features and labels
X_text = df["text"]
y = df["label"]

# Convert text → vectors
vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(X_text)

import pickle

# Load trained model
model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

# Save model
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print("✅ Model trained with dataset")