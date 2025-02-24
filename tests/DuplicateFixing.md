# Duplicate Questions Fix Method
---
## 1. Practical Methods & Ideas
### A. Deduplication Within a Single Test
#### Collect and Index Questions
---
##### Create a structured list or array of all 100 questions in the test.
##### Each entry can hold: test ID, question number, question text, correct answer, distractors, etc.
---
#### Exact String Matching
---
#### Quick check to catch verbatim duplicates.
##### If questionText is identical, mark them as duplicates.
---
##### Near-Duplicate Detection (Similarity or “Fuzzy” Matching)
---
###### Use a similarity algorithm (e.g., Levenshtein distance, fuzzywuzzy, or embeddings from an LLM).
###### If similarity exceeds a certain threshold (like 80%–90%), mark as near-duplicate.
#### Decide on Remediation
---
###### Option A: Merge duplicates by removing or replacing them.
###### Option B: Rewrite duplicates to be unique in content or phrasing.
---
### B. Deduplication Across Multiple Tests in a Category
---
#### Combine All Tests
---
###### For each category, combine the 10 tests (100 questions each → ~1,000 questions total) into a single data structure.
---
#### Identify & Tag Duplicates Across Tests
---
###### Generate embeddings or use fuzzy matching across all question texts in the category.
###### Group questions that are identical or highly similar together.
###### Maintain a “Master” List
---
###### Once you find duplicates, decide which version remains “canonical.”
###### Other duplicates get flagged for rewriting or possible removal.
---
### C. Ensuring Uniqueness with AI-Generated Text
---
#### AI-Assisted Rewriting
---
###### Provide the AI with the original question + answer set and instructions on how to rephrase it.
###### Let it produce a fresh question that keeps the same concept but uses new wording, angles, or contexts.
###### Generate Entirely New Questions
---
###### If you have generic topics (e.g., “phishing”), instruct the AI to generate brand-new questions that test the same knowledge but from a different scenario or vantage point.
---
# 2. Sample AI Prompt for Rewriting Duplicates
### Below is a template you can adapt. This prompt tells the AI how you want duplicates handled and ensures it tries to create fresh variations. You can feed it one question at a time or a small batch that are known duplicates:
---
```bash
You are an expert test-question generator focused on cybersecurity topics. 
Your task is to take the following original questions and produce entirely new versions 
that test the same concept or knowledge area, but with:

1. Different context or scenario.
2. Different wording and phrasing.
3. Potentially new distractors or answers (while maintaining correct solution validity).
4. Ensure the new question is written to be unique from the original.

Original Question: 
[INSERT DUPLICATE QUESTION TEXT HERE]

Original Answers (with correct answer labeled): 
[INSERT ANSWER CHOICES HERE]

IMPORTANT REQUIREMENTS:
- The new question must remain a single-question, multiple-choice format.
- Keep the knowledge area the same (e.g., phishing, DoS) but rewrite the question so it cannot be identified as a near-duplicate by standard duplication checks.
- Provide 4 or more answer options, with only one correct option, clearly labeled.
- The new question text must be significantly different from the original (use new examples, new characters, new scenario elements, etc.).

Now produce your revised question and its multiple-choice answers with the correct answer indicated.
```
---
### Add Variation: For a single concept, request multiple angles:
---
#### Scenario-based (e.g., Bob in HR receives a suspicious email).
#### Definition-based (e.g., “Which term describes an attack in which...”).
#### Real-world examples (e.g., referencing a known event but changing enough detail to keep it fresh).
#### Invoke “Creative Mode”:
#### In your AI prompt, specify: “Generate the question as if you are writing for a brand-new textbook, ensuring zero overlap with previously generated questions.
---
# Question Prompt
## Here’s a second prompt for when the AI doesn’t “see” your entire dataset but you want to reduce the risk of duplicates:

---
```bash
You are a professional test-question writer. 
I need unique, never-before-seen cybersecurity multiple-choice questions 
about [TOPIC AREA: e.g., Phishing, DOS Attacks, Firewalls, Encryption, etc.].

Guidelines:
1. Write [NUMBER] multiple-choice questions in English.
2. Each question must present a different scenario or perspective 
   (avoid repeating the same user names, companies, system setups).
3. Provide 4 answer choices per question, label one of them as correct clearly.
4. Provide enough detail to ensure the question stands out from others in the same topic area 
   (e.g., add subtle real-world or hypothetical details).
5. Avoid reusing text or phrasing from common open-source question banks.
6. Keep the complexity at an intermediate to advanced level.

Now create these new questions and answer choices.
```
--
###### Systematic approach 
