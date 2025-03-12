#grc_stream_helper.py
import json
import logging
import re
from API.AI import client

logger = logging.getLogger(__name__)

def generate_grc_question(category, difficulty):
    """
    Generates a GRC-related multiple-choice question in JSON format.
    The model returns a JSON object with keys:
      question (string)
      options (array of 4 strings)
      correct_answer_index (int)
      explanations (dict of strings for "0","1","2","3")
      exam_tip (string)
    """
    prompt = f""" 
You are an expert in concepts found in certifications like CISSP, CompTIA Advanced Security Practitioner (CASP+), CISM, CRISC, and others. Your role is to generate 
challenging and diverse test questions using advanced mult-layered reasoning, related to governance, risk management, risk thresholds, types of risk, Audit, Management, Policy, Cyber Security Ethics, Threat Assessment, 
Leadership, Business Continuity, compliance, regulations, incident resposne, Incident Response and more. focusing on preparing for exams like CISSP/ISC2 and CompTIA certifications. Ensure the questions cover a wide range of scenarios,
principles, and concepts, with multiple-choice answers that are nuanced and complex and specific, avoiding repetitive patterns or overly simplified examples.

CONTEXT: The user has selected:
- Category: {category} (e.g., 'Regulation', 'Risk Management', 'Compliance', 'Audit', 'Governance', 'Management', 'Policy', 'Ethics', 'Threat Assessment', 'Leadership', 'Business Continuity', 'Incident Response', 'Random')
- Difficulty: {difficulty} (e.g., 'Easy', 'Medium', 'Hard')

REQUIREMENTS
1. Four options (0, 1, 2, 3) total, one correct answer. Extreme Distractor Plausibility: Every distractor is technically valid in some context—only minuscule details distinguish the correct answer.

2. Explanations:
   - Explain why the correct answer is correct with 2-3 sentences.

3. Include an "exam_tip" field that provides a short, memorable takeaway or mnemonic to help differentiate the correct concept from the others. The exam tip should help the user recall why the correct answer stands out using advanced multi-layered reasoning.

4. Return ONLY a JSON object with the fields:
   "question", "options", "correct_answer_index", "explanations", and "exam_tip"
   No extra text, no Markdown, no commentary outside the JSON.

EXAMPLE FORMAT:

{{
  "question": "The question",
  "options": ["highly plausible distractor 0","highly plausible distractor 1","highly plausible distractor 2","highly plausible distractor 3"],
  "correct_answer_index": 2,
  "explanations": {{
    2-3 sentence explanation
  }},
  "exam_tip": "A short, memorable hint or mnemonic that differentiates the correct approach from others using advanced multi-layered reasoning."
}}

Now generate the JSON object following these instructions.
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",  
            messages=[{"role": "user", "content": prompt}],
            max_tokens=750,
            temperature=0.6,
        )

        content = response.choices[0].message.content.strip()
      
        content = re.sub(r'^```.*\n', '', content)
        content = re.sub(r'\n```$', '', content)

        try:
            generated_question = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error("JSON parsing error in generate_grc_question: %s", e)
            logger.error("Model returned: %s", content)
            raise ValueError("Model did not return valid JSON.") from e

        logger.info("Generated GRC question successfully.")
        return generated_question

    except Exception as e:
        logger.error(f"Error generating GRC question: {str(e)}")
        raise

def generate_grc_questions_stream(category, difficulty):
    """
    Streams the GRC question JSON response chunk by chunk.
    Instead of returning a complete JSON object, it returns a generator
    that yields chunks of the response as they come in.
    
    Args:
        category: Question category
        difficulty: Question difficulty level
        
    Returns:
        Generator yielding chunks of JSON string
    """
    prompt = f"""
You are an expert in concepts found in certifications like CISSP, CompTIA Advanced Security Practitioner (CASP+), CISM, CRISC, and others. 
Your role is to generate a challenging and diverse test question related to governance, risk management, risk thresholds, types of risk, 
Audit, Management, Policy, Cyber Security Ethics, Threat Assessment, Leadership, Business Continuity, compliance, regulations, 
incident response, and more, focusing on preparing for exams like CISSP and CompTIA certifications. Make sure Extreme Distractor Plausibility: Every distractor is technically valid in some context—only minuscule details distinguish the correct answer.

CONTEXT: The user has selected:
- Category: {category}
- Difficulty: {difficulty}

REQUIREMENTS:
1. Generate ONE question in valid JSON format with:
   - "question": string,
   - "options": array of exactly 4 strings (indexes 0,1,2,3),
   - "correct_answer_index": integer (0,1,2,3),
   - "explanations": object with 2-3 sentences
   - "exam_tip": short mnemonic/hint.

2. The correct answer's explanation has at least 2 sentences describing precisely why it is correct, 
   and also clarifies why the others are incorrect.

3. Eplanantion should be 2-3 sentences

4. Provide an "exam_tip" as a short, memorable mnemonic or hint to help the test-taker recall the correct concept.

5. Return ONLY the JSON object. No extra text, disclaimers, or preludes.

Now generate the JSON object following these instructions. 
Remember: Provide ONLY valid JSON, nothing else.
"""

    try:
        # Make the streaming request
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=750,
            temperature=0.6,
            stream=True
        )

        def generator():
            try:
                for chunk in response:
                    delta = chunk.choices[0].delta
                    if delta:
                        content = getattr(delta, "content", None)
                        if content:
                            yield content
            except Exception as e:
                logger.error(f"Error streaming GRC question: {e}")
                yield f"{{\"error\": \"Error streaming content: {str(e)}\"}}"

        return generator()

    except Exception as e:
        logger.error(f"Error generating GRC question (stream): {e}")
        def err_gen():
            yield f"{{\"error\": \"Error generating question: {str(e)}\"}}"
        return err_gen()
