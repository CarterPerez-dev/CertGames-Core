import json
import logging
import re
from API.AI import client  

logger = logging.getLogger(__name__)

def generate_scenario(industry, attack_type, skill_level, threat_intensity):
    """
    Streams a scenario chunk-by-chunk from the LLM.
    """
    try:
        prompt = (
            f"Imagine a cybersecurity incident involving the {industry} industry. "
            f"The attack is of type {attack_type}, performed by someone with a skill level of {skill_level}, "
            f"and the threat intensity is rated as {threat_intensity} on a scale from 1-100. "
            "Provide enough details and a thorough story/scenario to explain the context/story as well as thoroughly "
            "explain the attack in a technical way and how it works in 3 paragraphs with a minimum of 5 sentences each. "
            "Then output actors in another paragraph (at least 3 sentences), then potential risks in another paragraph (at least 5 sentences), "
            "then mitigation steps in another paragraph (at least 3 sentences). Use paragraph breaks (new lines '\\n') between each section, "
            "so it is easy to read. Each section should be easy to understand but also in depth, technical, and educational."
        )

        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="gpt-4o-latest",
            max_tokens=1100,
            temperature=0.6,
            stream=True
        )

        def generator():
            try:
                for chunk in response:
                    if not hasattr(chunk, 'choices') or not chunk.choices:
                        continue
                        
                    choice = chunk.choices[0]
                    if not hasattr(choice, 'delta'):
                        continue
                    
                    # Try multiple ways to get content
                    delta = choice.delta
                    content = None
                    
                    # Method 1: Using getattr
                    try:
                        content = getattr(delta, "content", None)
                    except Exception as e:
                        logger.debug(f"Method 1 failed: {e}")
                    
                    # Method 2: Dictionary-style access
                    if content is None and hasattr(delta, "__getitem__"):
                        try:
                            content = delta["content"]
                        except (KeyError, TypeError) as e:
                            logger.debug(f"Method 2 failed: {e}")
                    
                    # Method 3: If delta itself is the content (string)
                    if content is None and isinstance(delta, str):
                        content = delta
                    
                    # Method 4: If delta has a method to get content
                    if content is None and hasattr(delta, "get"):
                        try:
                            content = delta.get("content", None)
                        except Exception as e:
                            logger.debug(f"Method 4 failed: {e}")
                    
                    # Method 5: Convert delta to dict if possible
                    if content is None and hasattr(delta, "__dict__"):
                        try:
                            delta_dict = delta.__dict__
                            content = delta_dict.get("content", None)
                        except Exception as e:
                            logger.debug(f"Method 5 failed: {e}")
                    
                    if content:
                        yield content
            except Exception as e:
                logger.error(f"Error while streaming scenario: {str(e)}")
                yield f"\n[Error occurred during streaming: {str(e)}]\n"

        return generator()

    except Exception as e:
        logger.error(f"Error generating scenario: {str(e)}")
        def err_gen():
            yield f"[Error generating scenario: {str(e)}]"
        return err_gen()

def break_down_scenario(scenario_text):
    """
    Example of further processing if needed.
    """
    return {
        "context": extract_context(scenario_text),
        "actors": extract_actors(scenario_text),
        "risks": extract_risks(scenario_text),
        "mitigation_steps": extract_mitigation(scenario_text)
    }

def extract_context(scenario_text):
    context_match = re.search(r"(.*?)(?:The attack|The adversary|The threat)", scenario_text, re.IGNORECASE)
    return context_match.group(0).strip() if context_match else "Context not found."

def extract_actors(scenario_text):
    actors_match = re.findall(r"\b(?:threat actor|adversary|attacker|insider)\b.*?", scenario_text, re.IGNORECASE)
    return actors_match if actors_match else ["Actors not found."]

def extract_risks(scenario_text):
    risks_match = re.findall(r"(risk of .*?)(\.|;|:)", scenario_text, re.IGNORECASE)
    risks = [risk[0] for risk in risks_match]
    return risks if risks else ["Risks not found."]

def extract_mitigation(scenario_text):
    mitigation_match = re.findall(r"(mitigation step|to mitigate|response step): (.*?)(\.|;|:)", scenario_text, re.IGNORECASE)
    mitigations = [step[1] for step in mitigation_match]
    return mitigations if mitigations else ["Mitigation steps not found."]

def generate_interactive_questions(scenario_text, retry_count=0):
    """
    Generate EXACTLY THREE advanced multiple-choice questions in JSON array form.
    We stream partial chunks as they arrive, but also accumulate them. 
    At the end, we do a final parse where we:
      - remove fences/backticks
      - use a regex to find the bracketed JSON array
    If we can't parse it, we optionally retry up to 2 times.
    """
    system_instructions = (
        "You are a highly intelligent cybersecurity tutor. You must follow formatting instructions exactly, "
        "with no extra disclaimers or commentary."
    )

    user_prompt = f"""
Below is a detailed cyberattack scenario:

{scenario_text}

Your task:
1) Generate exactly THREE advanced, non-trivial multiple-choice questions based on the scenario, requiring critical thinking and highly plasuible ditstractors to prvent process of eliminination, or specialized cybersecurity knowledge beyond merely re-reading the text.
2) Each question must have four options labeled 'A', 'B', 'C', and 'D' (no extra letters or symbols).
3) Indicate the correct answer with a key 'correct_answer' whose value is a single letter (e.g., 'B').
4) Provide a concise 'explanation' focusing on why the correct answer is correct (and relevant to the scenario or cybersecurity concepts).
5) Your output MUST be a valid JSON array with exactly three objects. No disclaimers, no extra text, and no surrounding characters.

Example format:

[
  {{
    "question": "Given the company's reliance on AI, which method best defends against membership inference?",
    "options": {{
      "A": "Basic encryption",
      "B": "Differential privacy",
      "C": "Physical access controls",
      "D": "Frequent model re-training"
    }},
    "correct_answer": "B",
    "explanation": "Differential privacy adds noise to the data, making it harder for attackers to infer membership."
  }},
  // ... two more questions
]

Nothing else.
"""

    try:
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_instructions},
                {"role": "user", "content": user_prompt},
            ],
            model="gpt-4o-latest",
            max_tokens=1200,
            temperature=0.3,
            stream=True
        )

        accumulated_response = ""

        def chunk_generator():
            nonlocal accumulated_response
            try:
                for chunk in response:
                    # Debug: Print the structure of the chunk
                    logger.debug(f"Chunk type: {type(chunk)}")
                    logger.debug(f"Chunk structure: {dir(chunk)}")
                    
                    if not hasattr(chunk, 'choices') or not chunk.choices:
                        continue
                        
                    choice = chunk.choices[0]
                    if not hasattr(choice, 'delta'):
                        continue
                    
                    # Debug the delta object
                    delta = choice.delta
                    logger.debug(f"Delta type: {type(delta)}")
                    logger.debug(f"Delta structure: {dir(delta)}")
                    
                    # Try multiple ways to get content
                    content = None
                    
                    # Method 1: Using getattr
                    try:
                        content = getattr(delta, "content", None)
                    except Exception as e:
                        logger.debug(f"Method 1 failed: {e}")
                    
                    # Method 2: Dictionary-style access
                    if content is None and hasattr(delta, "__getitem__"):
                        try:
                            content = delta["content"]
                        except (KeyError, TypeError) as e:
                            logger.debug(f"Method 2 failed: {e}")
                    
                    # Method 3: If delta itself is the content (string)
                    if content is None and isinstance(delta, str):
                        content = delta
                    
                    # Method 4: If delta has a method to get content
                    if content is None and hasattr(delta, "get"):
                        try:
                            content = delta.get("content", None)
                        except Exception as e:
                            logger.debug(f"Method 4 failed: {e}")
                    
                    # Method 5: Convert delta to dict if possible
                    if content is None and hasattr(delta, "__dict__"):
                        try:
                            delta_dict = delta.__dict__
                            content = delta_dict.get("content", None)
                        except Exception as e:
                            logger.debug(f"Method 5 failed: {e}")
                    
                    if content:
                        accumulated_response += content
                        yield content
                        
            except Exception as e:
                logger.error(f"Error streaming interactive questions: {str(e)}")
                if retry_count < 2:
                    logger.info(f"Retrying interactive questions generation (Attempt {retry_count + 2})")
                    yield from generate_interactive_questions(scenario_text, retry_count + 1)
                else:
                    yield json.dumps([{"error": f"Error occurred: {str(e)}"}])

        # The chunk_generator yields partial data as it arrives
        # After it's done, we parse the full text we have in accumulated_response
        def finalize():
            # This function is called after we finish streaming. We validate the final JSON.
            try:
                cleaned = accumulated_response.strip()
                logger.debug(f"Final accumulated response: {cleaned[:100]}...")

                # Strip code fences if present
                cleaned = re.sub(r"```[\w]*\n?", "", cleaned)
                # Attempt to find the bracketed JSON array
                # We'll look for something that starts with [ and ends with ]
                match = re.search(r"\[\s*\{.*\}\s*\]", cleaned, re.DOTALL)
                if match:
                    final_json_str = match.group(0).strip()
                    # Now parse
                    parsed = json.loads(final_json_str)
                    if isinstance(parsed, list) and len(parsed) == 3:
                        logger.debug("Successfully generated three interactive questions (final parse).")
                    else:
                        logger.error("Model did not generate exactly three questions in final parse.")
                else:
                    logger.error("No bracketed JSON array found in final interactive questions text.")
            except json.JSONDecodeError as je:
                logger.error(f"JSON decode error in final parse: {je}")
                logger.error(f"Content received: {accumulated_response}")
            except Exception as e:
                logger.error(f"Unexpected error in final parse: {e}")

        # We return a generator that first yields the chunked data
        # Then yields nothing more but triggers 'finalize' at the end
        def master_generator():
            for c in chunk_generator():
                yield c
            # Once done streaming, we do final parse checks
            finalize()

        return master_generator()

    except Exception as e:
        logger.error(f"Error generating interactive questions: {e}")
        if retry_count < 2:
            logger.info(f"Retrying interactive questions generation (Attempt {retry_count + 2})")
            return generate_interactive_questions(scenario_text, retry_count + 1)
        else:
            def err_gen():
                yield json.dumps([{"error": f"Error generating interactive questions: {str(e)}"}])
            return err_gen()
