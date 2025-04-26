#analogy_stream_helper.py
import logging
from API.AI import client
import json
from helpers.ai_guard import apply_ai_guardrails, get_streaming_error_generator
from ai_utils import get_current_user_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def generate_analogy_stream(analogy_type, concept1, concept2=None, concept3=None, category="real-world", user_id=None):
    """
    Generate an analogy and stream the results token by token.
    Returns a generator that yields partial text chunks as they're generated.
    
    Args:
        analogy_type: Type of analogy ('single', 'comparison', 'triple')
        concept1: Primary concept
        concept2: Secondary concept (for comparison or triple)
        concept3: Tertiary concept (for triple only)
        category: Context category for the analogy
        
    Returns:
        Generator yielding text chunks
    """
    prompt = ""
    
    if analogy_type == "single":
        prompt = (
            f"Generate an analogy for the concept '{concept1}' using the context of '{category}'. "
            "Make it easy to understand but informative and in a teaching style, concise but in depth, "
            "and entertaining, with one key info at the end to make sure the info is remembered. "
            "Do not explicitly say that you will create the analogy just output the analogy/explanation only."
        )
    elif analogy_type == "comparison":
        prompt = (
            f"Compare '{concept1}' and '{concept2}' using an analogy in the context of '{category}'. "
            "Explain how they are similar and different or how they might work in conjunction with each other, "
            "in a teaching style, informative, concise but in depth, and entertaining, with one key info at the end "
            "to make sure the info is remembered. Do not explicitly say that you will create the analogy just output "
            "the analogy/explanation only."
        )
    elif analogy_type == "triple":
        prompt = (
            f"Compare '{concept1}', '{concept2}', and '{concept3}' using an analogy in the context of '{category}'. "
            "Explain how they are similar and different or how they might work in conjunction with each other, "
            "in a teaching style, informative, concise but in depth, and entertaining, with one key info at the end "
            "to make sure the info is remembered. Do not explicitly say that you will create the analogy just output "
            "the analogy/explanation only."
        )
    else:
        # Default to single if type not recognized
        prompt = (
            f"Generate an analogy for the concept '{concept1}' using the context of '{category}'. "
            "Make it easy to understand but informative and in a teaching style, concise but in depth, "
            "and entertaining, with one key info at the end to make sure the info is remembered. "
            "Do not explicitly say that you will create the analogy just output the analogy/explanation only."
        )
    
    logger.debug(f"Analogy stream prompt: {prompt[:100]}...")
    
    
    proceed, prompt, error_message = apply_ai_guardrails(prompt, 'analogy', user_id)
    if not proceed:
        return get_streaming_error_generator(error_message)
        
    try:
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="gpt-4o",
            max_tokens=1200, 
            temperature=0.7,
            stream=True
        )
        
        def generator():
            try:
                for chunk in response:
                    if chunk.choices and chunk.choices[0].delta:
                        content = getattr(chunk.choices[0].delta, "content", None)
                        if content:
                            yield content
            except Exception as e:
                logger.error(f"Error while streaming analogy: {str(e)}")
                yield f"\n[Error occurred during streaming: {str(e)}]\n"
        
        return generator()
    
    except Exception as e:
        logger.error(f"Error generating analogy stream: {str(e)}")
        def error_generator():
            yield f"[Error generating analogy: {str(e)}]"
        return error_generator()
