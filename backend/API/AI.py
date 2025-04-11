import os
import logging
from openai import OpenAI
from dotenv import load_dotenv

# OPENAI KEY = sk-Z97lA2Xj058o561VERVumY457C5T3vN4nD2r8JE5qbbt8W42mD168vkllSo7xE4Eh49g3A2L3b5Elgqv9ynW4IHzh0P8jE6m


# KIDDDDDING, YOU REALLY THOUGHT I WAS THAT DUMB???

load_dotenv()


logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def load_api_key() -> str:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        logger.error("OpenAI API key is missing. Please ensure it's set in the environment variables.")
        raise ValueError("OpenAI API key is required but not found.")
    return api_key


api_key = load_api_key()
client = OpenAI(api_key=api_key)



