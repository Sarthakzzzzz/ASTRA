import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

# Load environment variables from .env file
load_dotenv()

def get_model(json_mode=False):
    """Returns a LangChain ChatGoogleGenerativeAI model."""
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if api_key:
        api_key = api_key.strip()
    
    if not api_key:
        raise ValueError("GEMINI_API_KEY or GOOGLE_API_KEY environment variable is missing")
    
    # Use the model name as requested
    model_name = "gemini-2.5-flash-lite"
    
    model = ChatGoogleGenerativeAI(
        model=model_name,
        google_api_key=api_key,
        temperature=0.3,
        max_output_tokens=2048,
        timeout=15
    )
    
    if json_mode:
        # LangChain handles JSON mode via bind_tools or specific templates, 
        # but for simple compatibility we can inject it into the model configuration if needed.
        # However, ChatGoogleGenerativeAI doesn't directly take response_mime_type in __init__
        # and instead uses .with_structured_output() or prompt engineering.
        pass

    return model
