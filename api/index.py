import os
import sys

# Add the 'backend' folder to the Python path so Vercel can find the 'app' module
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.main import app
