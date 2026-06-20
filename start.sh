#!/bin/bash
osascript -e 'tell app "Terminal" to do script "cd ~/Desktop/fishing-ai && source venv/bin/activate && uvicorn api.main:app --reload --port 8000"'
osascript -e 'tell app "Terminal" to do script "cd ~/Desktop/fishing-ai/dashboard && npm run dev"'
osascript -e 'tell app "Terminal" to do script "cd ~/Desktop/fishing-ai && source venv/bin/activate && celery -A pipeline.worker worker --loglevel=info -Q critical,high,normal"'
osascript -e 'tell app "Terminal" to do script "cd ~/Desktop/fishing-ai && source venv/bin/activate && celery -A pipeline.worker beat --loglevel=info"'
