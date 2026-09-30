FROM python:3.12-slim
WORKDIR /app
COPY memorize-lab.html ./
COPY backend/server.py ./backend/server.py
ENV PORT=8765
ENV ML_STATIC_DIR=/app
ENV ML_DB_PATH=/app/backend/memorize.db
EXPOSE 8765
CMD ["python", "backend/server.py"]
