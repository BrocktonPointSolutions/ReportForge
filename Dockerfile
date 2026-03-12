FROM python:3.12-slim
LABEL version="1.2.3"
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .
EXPOSE 8000
CMD ["reportforge", "serve", "--host", "0.0.0.0", "--port", "8000"]
