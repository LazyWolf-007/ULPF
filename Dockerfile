FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ulpf/ ulpf/
COPY samples/ samples/

RUN python -m ulpf.pipeline samples out

CMD ["python", "-u", "-m", "ulpf.app", "out"]
