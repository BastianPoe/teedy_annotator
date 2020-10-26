FROM python:3.7-slim

COPY requirements.txt /
RUN pip install -r /requirements.txt

COPY annotator.py /
WORKDIR /

CMD ["python3", "/annotator.py", "-i", "/import", "-c", "/annotator.cfg", "-l", "/annotator.log", "-t", "/tags"]
