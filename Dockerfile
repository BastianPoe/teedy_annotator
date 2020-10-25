FROM python:3.7-alpine

COPY annotator.py /
WORKDIR /

CMD ["python3", "/annotator.py", "-i", "/import", "-c", "/annotator.cfg", "-l", "/annotator.log"]
