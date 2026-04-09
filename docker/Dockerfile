FROM python:3.11-slim

RUN pip install stillrunning

ENV TOKEN=""
ENV ALERT_EMAIL=""
ENV ALERT_METHOD="email"

CMD stillrunning --token $TOKEN --non-interactive
