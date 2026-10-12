FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir python-evtx
ENTRYPOINT ["python", "-m", "evtxtriage.cli"]
# docker run --rm -v $PWD/samples:/s evtx-triage /s/DE_1102_security_log_cleared.evtx -o /s/out
