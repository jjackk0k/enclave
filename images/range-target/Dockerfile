# Enclave RANGE — isolated, disposable, deliberately-vulnerable practice target.
# Lives on the sealed lab network at a fixed in-scope IP so operators can safely
# scan/exploit IT (and nothing else) to test what they build. Non-root; no secrets.
FROM python:3.12-alpine
RUN adduser -D -u 1000 target
COPY vuln-server.py /vuln-server.py
USER target
EXPOSE 8080
LABEL org.enclave.role="range-target" org.enclave.warning="deliberately vulnerable — lab use only"
CMD ["python3", "/vuln-server.py"]
