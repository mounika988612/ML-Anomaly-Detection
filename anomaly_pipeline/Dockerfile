# Scoring service image (CPU). The model bundle is NOT baked in: mount it read-only at /models/prod.
#   docker build -t ids-detect .
#   docker run --rm -p 8080:8080 -e IDS_API_KEYS=change-me -v "$PWD/models/prod:/models/prod:ro" ids-detect
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY ids_pipeline ./ids_pipeline
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch \
 && pip install --no-cache-dir --prefix=/install ".[serve]" --extra-index-url https://download.pytorch.org/whl/cpu

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 IDS_BUNDLE_DIR=/models/prod OMP_NUM_THREADS=2
COPY --from=build /usr/local /usr/local
COPY --from=build /install /usr/local
RUN useradd --system --uid 10001 --no-create-home ids
USER ids
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=4).status == 200 else 1)"
ENTRYPOINT ["ids-detect"]
CMD ["serve", "--bundle", "/models/prod", "--host", "0.0.0.0", "--port", "8080"]
