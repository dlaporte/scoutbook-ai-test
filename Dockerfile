FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir $(python3 -c "\
import tomllib; \
deps = tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']; \
print(' '.join(deps))")

COPY . .

ENV HOME=/home/mcp
RUN mkdir -p /data && \
    useradd -m -u 1000 mcp && \
    mkdir -p /home/mcp/.local/share/fastmcp && \
    chown -R mcp:mcp /app /data /home/mcp

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import socket; s=socket.create_connection(('localhost',8000),timeout=3); s.close()" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["fastmcp", "run", "main.py", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000"]
