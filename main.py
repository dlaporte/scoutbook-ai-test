import logging
import os

log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

from fastmcp import FastMCP
from bsa_oauth_provider import BSAOAuthProvider

auth_provider = BSAOAuthProvider()

mcp = FastMCP(
    name="scoutbook-openapi",
    instructions="""\
BSA Scoutbook MCP server — read-only access to Scoutbook data for unit leaders, \
committee members, and district volunteers. Authentication is handled via OAuth; \
your client will open a browser login page automatically when needed.

Tools are auto-generated from the BSA Scoutbook OpenAPI specification. Each API \
endpoint is available as a separate tool.\
""",
    auth=auth_provider,
)

# Register every OpenAPI endpoint as a separate MCP tool
from openapi_tools import register_openapi_tools

tool_count = register_openapi_tools(mcp)

logger = logging.getLogger("scoutbook.main")
logger.info("Server ready with %d auto-generated tools from OpenAPI spec", tool_count)
