"""Dynamically generate MCP tools from an OpenAPI 3.0 spec.

This module reads openapi.yaml and registers one MCP tool per endpoint.
Each tool exposes path parameters, query parameters, and request body
fields as function arguments, with docstrings pulled from the OpenAPI
descriptions.
"""

import json
import logging
import re
from pathlib import Path

import yaml

from api import api_request
from auth import get_auth

logger = logging.getLogger("scoutbook.openapi_tools")

# Path parameters use {name} syntax in OpenAPI
PATH_PARAM_RE = re.compile(r"\{(\w+)\}")


def _sanitize_name(path: str, method: str) -> str:
    """Convert an OpenAPI path + method to a valid Python function / tool name.

    Examples:
        GET  /persons/{personGuid}/profile          -> get_persons_profile
        POST /advancements/advancementHistory       -> post_advancements_advancementhistory
        GET  /advancements/v2/youth/{userId}/ranks  -> get_advancements_v2_youth_ranks
        GET  /lookups/address/countries              -> get_lookups_address_countries
    """
    # Remove path parameters
    clean = PATH_PARAM_RE.sub("", path)
    # Remove leading/trailing slashes and collapse doubles
    clean = clean.strip("/").replace("//", "/")
    # Replace slashes and hyphens with underscores
    clean = clean.replace("/", "_").replace("-", "_")
    # Lowercase
    clean = clean.lower()
    # Remove consecutive underscores
    while "__" in clean:
        clean = clean.replace("__", "_")
    clean = clean.strip("_")
    return f"{method.lower()}_{clean}"


def _build_docstring(op: dict, path: str, method: str, params: list, body_props: dict | None) -> str:
    """Build a docstring from the OpenAPI operation, including parameter descriptions."""
    parts = []

    # Summary
    summary = op.get("summary", "")
    if summary:
        parts.append(summary)

    # Description
    desc = op.get("description", "")
    if desc:
        parts.append("")
        parts.append(desc.strip())

    # Endpoint info
    parts.append("")
    parts.append(f"API endpoint: {method.upper()} {path}")

    # Tags
    tags = op.get("tags", [])
    if tags:
        parts.append(f"Category: {', '.join(tags)}")

    # Parameters section
    if params:
        parts.append("")
        parts.append("Parameters:")
        for p in params:
            name = p.get("name", "")
            p_desc = p.get("description", "")
            p_in = p.get("in", "")
            required = p.get("required", False)
            schema = p.get("schema", {})
            p_type = schema.get("type", "string")
            p_format = schema.get("format", "")
            default = schema.get("default")
            enum = schema.get("enum", [])

            line = f"  - {name} ({p_in}, {p_type}"
            if p_format:
                line += f", format: {p_format}"
            if required:
                line += ", required"
            else:
                line += ", optional"
            if default is not None:
                line += f", default: {default}"
            line += ")"
            if p_desc:
                line += f": {p_desc}"
            if enum:
                line += f" Allowed values: {', '.join(str(e) for e in enum)}"
            parts.append(line)

    # Request body section
    if body_props:
        parts.append("")
        parts.append("Request body fields:")
        for name, schema in body_props.items():
            p_type = schema.get("type", "any")
            p_desc = schema.get("description", "")
            enum = schema.get("enum", [])
            default = schema.get("default")
            line = f"  - {name} ({p_type}"
            if default is not None:
                line += f", default: {default}"
            line += ")"
            if p_desc:
                line += f": {p_desc}"
            if enum:
                line += f" Allowed values: {', '.join(str(e) for e in enum)}"
            parts.append(line)

    # Response info
    responses = op.get("responses", {})
    if responses:
        parts.append("")
        parts.append("Responses:")
        for code, resp in responses.items():
            resp_desc = resp.get("description", "")
            parts.append(f"  - {code}: {resp_desc}")

    return "\n".join(parts)


def _make_tool_func(path: str, method: str, op: dict):
    """Create an async function that calls the BSA API for this endpoint."""
    params = op.get("parameters", [])

    # Extract request body properties
    body_schema = None
    body_props = {}
    body_required_fields = []
    request_body = op.get("requestBody", {})
    if request_body:
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        body_schema = json_content.get("schema", {})
        if body_schema.get("type") == "object":
            body_props = body_schema.get("properties", {})
            body_required_fields = body_schema.get("required", [])
        elif body_schema.get("type") == "array":
            # For array request bodies (like empty []), we'll handle specially
            body_props = {"_request_body": body_schema}

    # Separate path params from query params
    path_params = [p for p in params if p.get("in") == "path"]
    query_params = [p for p in params if p.get("in") == "query"]

    docstring = _build_docstring(op, path, method, params, body_props if body_props else None)

    # Build the function signature dynamically
    # All parameters become keyword arguments
    all_param_names = []
    for p in path_params:
        all_param_names.append(p["name"])
    for p in query_params:
        all_param_names.append(p["name"])
    for name in body_props:
        if name != "_request_body":
            all_param_names.append(name)

    # We need to handle the case where body is a plain array
    has_array_body = (body_schema and body_schema.get("type") == "array"
                      and "_request_body" in body_props)

    async def tool_func(**kwargs) -> str:
        auth = get_auth()

        # Build the actual path with substituted parameters
        actual_path = path
        for p in path_params:
            name = p["name"]
            value = kwargs.get(name, "")
            if not value:
                return json.dumps({"error": f"Missing required path parameter: {name}"})
            actual_path = actual_path.replace(f"{{{name}}}", str(value))

        # Build query params
        qparams = {}
        for p in query_params:
            name = p["name"]
            value = kwargs.get(name)
            if value is not None and value != "":
                qparams[name] = str(value)

        # Build request body
        body = None
        if has_array_body:
            body = []
        elif body_props and "_request_body" not in body_props:
            body = {}
            for name in body_props:
                value = kwargs.get(name)
                if value is not None:
                    body[name] = value
            if not body:
                body = None

        result = await api_request(
            endpoint=actual_path,
            token=auth["token"],
            method=method.upper(),
            params=qparams if qparams else None,
            body=body,
            cache_ttl=120,
        )
        return json.dumps(result)

    tool_func.__doc__ = docstring
    return tool_func


def register_openapi_tools(mcp) -> int:
    """Parse openapi.yaml and register every endpoint as an MCP tool.

    Returns the number of tools registered.
    """
    spec_path = Path(__file__).parent / "openapi.yaml"
    with open(spec_path) as f:
        spec = yaml.safe_load(f)

    paths = spec.get("paths", {})
    count = 0
    tool_names_seen = set()

    for path, path_item in paths.items():
        for method in ("get", "post", "put", "patch", "delete"):
            if method not in path_item:
                continue

            op = path_item[method]

            # Skip the authenticate endpoint — handled by OAuth
            if "authenticate" in path.lower():
                continue

            tool_name = _sanitize_name(path, method)

            # Deduplicate names (some paths differ only by param type)
            if tool_name in tool_names_seen:
                # Append a suffix from the first path param type
                params = op.get("parameters", [])
                for p in params:
                    if p.get("in") == "path":
                        schema = p.get("schema", {})
                        suffix = schema.get("format") or schema.get("type", "")
                        if suffix:
                            tool_name = f"{tool_name}_by_{suffix}"
                            break
                # If still duplicate, append numeric suffix
                if tool_name in tool_names_seen:
                    i = 2
                    while f"{tool_name}_{i}" in tool_names_seen:
                        i += 1
                    tool_name = f"{tool_name}_{i}"

            tool_names_seen.add(tool_name)

            func = _make_tool_func(path, method, op)
            func.__name__ = tool_name
            func.__qualname__ = tool_name

            mcp.tool(func)
            count += 1
            logger.debug("Registered tool: %s (%s %s)", tool_name, method.upper(), path)

    logger.info("Registered %d tools from OpenAPI spec (%d paths)", count, len(paths))
    return count
