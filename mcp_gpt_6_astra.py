import os
import json
import http.client
from typing import Optional, List, Dict, Any
from mcp.server.mcpserver import MCPServer

# Initialize MCP Server for GPT-6-Astra
mcp = MCPServer(
    name="gpt-6-astra",
    instructions="MCP Server providing multimodal vision and autonomous web search capabilities via GPT-6-Astra on api.kie.ai"
)

DEFAULT_HOST = "api.kie.ai"
DEFAULT_ENDPOINT = "/codex/v1/responses"
DEFAULT_MODEL = "gpt-6-astra"


def _call_kie_api(
    prompt: str,
    image_url: Optional[str] = None,
    web_search: bool = True,
    reasoning_effort: str = "high",
    token: Optional[str] = None,
) -> str:
    active_token = (
        token
        or os.environ.get("KIE_AI_API_KEY")
        or os.environ.get("KIE_AI_TOKEN")
        or "<token>"
    )

    content_items: List[Dict[str, str]] = [
        {"type": "input_text", "text": prompt}
    ]

    if image_url:
        content_items.append({"type": "input_image", "image_url": image_url})

    tools = [{"type": "web_search"}] if web_search else []

    payload = json.dumps({
        "model": DEFAULT_MODEL,
        "input": [
            {
                "role": "user",
                "content": content_items
            }
        ],
        "tools": tools,
        "reasoning": {
            "effort": reasoning_effort
        }
    })

    headers = {
        "Authorization": f"Bearer {active_token}",
        "Content-Type": "application/json"
    }

    try:
        conn = http.client.HTTPSConnection(DEFAULT_HOST, timeout=60)
        conn.request("POST", DEFAULT_ENDPOINT, payload, headers)
        res = conn.getresponse()
        raw_bytes = res.read()
        status_code = res.status
        conn.close()

        decoded = raw_bytes.decode("utf-8", errors="replace")

        if status_code != 200:
            return f"Error from api.kie.ai (HTTP {status_code}): {decoded}"

        try:
            parsed = json.loads(decoded)
            # Try to extract the cleanest response text
            if isinstance(parsed, dict):
                choices = parsed.get("choices")
                if isinstance(choices, list) and len(choices) > 0:
                    msg = choices[0].get("message", {})
                    content = msg.get("content", "")
                    reasoning = msg.get("reasoning")
                    if reasoning:
                        return f"{content}\n\n[Reasoning]:\n{reasoning}"
                    return content or decoded
                elif "output" in parsed:
                    out = parsed["output"]
                    if isinstance(out, list) and len(out) > 0:
                        first = out[0]
                        return first.get("content") or first.get("text", str(first))
                    return str(out)
                elif "response" in parsed:
                    return str(parsed["response"])
                elif "text" in parsed:
                    return str(parsed["text"])
            return decoded
        except Exception:
            return decoded

    except Exception as e:
        return f"Failed to connect to api.kie.ai: {str(e)}"


@mcp.tool(
    name="ask_gpt_6_astra",
    description="Query GPT-6-Astra on api.kie.ai with advanced reasoning, optional image input, and live web search."
)
def ask_gpt_6_astra(
    prompt: str,
    image_url: Optional[str] = None,
    web_search: bool = True,
    reasoning_effort: str = "high"
) -> str:
    """
    Sends a query to GPT-6-Astra with high reasoning effort and optional web search.
    """
    return _call_kie_api(
        prompt=prompt,
        image_url=image_url,
        web_search=web_search,
        reasoning_effort=reasoning_effort
    )


@mcp.tool(
    name="analyze_image_with_gpt_6_astra",
    description="Multimodal visual analysis of an image URL using GPT-6-Astra and web search."
)
def analyze_image_with_gpt_6_astra(
    image_url: str,
    prompt: str = "What is in this image?",
    web_search: bool = True,
    reasoning_effort: str = "high"
) -> str:
    """
    Analyzes an image using GPT-6-Astra.
    """
    return _call_kie_api(
        prompt=prompt,
        image_url=image_url,
        web_search=web_search,
        reasoning_effort=reasoning_effort
    )


@mcp.tool(
    name="web_search_with_gpt_6_astra",
    description="Executes a web search query with GPT-6-Astra deep reasoning synthesis."
)
def web_search_with_gpt_6_astra(
    query: str,
    reasoning_effort: str = "high"
) -> str:
    """
    Executes autonomous web search and deep reasoning synthesis with GPT-6-Astra.
    """
    return _call_kie_api(
        prompt=f"Search the web and provide a detailed, verified answer for: {query}",
        image_url=None,
        web_search=True,
        reasoning_effort=reasoning_effort
    )


if __name__ == "__main__":
    mcp.run("stdio")
