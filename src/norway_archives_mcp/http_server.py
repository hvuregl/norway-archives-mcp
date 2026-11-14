import asyncio
import os

from .server import mcp


def main():
    host = os.environ.get("MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "10000"))

    asyncio.run(
        mcp.run_streamable_http_async(
            host=host,
            port=port,
            streamable_http_path="/mcp",
            stateless_http=True,
        )
    )


if __name__ == "__main__":
    main()
