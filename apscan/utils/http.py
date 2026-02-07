import httpx
import time
from apscan.core.context import ScanRequest, ScanResponse

class HTTPClient:
    def __init__(self):
        self.client = httpx.AsyncClient(verify=False, timeout=10.0)

    async def send(self, request: ScanRequest) -> ScanResponse:
        start_time = time.time()
        try:
            response = await self.client.request(
                method=request.method,
                url=request.url,
                headers=request.headers,
                params=request.params,
                json=request.json_body,
                data=request.data,
                files=request.files,
                cookies=request.cookies
            )
            elapsed = time.time() - start_time
            return ScanResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
                elapsed_time=elapsed
            )
        except Exception as e:
            # Handle connection errors, etc.
            return ScanResponse(
                status_code=0,
                headers={},
                body=str(e),
                elapsed_time=time.time() - start_time
            )

    async def close(self):
        await self.client.aclose()
