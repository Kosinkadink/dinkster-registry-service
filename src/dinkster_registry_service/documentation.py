import json
from pathlib import Path

from fastapi import APIRouter, Request, Response
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from starlette.responses import HTMLResponse

documentation_router = APIRouter()


@documentation_router.get("/favicon.ico", include_in_schema=False)
@documentation_router.get("/favicon.svg", include_in_schema=False)
@documentation_router.get("/favicon-32.png", include_in_schema=False)
@documentation_router.get("/apple-touch-icon.png", include_in_schema=False)
@documentation_router.get("/icon-192.png", include_in_schema=False)
@documentation_router.get("/icon-512.png", include_in_schema=False)
async def favicon(request: Request) -> Response:
    filename = request.url.path.rsplit("/", 1)[-1]
    media_type = {
        "favicon.ico": "image/vnd.microsoft.icon",
        "favicon.svg": "image/svg+xml",
        "favicon-32.png": "image/png",
        "apple-touch-icon.png": "image/png",
        "icon-192.png": "image/png",
        "icon-512.png": "image/png",
    }[filename]
    return Response(
        Path(__file__).with_name(filename).read_bytes(),
        media_type=media_type,
        headers={"X-Content-Type-Options": "nosniff"},
    )


@documentation_router.get("/manifest.webmanifest", include_in_schema=False)
async def web_manifest(request: Request) -> Response:
    root = request.scope.get("root_path", "").rstrip("/")
    return Response(
        json.dumps(
            {
                "name": "Dinkster Registry",
                "short_name": "Dinkster",
                "start_url": f"{root}/docs",
                "icons": [
                    {
                        "src": f"{root}/icon-{size}.png",
                        "sizes": f"{size}x{size}",
                        "type": "image/png",
                    }
                    for size in (192, 512)
                ],
            }
        ),
        media_type="application/manifest+json",
        headers={"X-Content-Type-Options": "nosniff"},
    )


@documentation_router.get("/docs", include_in_schema=False)
@documentation_router.get("/redoc", include_in_schema=False)
@documentation_router.get("/docs/oauth2-redirect", include_in_schema=False)
async def api_documentation(request: Request) -> HTMLResponse:
    root = request.scope.get("root_path", "").rstrip("/")
    if request.url.path.endswith("/oauth2-redirect"):
        page = get_swagger_ui_oauth2_redirect_html()
    elif request.url.path.endswith("/redoc"):
        page = get_redoc_html(
            openapi_url=f"{root}{request.app.openapi_url}",
            title=f"{request.app.title} - ReDoc",
            redoc_favicon_url=f"{root}/favicon.ico",
        )
    else:
        page = get_swagger_ui_html(
            openapi_url=f"{root}{request.app.openapi_url}",
            title=f"{request.app.title} - Swagger UI",
            swagger_favicon_url=f"{root}/favicon.ico",
            oauth2_redirect_url=f"{root}/docs/oauth2-redirect",
        )
    return HTMLResponse(bytes(page.body).decode().replace("</head>", f"{icon_links(root)}</head>"))


def icon_links(root: str) -> str:
    return (
        f'<link rel="icon" type="image/svg+xml" href="{root}/favicon.svg">'
        f'<link rel="icon" type="image/png" sizes="32x32" href="{root}/favicon-32.png">'
        f'<link rel="apple-touch-icon" sizes="180x180" href="{root}/apple-touch-icon.png">'
        f'<link rel="manifest" href="{root}/manifest.webmanifest">'
    )
