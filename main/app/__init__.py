from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

main_app = FastAPI(
    title="ERP System APIs",
    docs_url="/dx",
    redoc_url="/rx",
)


def gather_router(routers):
    [main_app.include_router(router) for router in routers]


if main_app:
    from ..src.apis import user
    from ..src.apis import auth

    gather_router(
        [
            user.router,
            auth.router,
        ]
    )
