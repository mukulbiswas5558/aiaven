from fastapi import FastAPI

main_app = FastAPI(
    title="ERP System APIs",
    docs_url="/dx",
    redoc_url="/rx",
)

# Add middleware globally to the FastAPI application
# main_app.add_middleware(RoleMiddleware)  # Apply your custom RoleMiddleware globally

# Include routers in the main app
def gather_router(routers):
    for router in routers:
        main_app.include_router(router)

if main_app:
    from ..src.apis import user
    from ..src.apis import auth
    from ..src.apis import department

    gather_router(
        [
            user.router,
            auth.router,
            department.router,
        ]
    )