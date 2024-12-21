from main.app import main_app

App = main_app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("run:App", reload=True)
