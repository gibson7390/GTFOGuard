from gtfoguard.engine import Engine
from gtfoguard.ui.display import Display


def main() -> None:
    results = Engine().run()
    Display().render(results)


if __name__ == "__main__":
    main()
