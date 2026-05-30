import logging
from rich.logging import RichHandler
from rich.console import Console
from rich.theme import Theme

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red",
    "critical": "bold red",
    "success": "bold green",
})

console = Console(theme=custom_theme)

def setup_logging():
    logging.basicConfig(
        level="INFO",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console)]
    )
    return logging.getLogger("SNI-Spoofing")

logger = setup_logging()

def log_success(message):
    console.print(f"[success]SUCCESS[/success]: {message}")

def log_info(message):
    logger.info(message)

def log_warn(message):
    logger.warning(message)

def log_error(message, exc_info=False):
    logger.error(message, exc_info=exc_info)
