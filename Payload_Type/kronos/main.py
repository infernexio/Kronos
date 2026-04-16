import mythic_container
import asyncio
import os
from importlib.metadata import version, PackageNotFoundError
from kronos.mythic import *

def _safe_env(name: str, default: str = "<unset>") -> str:
	return os.getenv(name, default)

def _print_startup_diagnostics() -> None:
	try:
		mc_version = version("mythic-container")
	except PackageNotFoundError:
		mc_version = "<not-installed>"

	print(f"[kronos] mythic-container={mc_version}", flush=True)
	print(
		"[kronos] rabbitmq="
		f"host={_safe_env('RABBITMQ_HOST')} "
		f"port={_safe_env('RABBITMQ_PORT')} "
		f"vhost={_safe_env('RABBITMQ_VHOST')}",
		flush=True,
	)
	print(
		"[kronos] container="
		f"name={_safe_env('MYTHIC_CONTAINER_NAME')} "
		f"type={_safe_env('MYTHIC_CONTAINER_TYPE')}",
		flush=True,
	)

_print_startup_diagnostics()
mythic_container.mythic_service.start_and_run_forever()
