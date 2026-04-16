FROM ghcr.io/its-a-feature/mythic_python_base:v3.4.0.41

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
	    curl \
	    ca-certificates \
	    git \
	    mingw-w64 \
	    gnupg \
	&& echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list.d/bookworm.list \
	&& apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends -t bookworm \
	    nim \
	&& rm -rf /var/lib/apt/lists/*

RUN pip install requests

ENV PATH="${PATH}:/root/.nimble/bin"
RUN nimble -y install winim
RUN nimble -y install puppy
RUN nimble -y install nimcrypto@0.7.1
RUN nimble -y install websocket

WORKDIR /Mythic/
CMD ["python3", "main.py"]
