FROM itsafeaturemythic/mythic_python_base:latest

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
RUN pip install --no-cache-dir --upgrade mythic-container==0.6.6

ENV PATH="${PATH}:/root/.nimble/bin"
RUN nimble -y install winim
RUN nimble -y install puppy
RUN nimble -y install nimcrypto@0.7.1
RUN nimble -y install websocket

WORKDIR /Mythic/
CMD ["python3", "main.py"]
