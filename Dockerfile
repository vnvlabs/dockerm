
ARG FROM_IMAGE=ubuntu:20.04
FROM ${FROM_IMAGE}


RUN apt-get update && apt-get install -y virtualenv


COPY ./requirements.txt /py/requirements.txt
WORKDIR /py
RUN virtualenv --python=python3 virt && virt/bin/pip install -r requirements.txt

COPY . /dockerm
ARG GUI_IMAGE=ghcr.io/vnvlabs/gui:v1.0
ENV VNV_GUI_IMAGE=$GUI_IMAGE

WORKDIR /dockerm
ENTRYPOINT ["/py/virt/bin/python", "run.py"]
CMD ["--code", "super_secret_secret","--port","5000"]

