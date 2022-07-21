
ARG FROM_IMAGE=ubuntu
FROM ${FROM_IMAGE}:latest

RUN apt-get update && apt-get install -y virtualenv

COPY . /docker_wrapper
WORKDIR /docker_wrapper
RUN virtualenv --python=python3 virt && virt/bin/pip install -r requirements.txt
ENTRYPOINT ["./virt/bin/python", "run.py"]
CMD ["--code", "super_secret_secret","--port","5000"]
