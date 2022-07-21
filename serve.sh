
#Command to SERVE THE DOCKER IMAGE
docker run --rm -it --network="host" -v /var/run/docker.sock:/var/run/docker.sock dockerm --code Hello --port 5010
