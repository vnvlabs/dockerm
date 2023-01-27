# vnv-serve

Simple Docker Server for managing docker images on a resource with docker preinstalled. 


Since we need to launch docker containers inside this image, we need to launch with the following command 


docker run --rm -it --network="host" -v /var/run/docker.sock:/var/run/docker.sock dockerm .....
