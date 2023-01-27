

#Build the serve docker image.  
docker build -f Dockerfile -t $1 --build-arg GUI_IMAGE=$2 .







