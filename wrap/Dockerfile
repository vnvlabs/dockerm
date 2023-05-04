

ARG FROM_IMAGE=ubuntu:20.04
ARG GUI_IMAGE=ghcr.io/vnvlabs/gui:v1.0

FROM ${GUI_IMAGE}
RUN rm -rf /vnvgui/gui/virt

FROM ${FROM_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive 
ENV TZ=America/New_York
ENV THEIA_DEFAULT_PLUGINS=local-dir:/vnvgui/theia/plugins
ENV PARAVIEW_DIR=/vnvgui/paraview 
ENV PVPYTHON=${PARAVIEW_DIR}/bin/pvpython 
ENV PATH=/vnvgui/node/bin/:$PATH 
ENV DOWNLOAD_PARAVIEW=1

COPY --from=0 /vnvgui/node /vnvgui/node
COPY --from=0 /vnvgui/theia /vnvgui/theia
COPY --from=0 /vnvgui/gui /vnvgui/gui
COPY --from=0 /vnvgui/paraview /vnvgui/paraview 

RUN apt-get -y update && apt-get install -y python3-dev python3-pip libsecret-1-dev wget curl git libglapi-mesa && pip3 install virtualenv
RUN cd /vnvgui/gui && virtualenv virt && virt/bin/pip install -r ./requirements.txt 
LABEL VNV_GUI_EQUIPT=1

WORKDIR /vnvgui/gui
ENTRYPOINT ["./launch.sh"]


