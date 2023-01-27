#!/bin/bash 

# Launch with mapping Theia and Paraview. This is used by the serve app



#Pull down the GUI image in the background so we have it when we need it. 
docker pull ${GUI_IMAGE} & 

cd /dockerm
virt/bin/python run.py ${@:1}