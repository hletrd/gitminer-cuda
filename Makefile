NVCC=nvcc
CXX=c++
GLSLC=glslc

gitminer: gitminer.cu
	$(NVCC) gitminer.cu -O3 -m64 -std=c++17 -arch=sm_89 -D_FORCE_INLINES -D_MWAITXINTRIN_H_INCLUDED -o gitminer

gitminer_cpu: gitminer.cpp
	$(CXX) gitminer.cpp -O3 -std=c++17 -pthread -o gitminer_cpu

gitminer_metal: gitminer_metal.mm
	$(CXX) gitminer_metal.mm -O3 -std=c++17 -framework Metal -framework Foundation -o gitminer_metal

gitminer_opencl: gitminer_opencl.cpp
	$(CXX) gitminer_opencl.cpp -O3 -std=c++17 -framework OpenCL -o gitminer_opencl

sha1_kernel.spv: sha1_kernel.comp
	$(GLSLC) sha1_kernel.comp -o sha1_kernel.spv

gitminer_vulkan: gitminer_vulkan.cpp sha1_kernel.spv
	$(CXX) gitminer_vulkan.cpp -O3 -std=c++17 -lvulkan -o gitminer_vulkan

clean:
	rm -f ./gitminer ./gitminer_cpu ./gitminer_metal ./gitminer_opencl ./gitminer_vulkan ./sha1_kernel.spv
