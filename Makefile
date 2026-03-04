NVCC=nvcc
CXX=c++

gitminer: gitminer.cu
	$(NVCC) gitminer.cu -O3 -m64 -std=c++11 -D_FORCE_INLINES -D_MWAITXINTRIN_H_INCLUDED -o gitminer

gitminer_cpu: gitminer.cpp
	$(CXX) gitminer.cpp -O3 -std=c++17 -pthread -o gitminer_cpu

clean:
	rm -f ./gitminer ./gitminer_cpu
