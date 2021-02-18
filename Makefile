NVCC=nvcc

gitminer: gitminer.cu
	$(NVCC) gitminer.cu -O3 -m64 -std=c++11 -D_FORCE_INLINES -D_MWAITXINTRIN_H_INCLUDED -o gitminer

clean:
	rm -f ./gitminer
