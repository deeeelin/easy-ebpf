# generate vmlinux header
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 

# build bpf kernel object file
minimal.bpf.o: minimal.bpf.c
	clang -g -O2 -target bpf -c $^ -o $@

# generate skeleton
minimal.skel.h: minimal.bpf.o
	bpftool gen skeleton $^ > $@
    
# build app
minimal: minimal.c
	clang -g $^ -lbpf -lelf -lz -o $@

# build bpf kernel object file
tcprtt.bpf.o: tcprtt.bff.c
	clang -g -O2 -target bpf -c $^ -o $@

# generate skeleton
tcprtt.skel.h: tcprtt.bpf.o
	bpftool gen skeleton $^ > $@
    
# build app
tcprtt: tcprtt.c
	clang -g $^ -lbpf -lelf -lz -o $@

# build bpf kernel object file
bootstrap.bpf.o: bootstrap.bpf.c
	clang -g -O2 -target bpf -c $^ -o $@

# generate skeleton
bootstrap.skel.h: bootstrap.bpf.o
	bpftool gen skeleton $^ > $@
    
# build app
bootstrap: bootstrap.c
	clang -g $^ -lbpf -lelf -lz -o $@

# build bpf kernel object file
tcprtt_tp.bpf.o: tcprtt_tp.bpf.c
	clang -g -O2 -target bpf -c $^ -o $@

# generate skeleton
tcprtt_tp.skel.h: tcprtt_tp.bpf.o
	bpftool gen skeleton $^ > $@
    
# build app
tcprtt_tp: tcprtt_tp.c
	clang -g $^ -lbpf -lelf -lz -o $@
