instructions = nprj0.pdf nprj1.pdf nprj2.pdf nprj3.pdf faq.pdf kickoff-slides.pdf nprjw.pdf
programs = parser hub switch arp router #vswitch
tests = test-hub test-switch test-arp test-router #test-vswitch

all: network-driver $(programs) $(tests)
docs: $(instructions)


CFLAGS = -O0 -g # -Wall


network-driver: network-driver.c glab.h
	gcc -g -O0 -Wall -o network-driver network-driver.c

# Try to build instructions, but do not fail hard if this fails:
# The CI doesn't have pdflatex...
$(instructions): %.pdf: %.tex bonus.tex code.tex grading.tex setup.tex testing.tex

	pdflatex $<  || true
	pdflatex $<  || true
	pdflatex $<  || true
# $(instructions): %.pdf: %.tex bonus.tex code.tex grading.tex setup.tex testing.tex
#    pdflatex -interaction=batchmode $<
#    pdflatex -interaction=batchmode $<


clean:
	rm -f network-driver sample-parser $(instructions) *.log *.aux *.out $(programs)

$(programs): %: %.c glab.h loop.c print.c crc.c
	gcc $(CFLAGS) $^ -o $@

test-hub: test-hub.c harness.c harness.h
	gcc $(CFLAGS) $^ -o $@
test-switch: test-switch.c harness.c harness.h
	gcc $(CFLAGS) $^ -o $@
#test-vswitch: test-vswitch.c harness.c harness.h
#	gcc $(CFLAGS) $^ -o $@
test-arp: test-arp.c harness.c harness.h
	gcc $(CFLAGS) $^ -o $@
test-router: test-router.c harness.c harness.h
	gcc $(CFLAGS) $^ -o $@

check: check-hub check-switch check-arp check-router

check-hub: test-hub
	./test-hub ./hub
check-switch: test-switch
	./test-switch ./switch
#check-vswitch: test-vswitch
#	./test-vswitch ./vswitch
check-arp: test-arp
	./test-arp ./arp
check-router: test-router
	./test-router ./router
arch.pdf: arch.svg
	rsvg-convert -f pdf -o arch.pdf arch.svg

# tests switch
#check-switch-ref: test-switch
#	./test-switch ./reference-switch
#check-switch-bug1: test-switch
#	./test-switch ./bug1-switch
#check-switch-bug2: test-switch
#	./test-switch ./bug2-switch
#check-switch-bug3: test-switch
#	./test-switch ./bug3-switch

# tests arp
#check-arp-ref: test-arp
#	./test-arp ./reference-arp
#check-arp-bug1: test-arp
#	./test-arp ./bug1-arp
#check-arp-bug2: test-arp
#	./test-arp ./bug2-arp

# test switch
check-router-ref: test-router
	./test-router ./reference-router
check-router-bug1: test-router
	./test-router ./bug1-router
check-router-bug2: test-router
	./test-router ./bug2-router
check-router-bug3: test-router
	./test-router ./bug3-router
check-router-bug4: test-router
	./test-router ./bug4-router


.PHONY: clean check check-hub check-switch check-arp check-router check-router-ref check-router-bug1 check-router-bug2  check-router-bug3  check-router-bug4  
#check-switch-ref check-switch-bug1 check-switch-bug2 check-switch-bug3 
#check-arp-ref check-arp-bug1 check-arp-bug2
