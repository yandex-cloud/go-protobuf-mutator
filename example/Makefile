CXX = clang++
LDFLAGS = -L . -L /usr/local/lib -lresolv
DURATION = 60

.PHONY: all clean go-fuzz.a go-fuzz coverage build-docker

all: coverage

build-docker:
	docker build -t fuzzing:v1.0.0 .

go-fuzz.a:
	CGO_ENABLED=1 go build -o $@ \
		-cover \
		-covermode=atomic \
		-buildmode c-archive \
		-buildvcs=false \
		-tags libfuzzer \
		-gcflags all=-d=libfuzzer \
		-gcflags syscall=-d=libfuzzer=0 \
	./cmd/...

go-fuzz: fuzz
	GOCOVERDIR=. GOEXPERIMENT=coverageredesign ./fuzz ./corpus -max_total_time=$(DURATION) -rss_limit_mb=0 -timeout=100000

coverage: go-fuzz
	go tool covdata textfmt -i . -o result.txt
	go tool cover -html=./result.txt -o result.html
	go tool cover -func=./result.txt -o result_func.txt

cov-only:
	go tool covdata textfmt -i . -o result.txt
	go tool cover -html=./result.txt -o result.html
	go tool cover -func=./result.txt -o result_func.txt

fuzz: go-fuzz.a $(OBJ)
	$(CXX) -o fuzz $(OBJ) go-fuzz.a $(LDFLAGS) -fsanitize=fuzzer

clean:
	$(RM) $(OBJ)
