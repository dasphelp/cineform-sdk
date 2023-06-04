FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake uuid-dev clang

COPY . /repo
WORKDIR /repo/build
RUN cmake ..
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_GetRand.cpp -fsanitize=fuzzer,address /repo/Example/utils.cpp -I /repo/Common/ -I /repo/Example/ -o /fuzz 

FROM ubuntu:20.04 as package
COPY --from=builder /repo/build/WaveletDemo /
COPY --from=builder /repo/build/TestCFHD /
COPY --from=builder /fuzz /fuzz_GetRand
