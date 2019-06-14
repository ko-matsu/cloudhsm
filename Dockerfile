FROM golang:alpine


ARG SWIG_VER=3.0.12

RUN apk add --update --no-cache g++ pcre pcre-dev make git autoconf automake libtool python-dev cmake \
  && wget https://sourceforge.net/projects/swig/files/swig/swig-$SWIG_VER/swig-$SWIG_VER.tar.gz \
  && tar -xzvf swig-$SWIG_VER.tar.gz \
  && cd swig-$SWIG_VER/ \
  && ./configure --prefix=/home/Jerry/library/swigtool \
  && make \
  && make install \
  && ./swig -version

COPY ./ /cloudhsm/

WORKDIR /cloudhsm

RUN mkdir build && cd build && cmake .. && make && cd ..\
  && /go/swig-$SWIG_VER/swig -go -c++ -cgo -intgosize 32 -o cloudhsm.cxx swig.i \
  && rm -rf /go/swig-$SWIG_VER \
  && apk del g++ pcre pcre-dev make git autoconf automake libtool python-dev cmake

