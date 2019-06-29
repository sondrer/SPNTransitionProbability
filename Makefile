#!/usr/bin/make

CXX=clang++
CXX_FLAGS=-Wall --std=c++14 -pedantic -O2

all: transition_matrix

transition_matrix:
	$(CXX) $(CXX_FLAGS) $@.cc -o $@ -lntl