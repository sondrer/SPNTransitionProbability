# SPNTransitionProbability
Simple C/C++ code for experimenting with weight transition probabilities in
AES-like ciphers. The Z-table is essentially the weight distribution of the MDS
code used in AES. 


## Dependencies
- A C++ compiler. Per default, `g++` is declared in the `Makefile`, but this 
  can be changed to `clang` or any other at your own choice.

- Victor Shoup's NTL library:
  https://www.shoup.net/ntl/
  
- `make` for building.


## Building
- If `make`, a C++ compiler `g++`, and NTL are installed, you can simply type 
  `make` in the command-line and the default target `transition_matrix` 
  will be built. 
  
- Alternatively, typing `make transition_matrix` also builds the target 
  `transition_matrix` for you.
 
 
## Usage
- Executing `transition_matrix` computes the difference of the transition
  probabilities for the AES ($p_{AES}$) and that of a random permutation 
  ($p_{rand}$) and outputs $p_{AES} - p_{rand}$.


##### TODO: 
Apply linear optimization to the state transition-probability matrix to
find the minimal distinguishing complexity. 
