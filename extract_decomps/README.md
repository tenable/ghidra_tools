# Ghidra Decomp Extractor





## Setup

### Ghidra Setup

* Install Ghidra Bridge for Python3 via https://github.com/justfoxing/ghidra_bridge

* Start ghidra bridge background server

  ![image-20220726143115698](/Users/dinobytes/dev/ghidra_tools/extract_decomps/assets/image-20220726143115698.png)

* Don't forget to shut down the Ghidra Bridge when you're getting ready to close the analysis window!

  

### Python Setup

* Create and initialize your desired base Python environment.

* Install dependencies

  ```
  pip install -r requirements.txt
  ```



## Usage

```k
$ python extract.py -h
usage: extract.py [-h] [-o OUTPUT] [-v] [-t TIMEOUT]

Extract ghidra decompilation output for currently loaded program.

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Set output directory (default is current directory + program name)
  -v, --verbose         Display verbose logging output
  -t TIMEOUT, --timeout TIMEOUT
                        Custom timeout for individual function decompilation (default = 1000)
```