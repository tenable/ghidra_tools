#! /usr/bin/env python3

import argparse
import logging
import os

import ghidra_bridge

# Load Ghidra Bridge and make Ghidra namespace available
TIMEOUT = 1000
gb = ghidra_bridge.GhidraBridge(namespace=globals(), response_timeout=TIMEOUT)

def get_program_info():
    """Gather information for currentProgram in Ghidra."""
    logging.debug("Gathering program information...")
    program_info = {}
    program_info["program_name"] = currentProgram.getName()
    program_info["creation_date"] = gb.remote_eval("currentProgram.getCreationDate()")
    program_info["language_id"] = gb.remote_eval("currentProgram.getLanguageID()")
    program_info["compiler_spec_id"] = gb.remote_eval("currentProgram.getCompilerSpec().getCompilerSpecID()")
    
    logging.info(f"Program Name: {program_info['program_name']}")
    logging.info(f"Creation Date: {program_info['creation_date']}")
    logging.info(f"Language ID: {program_info['language_id']}")
    logging.info(f"Compiler Spec ID: {program_info['compiler_spec_id']}")

    return program_info

def create_output_dir(path):
    """
    Create directory to store decompiled functions to. Will error and exit if
    the directory already exists and contains files.

    path: File path to desired directory
    """
    logging.info(f"Using '{path}' as output directory...")

    if os.path.isdir(path):
        if os.listdir(path):
            logging.error(f"{path} already contains files!")
            exit()
        return path
    
    os.mkdir(path)

def extract_decomps(output_dir):
    logging.info("Extracting decompiled functions...")
    decomp = ghidra.app.decompiler.DecompInterface()
    decomp.openProgram(currentProgram)
    functions = list(currentProgram.functionManager.getFunctions(True))
    failed_to_extract = []
    count = 0

    for function in functions:
        logging.debug(f"Decompiling {function.name}")
        decomp_res = decomp.decompileFunction(function, TIMEOUT, monitor)

        if decomp_res.isTimedOut():
            logging.warning("Timed out while attempting to decompile '{function.name}'")
        elif not decomp_res.decompileCompleted():
            logging.error(f"Failed to decompile {function.name}")
            logging.error("    Error: " + decomp_res.getErrorMessage())
            failed_to_extract.append(function.name)
            continue
    
        decomp_src = decomp_res.getDecompiledFunction().getC()

        try:
            filename = f"{function.name}@{function.getEntryPoint()}.c"
            path = os.path.join(output_dir, filename)
            with open(path, "w") as f:
                logging.debug(f"Saving to '{path}'")
                f.write(decomp_src)
                count += 1
        except Exception as e:
            logging.error(e)
            failed_to_extract.append(function.name)
            continue
    
    logging.info(f"Extracted {str(count)} out of {str(len(functions))} functions")
    if failed_to_extract:
        logging.warning("Failed to extract the following functions:\n\n  - " + "\n  - ".join(failed_to_extract))

def main(output_dir=None):
    """Main function."""
    program_info = get_program_info()

    # Default output directory to current directory + program name + _extraction
    if output_dir is None:
        output_dir = program_info["program_name"] + "_extraction"
    
    create_output_dir(output_dir)
    extract_decomps(output_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract ghidra decompilation output for currently loaded program.")
    parser.add_argument("-o", "--output", help="Set output directory (default is current directory + program name)")
    parser.add_argument("-v", "--verbose", action="count", help="Display verbose logging output")
    parser.add_argument("-t", "--timeout", type=int, help="Custom timeout for individual function decompilation (default = 1000)")
    args = parser.parse_args()

    if args.output:
        output_dir = args.output
    else:
        output_dir = None
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if args.timeout:
        TIMEOUT = args.timeout
 
    main(output_dir=output_dir)
