# Query OpenAI for a comment
#@author Lucca Fraser
#@category AI
#@keybinding
#@menupath
#@toolbar

import subprocess as sp
import textwrap
import logging
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL
import json
import os
import re
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function, FunctionManager
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import DuplicateNameException
from ghidra.program.model.symbol import SourceType


##########################################################################################
# Script Configuration
##########################################################################################
#MODEL = "text-curie-001" # Choose which large language model we query
MODEL = "text-davinci-003" # Choose which large language model we query
TEMPERATURE = 0.19    # Set higher for more adventurous comments, lower for more conservative
TIMEOUT = 600         # How many seconds should we wait for a response from OpenAI?
MAXTOKENS = 512       # The maximum number of tokens to request from OpenAI
C3POSAY = True        # True if you want the cute C-3PO ASCII art, False otherwise
#LANGUAGE = "the form of a sonnet"  # This can also be used as a style parameter for the comment
LANGUAGE = "English"  # This can also be used as a style parameter for the comment
EXTRA = ""            # Extra text appended to the prompt.
#EXTRA = "but write everything in the form of a sonnet" # for example
LOGLEVEL = INFO       # Adjust for more or less line noise in the console.
COMMENTWIDTH = 80     # How wide the comment, inside the little speech balloon, should be.
C3POASCII = r"""
          /~\
         |oo )
         _\=/_
        /     \
       //|/.\|\\
      ||  \_/  ||
      || |\ /| ||
       # \_ _/  #
         | | |
         | | |
         []|[]
         | | |
        /_]_[_\
"""
##########################################################################################


SCRIPTDIR = os.path.dirname(os.path.realpath(__file__))
ICONPATH = os.path.join(SCRIPTDIR, "c3po.png")
# Now how do I set the icon? I'm not sure.
SOURCE = "OpenAI GPT-3"
TAG = SOURCE + " generated comment, take with a grain of salt:"
FOOTER = "Model: {model}, Temperature: {temperature}".format(model=MODEL, temperature=TEMPERATURE)

logging.getLogger().setLevel(LOGLEVEL)

def flatten_list(l):
    return [item for sublist in l for item in sublist]

def wordwrap(s, width=COMMENTWIDTH, pad=True):
    """Wrap a string to a given number of characters, but don't break words."""
    # first replace single line breaks with double line breaks
    lines = [textwrap.TextWrapper(width=width, 
                                 break_long_words=False, 
                                 break_on_hyphens=True, 
                                 replace_whitespace=False).wrap("    " + L)
            for L in s.splitlines()]
    # now flatten the lines list
    lines = flatten_list(lines)
    if pad:
        lines = [line.ljust(width) for line in lines]
    return "\n".join(lines)

def boxedtext(text, width=COMMENTWIDTH, tag=TAG):
    wrapped = wordwrap(text, width, pad=True)
    wrapped = "\n".join([tag.ljust(width), " ".ljust(width), wrapped, " ".ljust(width), FOOTER.ljust(width)])
    side_bordered = "|" + wrapped.replace("\n", "|\n|") + "|"
    top_border = "/" + "-" * (len(side_bordered.split("\n")[0]) - 2) + "\\"
    bottom_border = top_border[::-1]
    return top_border + "\n" + side_bordered + "\n" + bottom_border
    
def c3posay(text, width=COMMENTWIDTH, character=C3POASCII, tag=TAG):
    box = boxedtext(text, width, tag=tag)
    headwidth = len(character.split("\n")[1]) + 2
    return box + "\n" + " "*headwidth + "/" + character

def escape_unescaped_single_quotes(s):
    return re.sub(r"(?<!\\)'", r"\\'", s)

# Example
# $ curl https://api.openai.com/v1/completions -H "Content-Type: application/json" -H "Authorization: Bearer $OPENAI_API_KEY" -d '{"model": "text-davinci-003", "prompt": "Say this is a test", "temperature": 0, "max_tokens": 7}'
def openai_request_cmd(prompt, temperature=0.19, max_tokens=MAXTOKENS, model=MODEL):
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if openai_api_key is None:
        logging.error("OpenAI API key not found in environment variables!")
        return None
    data = {
      "model": MODEL,
      "prompt": escape_unescaped_single_quotes(prompt), #prompt.replace("'", "\\'"),
      "max_tokens": max_tokens,
      "temperature": temperature
    }
    json_data = json.dumps(data)
    url = "https://api.openai.com/v1/completions"
    cmd = ["curl",
           url,
           "-H", "Content-Type: application/json",
           "-H", "Authorization: Bearer {openai_api_key}".format(openai_api_key=openai_api_key),
           "-d", json_data]
    return cmd 


def openai_request(prompt, temperature=0.19, max_tokens=MAXTOKENS, model=MODEL):
    cmd = openai_request_cmd(prompt, temperature=temperature, max_tokens=max_tokens)
    cmdstr = " ".join(cmd)
    logging.info("Running command: {cmdstr}".format(cmdstr=cmdstr))
    res = sp.Popen(cmd, shell=False, stdout=sp.PIPE, stderr=sp.PIPE)
    exitcode = res.wait()
    out = res.stdout.read()
    err = res.stderr.read()
    if exitcode != 0:
        logging.error("OpenAI request failed with exit code {exitcode}".format(exitcode=exitcode))
        logging.error("Error: {err}".format(err=err))
        return None
    logging.info("OpenAI request succeeded with exit code {exitcode}".format(exitcode=exitcode))
    logging.info("Response: {out}".format(out=out))
    try:
        return json.loads(out)
    except Exception as e:
        logging.error("Failed to parse JSON response: {e}".format(e=e))
        return None


def get_current_function():
    listing = currentProgram.getListing()
    function = listing.getFunctionContaining(currentAddress)
    return function



def decompile_current_function(function=None):
    if function is None:
        function = get_current_function()
    logging.info("Current address is at {currentAddress}".format(currentAddress=currentAddress.__str__()))
    logging.info("Decompiling function: {function_name} at {function_entrypoint}".format(function_name=function.getName(), function_entrypoint=function.getEntryPoint().__str__()))
    decomp = ghidra.app.decompiler.DecompInterface()
    decomp.openProgram(currentProgram)
    decomp_res = decomp.decompileFunction(function, TIMEOUT, monitor)
    if decomp_res.isTimedOut():
        logging.warning("Timed out while attempting to decompile '{function_name}'".format(function_name=function.getName()))
    elif not decomp_res.decompileCompleted():
        logging.error("Failed to decompile {function_name}".format(function_name=function.getName()))
        logging.error("    Error: " + decomp_res.getErrorMessage())
        return None
    decomp_src = decomp_res.getDecompiledFunction().getC()
    return decomp_src

def generate_comment(c_code, temperature=0.19, program_info=None, prompt=None, model=MODEL, max_tokens=MAXTOKENS):
    intro = "Below is some C code that Ghidra decompiled from a binary that I'm trying to reverse engineer."
    #program_info = get_program_info()
    #if program_info:
    #    intro = intro.replace("a binary", f'a {program_info["language_id"]} binary')
    if prompt is None:
        prompt = """{intro}

```
{c_code}
```

Please provide a detailed explanation of what this code does, in {style}, that might be useful to a reverse engineer. Explain your reasoning as much as possible. Finally, suggest a suitable name for this function and for each variable bearing a default name, offer a more informative name, if the purpose of that variable is unambiguous. {extra}

""".format(intro=intro, c_code=c_code, style=LANGUAGE, extra=EXTRA)
    print("Prompt:\n\n{prompt}".format(prompt=prompt))
    response = openai_request(prompt=prompt, temperature=temperature, max_tokens=max_tokens, model=MODEL)
    try:
        res = response['choices'][0]['text'].strip()
        print(res)
        return res
    except Exception as e:
        logging.error("Failed to get response: {e}".format(e=e))
        return None


def add_explanatory_comment_to_current_function(temperature=0.19, model=MODEL, max_tokens=MAXTOKENS):
    function = get_current_function()
    if function is None:
        logging.error("Failed to get current function")
        return None
    old_comment = function.getComment()
    if old_comment is not None:
        if SOURCE in old_comment:
            function.setComment(None)
        else:
            logging.info("Function already has a comment")
            return None
    c_code = decompile_current_function(function)
    if c_code is None:
        logging.error("Failed to decompile current function")
        return
    approximate_tokens = len(c_code) // 2
    logging.info("Length of decompiled C code: {c_code_len} characters, guessing {approximate_tokens} tokens".format(c_code_len=len(c_code), approximate_tokens=approximate_tokens))
    if approximate_tokens < max_tokens and approximate_tokens + max_tokens > 3000:
        max_tokens = 4096 - approximate_tokens
    comment = generate_comment(c_code, temperature=temperature, model=model, max_tokens=max_tokens)
    if comment is None:
        logging.error("Failed to generate comment")
        return
    if C3POSAY:
        comment = c3posay(comment)
    else:
        comment = TAG + "\n" + comment
    listing = currentProgram.getListing()
    function = listing.getFunctionContaining(currentAddress)
    try:
        function.setComment(comment)
    except DuplicateNameException as e:
        logging.error("Failed to set comment: {e}".format(e=e))
        return
    logging.info("Added comment to function: {function_name}".format(function_name=function.getName()))
    return comment


add_explanatory_comment_to_current_function(temperature=0.19, model=MODEL, max_tokens=MAXTOKENS)
