# Query OpenAI for a comment
#@author Lucca Fraser
#@category AI
#@keybinding
#@menupath
#@toolbar

import subprocess as sp
import logging
import json
import os
import re
try:
    from ghidra.app.script import GhidraScript
    from ghidra.program.model.listing import Function, FunctionManager
    from ghidra.program.model.mem import MemoryAccessException
    from ghidra.util.exception import DuplicateNameException
    from ghidra.program.model.symbol import SourceType
except ImportError:
    print("I guess we're in the repl, huh?")
    pass


SOURCE = "OpenAI GPT-3"
TAG = SOURCE + " generated comment, take with a grain of salt:"
TEXTMODEL = "text-davinci-003"
CODEMODEL = "code-davinci-002"
MODEL = TEXTMODEL
LISTING = None
TIMEOUT = 6000
MAXTOKENS = 512
#STYLE = "the voice of C-3PO"
C3POSAY = True
STYLE = "English"

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


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

COMMENTWIDTH = 80

def wordwrap(s, width=COMMENTWIDTH, pad=True):
    """Wrap a string to a given number of characters, but don't break words."""
    # first, find the original line breaks
    words = s.split()
    lines = []
    while words:
        line = ""
        while words and len(line) + len(words[0]) < width:
            line += words.pop(0) + " "
        lines.append(line)
    if pad:
        lines = [line.ljust(width) for line in lines]
    return "\n".join(lines)

def boxedtext(text, width=COMMENTWIDTH, tag=TAG):
    wrapped = wordwrap(text, width)
    wrapped = "\n".join([tag.ljust(width), " ".ljust(width), wrapped])
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
    global LISTING
    try:
        if LISTING is None:
            LISTING = currentProgram.getListing()
        function = LISTING.getFunctionContaining(currentAddress)
        return function
    except Exception as e:
        logging.error("Failed to get current function: {e}".format(e=e))
        return None

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

Please provide a detailed explanation of what this code does, in {style}, that might be useful to a reverse engineer. Explain your reasoning as much as possible. Finally, suggest a suitable name for this function.

""".format(intro=intro, c_code=c_code, style=STYLE)
    print("Prompt:\n\n{prompt}".format(prompt=prompt))
    response = openai_request(prompt=prompt, temperature=temperature, max_tokens=max_tokens, model=TEXTMODEL)
    try:
        res = response['choices'][0]['text'].strip()
        print(res)
        return res
    except Exception as e:
        logging.error("Failed to get response: {e}".format(e=e))
        return None

def generate_comment_alt(c_code, temperature=0.19, program_info=None, prompt=None, model=CODEMODEL, max_tokens=MAXTOKENS):
    intro = "The purpose of this function is to "
    if prompt is None:
        prompt = """{c_code}

/**
The purpose of the function above is to
""".format(c_code=c_code)
    print("Prompt:\n\n{prompt}".format(prompt=prompt))
    response = openai_request(prompt=prompt, temperature=temperature, max_tokens=max_tokens, model=model)
    try:
        print(response)
        res = response['choices'][0]['text'].strip()
        res = intro + res
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
    #print(comment)
    function = LISTING.getFunctionContaining(currentAddress)
    try:
        function.setComment(comment)
    except DuplicateNameException as e:
        logging.error("Failed to set comment: {e}".format(e=e))
        return
    logging.info("Added comment to function: {function_name}".format(function_name=function.getName()))
    return comment


add_explanatory_comment_to_current_function(temperature=0.19, model=MODEL, max_tokens=MAXTOKENS)
