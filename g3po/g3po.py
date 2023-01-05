# Query OpenAI for a comment
#@author Lucca Fraser
#@category AI
#@keybinding
#@menupath
#@toolbar

import httplib
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
LOGLEVEL = DEBUG       # Adjust for more or less line noise in the console.
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


def send_https_request(address, path, data, headers):
    try:
        conn = httplib.HTTPSConnection(address)
        json_req_data = json.dumps(data)
        conn.request("POST", path, json_req_data, headers)
        response = conn.getresponse()
        json_data = response.read()
        conn.close()
        try:
            data = json.loads(json_data)
            return data
        except ValueError:
            logging.error("Could not parse JSON response from OpenAI!")
            logging.debug(json_data)
            return None
    except Exception as e:
        logging.error("Error sending HTTPS request: {e}".format(e=e))
        return None


def openai_request(prompt, temperature=0.19, max_tokens=MAXTOKENS, model=MODEL):
    data = {
      "model": MODEL,
      "prompt": prompt,
      "max_tokens": max_tokens,
      "temperature": temperature
    }
    # The URL is "https://api.openai.com/v1/completions"
    host = "api.openai.com"
    path = "/v1/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer {openai_api_key}".format(openai_api_key=os.getenv("OPENAI_API_KEY")),
    }
    data = send_https_request(host, path, data, headers)
    if data is None:
        logging.error("OpenAI request failed!")
        return None
    logging.info("OpenAI request succeeded!")
    logging.info("Response: {data}".format(data=data))
    return data


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


comment = add_explanatory_comment_to_current_function(temperature=0.19, model=MODEL, max_tokens=MAXTOKENS)
# comment = """
# /* /--------------------------------------------------------------------------------\
#    |OpenAI GPT-3 generated comment, take with a grain of salt:                      |
#    |                                                                                |
#    |    This code is a window procedure for a window created with the Windows API.  |
#    |It handles messages sent to the window, such as WM_DESTROY, WM_PAINT, and       |
#    |WM_COMMAND. It also handles custom messages sent to the window, such as 0x200   |
#    |and 0x201.                                                                      |
#    |    When the window receives a WM_DESTROY message, it deletes the device context|
#    |and frees any memory allocated to the window. It then posts a quit message to   |
#    |the application.                                                                |
#    |    When the window receives a WM_PAINT message, it creates a device context if |
#    |one does not already exist, and then blits the contents of the device context to|
#    |the window.                                                                     |
#    |    When the window receives a WM_COMMAND message, it checks the command ID and |
#    |if it is 0x68, it displays a dialog box. If it is 0x69, it destroys the window. |
#    |    When the window receives a custom message 0x200, it sets the window title to|
#    |a string containing the coordinates of the mouse cursor and the number of       |
#    |clicks.                                                                         |
#    |    When the window receives a custom message 0x201, it checks if the           |
#    |coordinates of the mouse cursor match the coordinates of a pixel in the device  |
#    |context. If they do, it blits the contents of the device context to the window. |
#    |If the coordinates do not match, it sets the window title to a string containing|
#    |the coordinates of the mouse cursor and the number of clicks.                   |
#    |    The function name could be "WindowProc" and the variables could be renamed  |
#    |as follows:                                                                     |
#    |    param_1 -> hwnd                                                             |
#    |    param_2 -> message                                                          |
#    |    param_3 -> wParam                                                           |
#    |    param_4 -> lParam                                                           |
#    |    sVar1 -> yCoord                                                             |
#    |    pHVar2 -> hdc                                                               |
#    |    hHeap -> hHeap                                                              |
#    |    LVar3 -> lResult                                                            |
#    |    uVar4 -> width                                                              |
#    |    uVar5 -> height                                                             |
#    |    uVar6 -> xCoord                                                             |
#    |    iVar7 -> x                                                                  |
#    |    uVar8 -> xCoordShort                                                        |
#    |    iVar9 -> y                                                                  |
#    |    dwFlags -> dwFlags                                                          |
#    |    lpMem -> lpMem                                                              |
#    |    local_148 -> szTitle                                                        |
#    |    local_44 -> ps                                                              |
#    |    DAT_004130e0 -> hInstance                                                   |
#    |    DAT_004130e4 -> hBitmap                                                     |
#    |    DAT_00412000 -> bInitialized                                                |
#    |                                                                                |
#    |Model: text-davinci-003, Temperature: 0.19                                      |
#    \--------------------------------------------------------------------------------/
#                   /
#              /~\
#             |oo )
#             _\=/_
#            /     \
#           //|/.\|\\
#          ||  \_/  ||
#          || |\ /| ||
#           # \_ _/  #
#             | | |
#             | | |
#             []|[]
#             | | |
#            /_]_[_\
#     */"""

def parse_response_for_vars(comment):
    """takes block comment from above, yields tuple of str old name & new name for each var"""
    for line in comment.split('\n'):
        if ' -> ' in line:
            old, new = line.split(' -> ')
            old = old.strip('| ')
            new = new.strip('| ')
            yield old, new


def rename_var(old_name, new_name, func, variables):
    """takes an old and new variable name and renames it
        old_name: str, old variable name
        new_name: str, new variable name
        func: Function, func we're working in
        variables: {str, Variable}, vars in the func we're working in """
    var_to_rename = variables[old_name]
    var_to_rename.setName(new_name, SourceType.USER_DEFINED)
    var_to_rename.setComment('GP3O renamed this from {} to {}'.format(old_name, new_name))

# TODO: ask gpt3 to give me a more parsable name :)
def parse_response_for_func_name(comment):
    pass

print('applying gpt-3 variable names')

func = get_current_function()
raw_vars = func.getAllVariables().tolist()
variables = {var.getName(): var for var in raw_vars}

for old, new in parse_response_for_vars(comment):
    rename_var(old, new, func, variables)



