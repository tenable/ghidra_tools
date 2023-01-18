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
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.flatapi import FlatProgramAPI

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
RENAME_FUNCTION = True   # Rename function per G3PO's suggestions
RENAME_VARIABLES = True  # Rename variables per G3PO's suggestions
OVERRIDE_COMMENTS = True # Override existing comments
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

STATE = getState()
PROGRAM = state.getCurrentProgram()
FLATAPI = FlatProgramAPI(PROGRAM)


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

Please explain what this code does, in {style}, and carefully explain your reasoning in a way that might be useful to a reverse engineer. Finally, suggest a suitable name for this function and suggest informative names for any variables whose purpose is clear. Print each suggested variable name on its own line in the form $old -> $new, where $old is the old name and $new is the  new name. Print the suggested function name on its own line in the form $old :: $new. {extra}

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
    if not OVERRIDE_COMMENTS:
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



def parse_response_for_vars(comment):
    """takes block comment from GPT, yields tuple of str old name & new name for each var"""
    for line in comment.split('\n'):
        if ' -> ' in line:
            old, new = line.split(' -> ')
            old = old.strip('| ')
            new = new.strip('| ')
            if old == new:
                continue
            yield old, new


def parse_response_for_name(comment):
    """takes block comment from GPT, yields new function name"""
    for line in comment.split('\n'):
        if ' :: ' in line:
            _, new = line.split(' :: ')
            new = new.strip('| ')
            return new


def rename_var(old_name, new_name, variables):
    """takes an old and new variable name from listing and renames it
        old_name: str, old variable name
        new_name: str, new variable name
        variables: {str, Variable}, vars in the func we're working in """
    try:
        var_to_rename = variables.get(old_name)
        if var_to_rename:
            var_to_rename.setName(new_name, SourceType.USER_DEFINED)
            var_to_rename.setComment('GP3O renamed this from {} to {}'.format(old_name, new_name))
            logging.debug('GP3O renamed variable {} to {}'.format(old_name, new_name))
        else:
            logging.debug('GP3O wanted to rename variable {} to {}, but no Variable found'.format(old_name, new_name))

    # only deals with listing vars, need to work with decomp to get the rest
    except KeyError:
        pass


# https://github.com/NationalSecurityAgency/ghidra/issues/1561#issuecomment-590025081
def rename_data(old_name, new_name):
    """takes an old and new data name, finds the data and renames it
        old_name: str, old variable name of the form DAT_{addr}
        new_name: str, new variable name"""
    new_name = new_name.upper()
    address = int(old_name.strip('DAT_'), 16)
    sym = FLATAPI.getSymbolAt(FLATAPI.toAddr(address))
    sym.setName(new_name, SourceType.USER_DEFINED)
    logging.debug('GP3O renamed Data {} to {}'.format(old_name, new_name))


def rename_high_variable(hv, new_name, data_type=None):
    """takes a high variable object, a new name, and, optionally, a data type
    and sets the name and data type of the high variable in the program database"""

    if data_type is None:
        data_type = hv.getDataType()
    return HighFunctionDBUtil.updateDBVariable(hv,
                unicode(new_name),
                data_type,
                SourceType.ANALYSIS)


def sanitize_variable_name(name):
    """takes a variable name and returns a sanitized version that can be used as a variable name in Ghidra
    name: str, variable name"""
    # strip out any characters that aren't letters, numbers, or underscores
    name = re.sub(r'[^a-zA-Z0-9_]', '', name)
    # if the first character is a number, prepend an underscore
    if name[0].isdigit():
        name = 'x' + name
    return name

def apply_variable_predictions(comment):
    logging.info('Applying gpt-3 variable names')

    func = get_current_function()
    raw_vars = func.getAllVariables().tolist()
    variables = {var.getName(): var for var in raw_vars}

    # John coming in clutch again
    # https://github.com/NationalSecurityAgency/ghidra/issues/2143#issuecomment-665300865
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(func.getProgram())
    res = ifc.decompileFunction(func, TIMEOUT, monitor)
    high_func = res.getHighFunction()
    lsm = high_func.getLocalSymbolMap()
    symbols = lsm.getSymbols()
    symbols = {var.getName(): var for var in symbols}

    for old, new in parse_response_for_vars(comment):
        new = sanitize_variable_name(new)
        if re.match(r"^DAT_[0-9a-f]+$", old): # Globals with default names
            try:
                rename_data(old, new)
            except Exception as e:
                logging.error('Failed to rename data: {}'.format(e))
        elif old in symbols and symbols[old] is not None:
            try:
                rename_high_variable(symbols[old], new)
            except Exception as e:
                logging.error('Failed to rename variable: {}'.format(e))
        else:
            logging.debug("GP3O wanted to rename variable {} to {}, but shan't".format(old, new))

    new_func_name = sanitize_variable_name(parse_response_for_name(comment))
    if new_func_name:
        func.setName(new_func_name, SourceType.USER_DEFINED)
        logging.debug('G3P0 renamed function to {}'.format(new_func_name))



comment = add_explanatory_comment_to_current_function(temperature=0.19, model=MODEL, max_tokens=MAXTOKENS)

if comment is not None and APPLYRESULTS:
    apply_variable_predictions(comment)
