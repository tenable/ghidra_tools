# Query OpenAI for a comment
# @author Olivia Lucca Fraser
# @category Machine Learning
# @keybinding Ctrl-G
# @menupath File.Analysis.G-3PO Analyse function with GPT
# @toolbar G3PO.png

##########################################################################################
# Script Configuration
##########################################################################################
# MODEL = "gpt-4" # Choose which large language model we query
MODEL = "gpt-3.5-turbo"  # Choose which large language model we query
# Set higher for more adventurous comments, lower for more conservative
TEMPERATURE = 0.05
TIMEOUT = 600         # How many seconds should we wait for a response from OpenAI?
MAXTOKENS = 1024       # The maximum number of tokens to request from OpenAI
G3POSAY = True        # True if you want the cute C-3PO ASCII art, False otherwise
# LANGUAGE = "the form of a sonnet"  # This can also be used as a style parameter for the comment
LANGUAGE = "English"  # This can also be used as a style parameter for the comment
EXTRA = ""            # Extra text appended to the prompt.
# EXTRA = "but write everything in the form of a sonnet" # for example
# How wide the comment, inside the little speech balloon, should be.
COMMENTWIDTH = 80
RENAME_FUNCTION = False  # Rename function per G3PO's suggestions
RENAME_VARIABLES = True  # Rename variables per G3PO's suggestions
OVERRIDE_COMMENTS = True  # Override existing comments
G3POASCII = r"""
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
TRY_TO_SUMMARIZE_LONG_FUNCTIONS = False  # very experimental, use at your own risk
SEND_ASSEMBLY = False
##########################################################################################

## 
# Note: I've updated this script so that it runs in the Ghidrathon Python 3 environment.
# It should remain backwards-compatible with the Jython 2.7 environment.
##

import textwrap
import logging
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL
import json
import os
import re
import ghidra
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

LOGLEVEL = INFO       # Adjust for more or less line noise in the console.

# The way we handle the API calls will vary depending on whether we're running jython
# or python3. Jython doesn't have the requests library, so we'll use httplib instead.
try:
    import httplib
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
except ImportError:
    import requests
    def send_https_request(address, path, data, headers):
        try:
            response = requests.post(
                "https://{address}{path}".format(address=address, path=path),
                json=data,
                headers=headers)
            try:
                data = response.json()
                return data
            except ValueError:
                logging.error("Could not parse JSON response from OpenAI!")
                logging.debug(response.text)
                return None
        except Exception as e:
            logging.error("Error sending HTTPS request: {e}".format(e=e))
            return None

try:
    import tiktoken
    ENCODING = tiktoken.encoding_for_model(MODEL)
    
    def estimate_number_of_tokens(s):
        if type(s) == str:
            return len(ENCODING.encode(s))
        elif type(s) == list:
            for item in s:
                token_count += estimate_number_of_tokens(item)
            return token_count
        elif type(s) == dict:
            for k,v in s.items():
                token_count += estimate_number_of_tokens(v) + 2

except ImportError:

    def estimate_number_of_tokens(s):
        return int(len(s)/2.3)


SOURCE = "AI"
TAG = SOURCE + " generated comment, take with a grain of salt:"
FOOTER = "Model: {model}, Temperature: {temperature}".format(
    model=MODEL, temperature=TEMPERATURE)

logging.getLogger().setLevel(LOGLEVEL)

STATE = getState()
PROGRAM = state.getCurrentProgram()
FLATAPI = FlatProgramAPI(PROGRAM)


def get_api_key():
    try:
        return os.environ["OPENAI_API_KEY"]
    except KeyError as ke:
        try:
            home = os.environ["HOME"]
            with open(os.path.join(home, ".openai_api_key")) as f:
                line = f.read().strip()
                return line.split("=")[1].strip('"\'')
        except Exception as e:
            logging.error(
                "Could not find OpenAI API key. Please set the OPENAI_API_KEY environment variable. Errors: {ke}, {e}".format(ke=ke, e=e))
            raise e


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
    wrapped = "\n".join([tag.ljust(width), " ".ljust(
        width), wrapped, " ".ljust(width), FOOTER.ljust(width)])
    side_bordered = "|" + wrapped.replace("\n", "|\n|") + "|"
    top_border = "/" + "-" * (len(side_bordered.split("\n")[0]) - 2) + "\\"
    bottom_border = top_border[::-1]
    return top_border + "\n" + side_bordered + "\n" + bottom_border


def g3posay(text, width=COMMENTWIDTH, character=G3POASCII, tag=TAG):
    box = boxedtext(text, width, tag=tag)
    headwidth = len(character.split("\n")[1]) + 2
    return box + "\n" + " "*headwidth + "/" + character


def escape_unescaped_single_quotes(s):
    return re.sub(r"(?<!\\)'", r"\\'", s)


def is_chat_model(model):
    return 'turbo' in model or 'gpt-4' in model


def openai_request(prompt, temperature=0.19, max_tokens=MAXTOKENS, model=MODEL):
    chat = is_chat_model(model)
    if not chat:
        prompt = '\n'.join(m['content'] for m in prompt)
    data = {
        "model": MODEL,
        "messages" if chat else "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": temperature
    }
    # The URL is "https://api.openai.com/v1/completions"
    host = "api.openai.com"
    path = "/v1/chat/completions" if chat else "/v1/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer {openai_api_key}".format(openai_api_key=get_api_key())
    }
    data = send_https_request(host, path, data, headers)
    if data is None:
        logging.error("OpenAI request failed!")
        return None
    logging.info("OpenAI request succeeded!")
    logging.info("Response: {data}".format(data=data))
    return data


def get_current_function():
    print("currentAddress: {currentAddress}".format(currentAddress=currentAddress))
    listing = currentProgram.getListing()
    function = listing.getFunctionContaining(currentAddress)
    return function


def decompile_current_function(function=None):
    if function is None:
        function = get_current_function()
    logging.info("Current address is at {currentAddress}".format(
        currentAddress=currentAddress.__str__()))
    logging.info("Decompiling function: {function_name} at {function_entrypoint}".format(
        function_name=function.getName(), function_entrypoint=function.getEntryPoint().__str__()))
    decomp = ghidra.app.decompiler.DecompInterface()
    decomp.openProgram(currentProgram)
    decomp_res = decomp.decompileFunction(function, TIMEOUT, monitor)
    if decomp_res.isTimedOut():
        logging.warning("Timed out while attempting to decompile '{function_name}'".format(
            function_name=function.getName()))
    elif not decomp_res.decompileCompleted():
        logging.error("Failed to decompile {function_name}".format(
            function_name=function.getName()))
        logging.error("    Error: " + decomp_res.getErrorMessage())
        return None
    decomp_src = decomp_res.getDecompiledFunction().getC()
    return decomp_src


def get_assembly(function=None):
    if function is None:
        function = get_current_function()
    listing = currentProgram.getListing()
    code_units = listing.getCodeUnits(function.getBody(), True)
    assembly = "\n".join([code_unit.toString() for code_unit in code_units])
    return assembly


def get_code(function=None):
    if SEND_ASSEMBLY:
        return get_assembly(function=function)
    else:
        return decompile_current_function(function=function)


def get_architecture():
    """Return the architecture, word size, and endianness of the current program."""
    arch = currentProgram.getLanguage().getProcessor().toString()
    word_size = currentProgram.getLanguage().getLanguageDescription().getSize()
    endianness = currentProgram.getLanguage(
    ).getLanguageDescription().getEndian().toString()
    return {'arch': arch, 'word_size': word_size, 'endianness': endianness}


def lang_description():
    lang = "C"
    if SEND_ASSEMBLY:
        arch_details = get_architecture()
        arch = arch_details['arch']
        word_size = arch_details['word_size']
        endianness = arch_details['endianness']
        lang = "{arch} {word_size}-bit {endianness}".format(
            arch=arch, word_size=word_size, endianness=endianness)
    return lang


def build_prompt_for_function(code, function_name):
    lang = lang_description()
    intro = """I am a reverse engineering assistant named G-3PO. When I am presented with C code decompiled from a {lang} binary, I will provide a high-level explanation of what that code does, in {style}, and speculate as to its purpose. I will explain my reasoning. I will suggest informative variable names for any variable whose purpose is clear, and I will suggest an informative name for the function itself. I will print each suggested variable name on its own line using the format
    
$old -> $new

I will then suggest a name for the function by printing it on its own line using the format

$old :: $new

If I observe any security vulnerabilities in the code, I will describe them in detail, and explain how they might be exploited.
""".format(lang=lang, style=LANGUAGE)
    system_msg = {"role": "system", "content": intro}
    prompt = """Here is code from the function {function_name}:\n\n```
{code}
```
""".format(function_name=function_name, code=code)
    prompt_msg = {"role": "user", "content": prompt}
    return [system_msg, prompt_msg]



def generate_comment(code, function_name, temperature=0.19, program_info=None, model=MODEL, max_tokens=MAXTOKENS):
    prompt = build_prompt_for_function(code, function_name)
    print("Prompt:\n\n{prompt}".format(prompt=prompt))
    response = openai_request(
        prompt=prompt, 
        temperature=temperature,
        max_tokens=max_tokens,
        model=MODEL)
    try:
        if is_chat_model(model):
            res = response['choices'][0]['message']['content'].strip()
        else:
            res = response['choices'][0]['text'].strip()
        print(res)
        return res
    except Exception as e:
        logging.error("Failed to get response: {e}".format(e=e))
        return None


def add_explanatory_comment_to_current_function(temperature=0.19, model=MODEL, max_tokens=MAXTOKENS):
    function = get_current_function()
    function_name = function.getName()
    if function is None:
        logging.error("Failed to get current function")
        return None
    old_comment = function.getComment()
    if old_comment is not None:
        if OVERRIDE_COMMENTS or SOURCE in old_comment:
            function.setComment(None)
        else:
            logging.info("Function {function_name} already has a comment".format(
                function_name=function_name))
            return None
    code = get_code(function)
    if code is None:
        logging.error("Failed to {action} current function {function_name}".format(
            function_name=function_name, action="disassemble" if SEND_ASSEMBLY else "decompile"))
        return
    approximate_tokens = estimate_number_of_tokens(code)
    logging.info("Length of decompiled C code: {code_len} characters, guessing {approximate_tokens} tokens".format(
        code_len=len(code), approximate_tokens=approximate_tokens))
    comment = generate_comment(code, function_name=function_name,
                               temperature=temperature, model=model, max_tokens=max_tokens)
    if comment is None:
        logging.error("Failed to generate comment")
        return
    if G3POSAY:
        comment = g3posay(comment)
    else:
        comment = TAG + "\n" + comment
    listing = currentProgram.getListing()
    function = listing.getFunctionContaining(currentAddress)
    try:
        function.setComment(comment)
    except DuplicateNameException as e:
        logging.error("Failed to set comment: {e}".format(e=e))
        return
    logging.info("Added comment to function: {function_name}".format(
        function_name=function.getName()))
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
            var_to_rename.setComment(
                'GP3O renamed this from {} to {}'.format(old_name, new_name))
            logging.debug(
                'GP3O renamed variable {} to {}'.format(old_name, new_name))
        else:
            logging.debug('GP3O wanted to rename variable {} to {}, but no Variable found'.format(
                old_name, new_name))

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
    # if running in Jython, we'll need to use unicode
    try:
        new_name = unicode(new_name)
    except NameError:
        pass
    return HighFunctionDBUtil.updateDBVariable(hv,
                                               new_name,
                                               data_type,
                                               SourceType.ANALYSIS)


def sanitize_variable_name(name):
    """takes a variable name and returns a sanitized version that can be used as a variable name in Ghidra
    name: str, variable name"""
    if not name:
        return name
    # strip out any characters that aren't letters, numbers, or underscores
    name = re.sub(r'[^a-zA-Z0-9_]', '', name)
    # if the first character is a number, prepend an underscore
    if name[0].isdigit():
        name = 'x' + name
    return name


def apply_variable_predictions(comment):
    logging.info('Applying GPT variable names')

    func = get_current_function()

    if RENAME_VARIABLES:
        raw_vars = [v for v in func.getAllVariables()]
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
            old = sanitize_variable_name(old)
            new = sanitize_variable_name(new)
            if not new:
                logging.error('Could not parse new name for {}'.format(old))
                continue
            if re.match(r"^DAT_[0-9a-f]+$", old):  # Globals with default names
                # suffix = old.split('_')[-1] # on second thought, we don't want stale address info
                # in a non-dynamic variable name
                try:
                    # handy to retain the address info here
                    rename_data(old, new)
                except Exception as e:
                    logging.error('Failed to rename data: {}'.format(e))
            elif old in symbols and symbols[old] is not None:
                try:
                    rename_high_variable(symbols[old], new)
                except Exception as e:
                    logging.error('Failed to rename variable: {}'.format(e))
            else:
                logging.debug(
                    "GP3O wanted to rename variable {} to {}, but shan't".format(old, new))

    if func.getName().startswith('FUN_') or RENAME_FUNCTION:
        new_func_name = sanitize_variable_name(
            parse_response_for_name(comment))
        if new_func_name:
            func.setName(new_func_name, SourceType.USER_DEFINED)
            logging.debug('G3P0 renamed function to {}'.format(new_func_name))


comment = add_explanatory_comment_to_current_function(
    temperature=0.19, model=MODEL, max_tokens=MAXTOKENS)

if comment is not None and (RENAME_FUNCTION or RENAME_VARIABLES):
    apply_variable_predictions(comment)
