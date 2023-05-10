# Query OpenAI for a comment
# @author Olivia Lucca Fraser
# @category Machine Learning
# @keybinding Ctrl-G
# @menupath File.Analysis.G-3PO Analyse function with GPT
# @toolbar G3PO.png

##########################################################################################
# Script Configuration
##########################################################################################
MODEL = "gpt-3.5-turbo"  # Choose which large language model we query
MODEL = askChoice("Model", "Please choose a language model to query", ["text-davinci-003", "gpt-3.5-turbo", "gpt-4", "claude-v1.2"], "gpt-3.5-turbo")
# If you have an OpenAI API key, gpt-3.5-turbo gives you the best bang for your buck.
# Use gpt-4 for slightly higher quality results, at a higher cost.
# If you have an Anthropic API key, try claude-v1.2, which also seems to work quite well.
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
import sys
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
            except ValueError as e:
                logging.error("Could not parse JSON response: {e}".format(e=e))
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
            except ValueError as e:
                logging.error("Could not parse JSON response: {e}".format(e=e))
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
    vendor = "ANTHROPIC" if MODEL.startswith("claude") else "OPENAI"
    try:
        return os.environ[vendor + "_API_KEY"]
    except KeyError as ke:
        try:
            home = os.environ["HOME"]
            keyfile = ".{v}_api_key".format(v=vendor.lower())
            with open(os.path.join(home, keyfile)) as f:
                line = f.readline().strip()
                return line.split("=")[1].strip('"\'')
        except Exception as e:
            logging.error(
                "Could not find {v} API key. Please set the {v}_API_KEY environment variable. Errors: {ke}, {e}".format(ke=ke, e=e, v=vendor))
            sys.exit(1)


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


def query(prompt, temperature=TEMPERATURE, max_tokens=MAXTOKENS, model=MODEL):
    vendor = "anthropic" if MODEL.startswith("claude") else "openai"
    if vendor == "anthropic":
        return anthropic_request(prompt, temperature, max_tokens, model)
    elif vendor == "openai":
        return openai_request(prompt, temperature, max_tokens, model)
    else:
        raise ValueError("Unknown vendor: {v}".format(v=vendor))


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
    res = send_https_request(host, path, data, headers)
    if res is None:
        logging.error("OpenAI request failed!")
        return None
    logging.info("OpenAI responded: {res}".format(res=res))
    if 'error' in res:
        logging.error("OpenAI error: {error}".format(error=res['error']['message']))
        return None
    if is_chat_model(model):
        response = res['choices'][0]['message']['content'].strip()
    else:
        response = res['choices'][0]['text'].strip()
    return response


def anthropic_request(prompt, temperature=0.19, max_tokens=MAXTOKENS, model=MODEL):
    ## Format the prompt
    formatted_prompt = []
    for message in prompt:
        role = 'Assistant' if message['role'] == 'assistant' else 'Human'
        formatted_prompt.append(
                "\n\n{role}: {content}".format(role=role, content=message['content']))
    formatted_prompt = ''.join(formatted_prompt) + "\n\nAssistant: "
    logging.debug(formatted_prompt)
    ## Send the request
    host = "api.anthropic.com"
    path = "/v1/complete"
    headers = {
            "Content-Type": "application/json",
            "x-api-key": get_api_key()
    }
    data = {
        "model": model,
        "prompt": formatted_prompt,
        "max_tokens_to_sample": max_tokens,
        "temperature": temperature,
        "stop_sequences": ["\n\nHuman:"]
        }
    res = send_https_request(host, path, data, headers)
    if res is None:
        logging.error("Anthropic request failed!")
        return None
    logging.info("Anthropic request succeeded!")
    logging.info("Response: {data}".format(data=res))
    return res['completion'].strip()


def get_current_function():
    logging.debug("currentAddress: {currentAddress}".format(currentAddress=currentAddress))
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
    intro = """You are a reverse engineering assistant named G-3PO. I am going to show you some C code decompiled from a {lang} binary. You are to provide a high-level explanation of what that code does, in {style}, and try to infer its purpose. Explain your reasoning, step by step. Suggest informative variable names for any variable whose purpose is clear, and suggest an informative name for the function itself. Please print each suggested variable name on its own line using the format
    
$old -> $new

Then suggest a name for the function by printing it on its own line using the format

$old :: $new

If you observe any security vulnerabilities in the code, describe them in detail, and explain how they might be exploited. Do you understand?
""".format(lang=lang, style=LANGUAGE)
    system_msg = {"role": "system", "content": intro}
    prompt = """Here is code from the function {function_name}:\n\n```
{code}
```
""".format(function_name=function_name, code=code)
    ack_msg = {"role": "assistant", "content": "Yes, I understand. Please show me the code."}
    prompt_msg = {"role": "user", "content": prompt}
    return [system_msg, ack_msg, prompt_msg]



def generate_comment(code, function_name, temperature=0.19, program_info=None, model=MODEL, max_tokens=MAXTOKENS):
    prompt = build_prompt_for_function(code, function_name)
    logging.debug("Prompt:\n\n{prompt}".format(prompt=prompt))
    response = query(
        prompt=prompt, 
        temperature=temperature,
        max_tokens=max_tokens,
        model=MODEL)
    return response


def add_explanatory_comment_to_current_function(temperature=0.19, model=MODEL, max_tokens=MAXTOKENS):
    function = get_current_function()
    function_name = function.getName()
    if function is None:
        logging.error("Failed to get current function")
        return None
    old_comment = function.getComment()
    if old_comment is not None:
        if OVERRIDE_COMMENTS or SOURCE in old_comment:
            logging.info("Removing old comment.")
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
        sys.exit(1)
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
    return comment, code


def parse_response_for_vars(comment):
    """takes block comment from AI, yields tuple of str old name & new name for each var"""
    # The LLM will sometimes wrap variable names in backticks, and sometimes prepend a dollar sign.
    # We want to ignore those artifacts.
    regex = re.compile(r'[`$]?([A-Za-z_][A-Za-z_0-9]*)`? -> [`$]?([A-Za-z_][A-Za-z_0-9]*)`?')
    for line in comment.split('\n'):
        m = regex.search(line)
        if m:
            old, new = m.groups()
            logging.debug("Found suggestion to rename {old} to {new}".format(old=old, new=new))
            if old == new or new == 'new':
                continue
            yield old, new


def parse_response_for_function_name(comment):
    """takes block comment from GPT, yields new function name"""
    regex = re.compile('[`$]?([A-Za-z_][A-Za-z_0-9]*)`? :: [$`]?([A-Za-z_][A-Za-z_0-9]*)`?')
    for line in comment.split('\n'):
        m = regex.search(line)
        if m:
            logging.debug("Renaming function to {new}".format(new=m.group(2)))
            _, new = m.groups()
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


def rename_high_variable(symbols, old_name, new_name, data_type=None):
    """takes a high variable object, a new name, and, optionally, a data type
    and sets the name and data type of the high variable in the program database"""

    if old_name not in symbols:
        logging.debug('GP3O wanted to rename variable {} to {}, but no variable found'.format(
            old_name, new_name))
        return
    hv = symbols[old_name]

    if data_type is None:
        data_type = hv.getDataType()

    # if running in Jython, we may need to ensure that the new name is in unicode
    try:
        new_name = unicode(new_name)
    except NameError:
        pass
    try:
        res = HighFunctionDBUtil.updateDBVariable(hv,
                                                  new_name,
                                                  data_type,
                                                  SourceType.ANALYSIS)
        logging.debug("Renamed {} to {}".format(old_name, new_name, res))
        return res
    except DuplicateNameException as e:
        logging.error("Failed to rename {} to {}: {}".format(
            old_name, new_name, e))
        return None



def apply_renaming_suggestions(comment, code):
    logging.info('Renaming variables...')

    func = get_current_function()
    func_name = func.getName()
    new_func_name = None

    if RENAME_VARIABLES:
        raw_vars = [v for v in func.getAllVariables()]
        variables = {var.getName(): var for var in raw_vars}
        logging.debug("Variables: {}".format(variables))

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
        logging.debug("Symbols: {}".format(symbols))

        for old, new in parse_response_for_vars(comment):
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
                    rename_high_variable(symbols, old, new)
                except Exception as e:
                    logging.error('Failed to rename variable: {}'.format(e))
            else:
                # check for hallucination
                if old not in code:
                    logging.error("G3PO wanted to rename variable {} to {}, but it may have been hallucinating.".format(old, new))
                elif old == func_name:
                    new_func_name = new
                else:
                    logging.error("GP3O wanted to rename variable {old} to {new}, but {old} was not found in the symbol table.".format(old=old, new=new))

    if func.getName().startswith('FUN_') or RENAME_FUNCTION:
        fn = parse_response_for_function_name(comment)
        new_func_name = fn or new_func_name # it may have been named with variable renaming syntax
        if new_func_name:
            func.setName(new_func_name, SourceType.USER_DEFINED)
            logging.debug('G3P0 renamed function to {}'.format(new_func_name))


comment, code = add_explanatory_comment_to_current_function(temperature=0.19, model=MODEL, max_tokens=MAXTOKENS)

if comment is not None and (RENAME_FUNCTION or RENAME_VARIABLES):
    apply_renaming_suggestions(comment, code)

