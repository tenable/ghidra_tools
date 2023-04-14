# G-3PO: A Protocol Droid for Ghidra

(The acronym probably stands for "Ghidra gpt-3 Program Oracle", or something like that.)

For a detailed writeup on the tool, and its rationale, see [G-3PO: A Protocol Droid for Ghidra](https://medium.com/tenable-techblog/g-3po-a-protocol-droid-for-ghidra-4b46fa72f1ff), on the Tenable TechBlog.


## Installing and Using G-3PO

G-3PO is ready for use. The only catch is that it does require an OpenAI API key, and the text completion service is unfree (as in beer, and as insofar as the model’s a black box). It is, however, reasonably cheap, and even with heavy use I haven’t spent more than the price of a cup of coffee while developing, debugging, and toying around with this tool.

To run the script:
- get yourself an OpenAI or Anthropic API key (G-3PO supports LLM backends from both companies)
- add the key as an environment variable by putting export `OPENAI_API_KEY=whateveryourkeyhappenstobe` or `ANTHROPIC_API_KEY=youranthropickeyifyouhaveone` in your `~/.profile` file, or any other file that will be sourced before you launch Ghidra
- copy or symlink g3po.py to your Ghidra scripts directory
- add that directory in the Script Manager window
- visit the decompiler window for a function you’d like some assistance interpreting
- and then either run the script from the Script Manager window by selecting it and hitting the ▶️ icon, or bind it to a hotkey and strike when needed

Ideally, I’d like to provide a way for the user to twiddle the various parameters used to solicit a response from model, such as the “temperature” in the request (high temperatures — approaching 2.0 — solicit a more adventurous response, while low temperatures instruct the model to respond conservatively), all from within Ghidra. There’s bound to be a way to do this, but it seems neither the Ghidra API documentation, Google, nor even ChatGPT are offering me much help in that regard, so for now you can adjust the settings by editing the global variables declared near the beginning of the g3po.py source file:

```python
##########################################################################################
# Script Configuration
##########################################################################################
MODEL = "gpt-3.5-turbo" # Choose which large language model we query -- gpt-4 and claude-v1.2 also supported
TEMPERATURE = 0.19   # Set higher for more adventurous comments, lower for more conservative
TIMEOUT = 600        # How many seconds should we wait for a response from OpenAI?
MAXTOKENS = 512      # The maximum number of tokens to request from OpenAI
C3POSAY = True       # True if you want the cute C-3PO ASCII art, False otherwise
LANGUAGE = "English" # This can also be used as a style parameter.
EXTRA = ""           # Extra text appended to the prompt.
LOGLEVEL = INFO      # Adjust for more or less line noise in the console.
COMMENTWIDTH = 80    # How wide the comment, inside the little speech balloon, should be.
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
##########################################################################################
```

The LANGUAGE and EXTRA parameters provide the user with an easy way to play with the form of the LLM’s commentary.

