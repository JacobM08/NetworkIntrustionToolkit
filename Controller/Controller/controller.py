import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from model.attack import *
from model.scanner import *
from model.networkmap import *
from model.tester import *

# Call the function
display()