# -*- coding: utf-8 -*-
import os
import sys
from cx_Freeze import setup, Executable 

includes = []
includefiles = [r"C:\Python\DLLs\tcl86t.dll", r"C:\Python\DLLs\tk86t.dll"]
build_exe_options = dict(
    packages = [],
    excludes = [],
    include_files=includefiles
)

os.environ['TCL_LIBRARY'] = r'C:\Python\tcl\tcl8.6'
os.environ['TK_LIBRARY'] = r'C:\Python\tcl\tk8.6'
base = 'Win32GUI' if sys.platform == 'win32' else None

setup(name = "Socksv5" , 
      version = "0.1" ,
      author = "Vinod Sarjerao Khandkar",
      author_email = "vinod.khandkar@iitb.ac.in",
      description = "SOCKS v5 proxy server" ,
      options = {"build_exe": build_exe_options},
      executables = [Executable("D:\Vinod\Code\Proxy\sproxy_app.py",base=base)])
