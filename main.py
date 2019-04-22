import PRISM, XKeyScore
from threading import Thread
import os, threading

runningPrism = False
PMonitorThread = None

def printOptions():
    global runningPrism, PMonitorThread

    string = "System\nSelect Option:\n"
    string +=  ") PRIMS running\n" if PMonitorThread else "1) Start PRIMS in background\n"
    string += """2) Start XKeyScore\n"""
    string += """3) exit\n"""
    print string

def runOption(option):
    global runningPrism, PMonitorThread

    if option == str(1):
        runningPrism =True
        PMonitorThread= Thread(target=PRISM.monitorNetwork, args=(False, 50, False, True))
        PMonitorThread.close = threading.Event()
        print "running Thread"
        PMonitorThread.start()
        print "PRISM monitor running"
    elif option == str(2):
        XKeyScore.bootstrap()
    elif option == str(3):
        if PMonitorThread: PMonitorThread.close.set()
        return exit()
    bootstrap()

def bootstrap():
    printOptions()
    option = raw_input('... ')
    runOption(option)
    
def main():
    os.system('cls')
    bootstrap()

main()
