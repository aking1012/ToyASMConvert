import gtk
import subprocess
import binascii
#Requires nasm and objdump
#Anticipates a linux user and gtk
#Shellcode to asm works for \x90\xcc, 90cc, mixed, newlines, and whitespace
#Doesn't clean up files in /tmp ... anticipates a reboot

class IntelToATT:
    #Accessor methods
    def setFile(self, arg):
        self.thisfile = arg + 'file.asm'
        self.thatfile = arg + 'file.o'

    def intelout(self, widget, data=None):    
        self.dtype = '-Mintel '
    def attoutfunc(self, widget, data=None):    
        self.dtype = ''

    #Callbacks
    #Die
    def destroy(self, widget, data=None):
        gtk.main_quit()
    #Assemble
    def assemble(self):
        proc = subprocess.Popen("nasm -o " + self.thatfile + " " + self.thisfile, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_v, stderr_v = proc.communicate('')
        return self.dump()
    
    def dump(self):
        proc = subprocess.Popen("objdump -D -b binary " + self.arch + self.dtype + self.thatfile, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_v, stderr_v = proc.communicate('')
        lines = stdout_v.split('\n')
        isdata = False
        att = []
        full = []
        for line in lines:
            if line == '':
                pass
            elif '<.data>' in line:
                isdata = True
            elif isdata:
                full.append(line.split('\t')[0].rstrip(':').lstrip())
                att.append(line.split('\t')[-1])
        insertLabels = []
        for line in att:
            line = str(line)
            if line[0] == 'j':
                insertLabels.append(line.split(' 0x'))
            else:
                insertLabels.append(['',''])
        i=0
        j=0
        labelFixup = {}
        for labelStuff in insertLabels:
            if labelStuff[1] != '':
                att.insert(full.index(labelStuff[1]), 'Label_'+str(j)+':')
                full.insert(full.index(labelStuff[1]), 'Label_'+str(j)+':')
                labelFixup[labelStuff[1]] = 'Label_'+str(j)
                j+=1
            i+=1
        i=0
        for line in att:
            line = str(line)
            if line[0] == 'j':
                att[i] = line.split(' 0x')[0] + labelFixup[line.split(' 0x')[1]]
            i+=1
        i=0
        for line in att:
            line = str(line)
            if line[-1] != ':':
                att[i] = '\t' + line + '; '
            i+=1
        return att

    #Get
    def get(self, widget, data=None):
        buf = self.textarea.get_buffer()
        start = buf.get_start_iter()
        end = buf.get_end_iter()
        sometext = buf.get_text(start, end)
        lines = sometext.split('\n')
        cleaned = []
        for line in lines:
            try:
                cleaned.append(line.split(';')[0].lstrip().rstrip())
                if cleaned[-1][-1] != ':':
                    cleaned[-1] = '\t' + cleaned[-1] + ';\n'
                else:
                    cleaned[-1] += '\n'
            except:
                pass
        asm = ''
        for line in cleaned:
            asm += line
        afile = 'section .text\n    global main\nmain:\n' + asm
        with open(self.thisfile, 'w') as f:
            f.write(afile)
        att = self.assemble()
        tmp = ''
        for line in att:
            tmp += line + '\n'
        if tmp == '':
            tmp = 'nop; Failed to parse'
        buf.set_text(tmp)
        self.textarea.set_buffer(buf)
        self.textarea.show_all()

    def shellcode(self, widget, data=None):
        buf = self.textarea.get_buffer()
        start = buf.get_start_iter()
        end = buf.get_end_iter()
        sometext = buf.get_text(start, end)
        line = sometext.replace(' ', '').replace('\t','').replace('\n','').replace('\r','').replace('\\x', '')
        try:
            afile = binascii.unhexlify(line)
            with open(self.thatfile, 'wb') as f:
                f.write(afile)
            att = self.dump()
            tmp = ''
            for line in att:
                tmp += line + '\n'
        except:
            tmp = 'nop; Failed to parse...'
        buf.set_text(tmp)
        self.textarea.set_buffer(buf)
        self.textarea.show_all()

    def __init__(self, intermediatedir='/tmp/'):
        #Set out class variables
        self.setFile(intermediatedir)
        self.arch = "-m i386 "
        self.dtype = ''
        #Make a window
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        #Make sure we can close it
        self.window.connect("destroy", self.destroy)
        #Get our vbox
        vbox = gtk.VBox()
        #Add a place to paste our Intel ASM
        scrollable = gtk.ScrolledWindow()
        self.textarea = gtk.TextView()
        scrollable.add(self.textarea)
        scrollable.set_size_request(400, 200)
        vbox.add(scrollable)
        #Add a go button
        self.go = gtk.Button()
        self.go.set_label('Intel')
        #Connect our go button
        self.go.connect("clicked", self.get)
        #Add a sc button
        self.sc = gtk.Button()
        self.sc.set_label('Shellcode')
        #Connect our go button
        self.sc.connect("clicked", self.shellcode)
        #Add a quit button
        self.quit = gtk.Button()
        self.quit.set_label('Quit')
        #Connect our quit button
        self.quit.connect("clicked", self.destroy)
        #Put it in containers
        hbox = gtk.HBox()
        hbox.add(self.go)
        hbox.add(self.sc)
        hbox.add(self.quit)
        vbox.add(hbox)
        #Output
        #Add output label
        output = gtk.Label()
        output.set_text('Set Output:')
        self.goout = gtk.Button()
        self.goout.set_label('Intel')
        self.goout.connect("clicked", self.intelout)
        #Add a sc button
        self.attout = gtk.Button()
        self.attout.set_label('AT&T')
        self.attout.connect("clicked", self.attoutfunc)
        hboxa = gtk.HBox()
        hboxa.add(output)
        hboxa.add(self.goout)
        hboxa.add(self.attout)
        vbox.add(hboxa)
        #Draw our window
        self.window.add(vbox)
        self.window.show_all()
        
if __name__ == '__main__':
    this = IntelToATT()
    gtk.main()